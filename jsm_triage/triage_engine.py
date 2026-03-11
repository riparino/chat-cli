"""Core triage engine – orchestrates AI providers and JSM updates."""

import json
import os
from typing import Optional

from .providers.base import AIProvider, TriageResult, ProviderError
from .jsm.models import Ticket

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert IT helpdesk triage assistant integrated with Atlassian Jira Service Management (JSM).
Your task is to analyse support tickets and produce a structured triage output.

ALWAYS respond with a single valid JSON object – no markdown, no prose outside the JSON.

JSON schema:
{
  "priority": "<Critical|High|Medium|Low>",
  "category": "<top-level category string>",
  "subcategory": "<specific sub-category string>",
  "suggested_team": "<team or queue name, or null>",
  "suggested_assignee": "<first-name last-name or role, or null>",
  "summary": "<1-2 sentence triage summary>",
  "suggested_actions": ["<action 1>", "<action 2>", "..."],
  "escalate": <true|false>,
  "escalation_reason": "<reason string, or null>",
  "estimated_resolution": "<e.g. '4 hours', '1-2 business days', or null>",
  "confidence": <0.0 to 1.0>
}

Priority guidance:
- Critical: Outage / total loss of service affecting many users or critical business process
- High:     Significant impact on productivity or single VIP user; time-sensitive
- Medium:   Moderate impact; workaround exists; can wait standard SLA
- Low:      Minor inconvenience; cosmetic; informational request

Category examples (adapt to context):
  Access & Permissions, Hardware, Software / Applications, Network & Connectivity,
  Email & Collaboration, Security Incident, Data & Storage, Onboarding / Offboarding,
  Facilities, Finance Systems, HR Systems, General Enquiry

Always consider: urgency signals (words like "URGENT", "can't work", "blocked"),
user seniority cues, scope (how many people affected), compliance/security risk."""


def _build_user_prompt(ticket: Ticket, org_context: Optional[str] = None) -> str:
    """Build the per-ticket user prompt."""
    data = ticket.to_triage_dict()
    context_block = f"\nOrganisation context:\n{org_context}\n" if org_context else ""

    return (
        f"Triage the following JSM ticket:{context_block}\n\n"
        f"```json\n{json.dumps(data, indent=2, ensure_ascii=False)}\n```\n\n"
        "Respond with a JSON triage object matching the schema above."
    )


# ---------------------------------------------------------------------------
# Provider chain management
# ---------------------------------------------------------------------------

_PROVIDER_ENV_HINTS = {
    "azure_openai": "AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_DEPLOYMENT",
    "github_copilot": "GITHUB_TOKEN",
    "openai": "OPENAI_API_KEY",
    "ms_copilot": "MS_COPILOT_ENDPOINT",
    "rovo": "ATLASSIAN_DOMAIN + ATLASSIAN_EMAIL + ATLASSIAN_API_TOKEN",
}


def build_provider_chain(
    preferred_order: Optional[list[str]] = None,
    instances: Optional[dict[str, "AIProvider"]] = None,
) -> list[AIProvider]:
    """
    Return available providers in preference order.

    Args:
        preferred_order: Provider name list, e.g.
            ["azure_openai", "github_copilot", "openai", "ms_copilot", "rovo"]
            Defaults to env var TRIAGE_PROVIDER_ORDER or the order above.
        instances: Pre-built provider objects keyed by name.  Use this to inject
            OAuth-authenticated providers from the CLI without monkey-patching.
            Names not present in *instances* get a default-constructed instance.
    """
    from .providers.azure_openai import AzureOpenAIProvider
    from .providers.github_copilot import GitHubCopilotProvider
    from .providers.openai_direct import OpenAIProvider
    from .providers.ms_copilot import MSCopilotProvider
    from .providers.rovo import RovoProvider

    default_classes: dict[str, type] = {
        "azure_openai":   AzureOpenAIProvider,
        "github_copilot": GitHubCopilotProvider,
        "openai":         OpenAIProvider,
        "ms_copilot":     MSCopilotProvider,
        "rovo":           RovoProvider,
    }

    if preferred_order is None:
        env_order = os.getenv("TRIAGE_PROVIDER_ORDER", "")
        preferred_order = (
            [p.strip() for p in env_order.split(",") if p.strip()]
            if env_order
            else list(default_classes.keys())
        )

    instances = instances or {}
    chain: list[AIProvider] = []
    for name in preferred_order:
        provider = instances.get(name)
        if provider is None:
            cls = default_classes.get(name)
            if cls is None:
                print(f"  Warning: unknown provider '{name}' – skipping")
                continue
            provider = cls()
        if provider.is_available():
            chain.append(provider)
        else:
            print(f"  Info: {provider.name} not configured ({_PROVIDER_ENV_HINTS.get(name, '')})")

    return chain


# ---------------------------------------------------------------------------
# Triage engine
# ---------------------------------------------------------------------------

class TriageEngine:
    """
    Coordinates AI provider fallback, JSM reads/writes, and result reporting.
    """

    def __init__(
        self,
        providers: Optional[list[AIProvider]] = None,
        org_context: Optional[str] = None,
        dry_run: bool = False,
    ):
        """
        Args:
            providers:    Ordered list of AI providers.  Auto-detected if None.
            org_context:  Free-text describing your org, teams, and products –
                          injected into every triage prompt to improve routing.
            dry_run:      When True, never write back to JSM.
        """
        self.providers = providers if providers is not None else build_provider_chain()
        self.org_context = org_context or os.getenv("TRIAGE_ORG_CONTEXT", "")
        self.dry_run = dry_run
        self._system_prompt = SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Core triage
    # ------------------------------------------------------------------

    def triage_ticket(self, ticket: Ticket) -> TriageResult:
        """
        Run the ticket through the provider chain, returning the first success.

        Raises:
            RuntimeError: If all providers fail.
        """
        user_prompt = _build_user_prompt(ticket, self.org_context)
        errors: list[str] = []

        for provider in self.providers:
            try:
                result = provider.triage_ticket(
                    system_prompt=self._system_prompt,
                    user_prompt=user_prompt,
                )
                return result
            except ProviderError as exc:
                errors.append(f"{provider.name}: {exc}")
                print(f"  Provider {provider.name} failed – trying next... ({exc})")

        raise RuntimeError(
            f"All providers failed for {ticket.key}:\n" + "\n".join(errors)
        )

    def triage_and_apply(
        self,
        ticket: Ticket,
        jsm_client,
        *,
        post_comment: bool = True,
        update_priority: bool = False,
        add_triage_label: bool = True,
    ) -> TriageResult:
        """
        Triage a ticket and optionally write results back to JSM.

        Args:
            ticket:           The ticket to triage.
            jsm_client:       A JSMClient instance.
            post_comment:     Post the triage summary as a JSM comment.
            update_priority:  Overwrite the ticket's priority field.
            add_triage_label: Add 'ai-triaged' label to the ticket.

        Returns:
            The TriageResult.
        """
        result = self.triage_ticket(ticket)

        if self.dry_run:
            return result

        if post_comment:
            try:
                jsm_client.add_multiline_comment(ticket.key, result.to_plaintext_comment())
            except Exception as exc:
                print(f"  Warning: could not post comment to {ticket.key}: {exc}")

        if update_priority and result.priority != ticket.priority:
            try:
                jsm_client.update_priority(ticket.key, result.priority)
            except Exception as exc:
                print(f"  Warning: could not update priority on {ticket.key}: {exc}")

        if add_triage_label:
            try:
                labels = list(set(ticket.labels + ["ai-triaged"]))
                jsm_client.update_labels(ticket.key, labels)
            except Exception as exc:
                print(f"  Warning: could not add label to {ticket.key}: {exc}")

        return result

    # ------------------------------------------------------------------
    # Interactive chat
    # ------------------------------------------------------------------

    def chat(self, messages: list[dict], ticket_context: Optional[Ticket] = None) -> str:
        """
        Free-form chat with the first available provider.

        Optionally injects ticket context into the system message.
        """
        if ticket_context:
            system_content = (
                f"{self._system_prompt}\n\n"
                f"Current ticket context:\n"
                f"```json\n{json.dumps(ticket_context.to_triage_dict(), indent=2)}\n```"
            )
        else:
            system_content = (
                "You are a helpful IT helpdesk assistant with expertise in "
                "Atlassian JSM, ITSM best practices, and enterprise IT support."
            )

        full_messages = [{"role": "system", "content": system_content}] + messages

        errors: list[str] = []
        for provider in self.providers:
            try:
                return provider.chat(full_messages)
            except (ProviderError, NotImplementedError) as exc:
                errors.append(f"{provider.name}: {exc}")

        raise RuntimeError("All providers failed for chat:\n" + "\n".join(errors))

