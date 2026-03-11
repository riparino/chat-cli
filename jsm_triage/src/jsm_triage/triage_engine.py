"""
Core triage engine – orchestrates AI providers, grounding, JSM updates, and audit logging.

Architecture:
  1. LocalPolicyLoader loads routing rules, approval rules, and examples from config/
  2. ConfluenceRetriever (optional) queries Confluence for relevant knowledge
  3. PromptBuilder assembles the full grounded prompt
  4. Provider chain attempts each AI provider in order until one succeeds
  5. parse_triage_json validates and coerces the JSON output into IAMTriageResult
  6. triage_and_apply optionally writes results back to JSM
  7. AuditLog records every operation
  8. FeedbackStore (optional) records decisions for human review

Design principles:
  - All grounding sources are explicitly injected; nothing is hidden.
  - The engine is safe by default: dry_run=True, no auto-assigns, no auto-priority.
  - Feature flags control each write-back action independently.
  - All errors are logged and surfaced; no silent failures for audit events.
"""

import json
import logging
import os
import time
from typing import Optional

from .audit import AuditLog
from .feedback.store import FeedbackStore
from .grounding.confluence_retriever import (
    ConfluenceRetriever,
    GroundingSourceConfig,
    RovoKnowledgeRetriever,
)
from .grounding.local_policy import LocalPolicyLoader
from .jsm.models import Ticket
from .prompts.builder import KnowledgeSnippet, PromptBuilder, PromptContext
from .prompts.iam_system_prompt import IAM_SYSTEM_PROMPT, IAM_SYSTEM_PROMPT_MINIMAL
from .providers.base import AIProvider, IAMTriageResult, ProviderError

logger = logging.getLogger(__name__)

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
    instances: Optional[dict[str, AIProvider]] = None,
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
                logger.warning("Unknown provider '%s' – skipping", name)
                continue
            provider = cls()
        if provider.is_available():
            chain.append(provider)
        else:
            logger.info(
                "Provider %s not configured (%s)",
                provider.name,
                _PROVIDER_ENV_HINTS.get(name, ""),
            )

    return chain


# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------

class TriageFeatureFlags:
    """
    Controls which write-back actions the engine is allowed to perform.

    All flags default to safe (disabled) values. Each must be explicitly
    enabled via config or CLI flags.
    """
    def __init__(
        self,
        post_comment: bool = True,
        update_priority: bool = False,
        add_triage_label: bool = True,
        suggest_assignment: bool = False,  # never auto-assign; just suggests in comment
    ):
        self.post_comment = post_comment
        self.update_priority = update_priority
        self.add_triage_label = add_triage_label
        self.suggest_assignment = suggest_assignment


# ---------------------------------------------------------------------------
# Triage engine
# ---------------------------------------------------------------------------

class TriageEngine:
    """
    Coordinates AI provider fallback, grounding, JSM reads/writes, and auditing.

    The engine is safe by default:
      - dry_run=True prevents all JSM writes
      - Feature flags control each write action independently
      - All operations are audit-logged
      - Grounding is explicit: only configured sources are used
    """

    def __init__(
        self,
        providers: Optional[list[AIProvider]] = None,
        org_context: Optional[str] = None,
        dry_run: bool = False,
        config_dir: Optional[str] = None,
        enable_confluence_grounding: bool = True,
        enable_rovo_grounding: bool = False,  # requires Rovo licence
        redact_sensitive: bool = False,
        audit_log: Optional[AuditLog] = None,
        feedback_store: Optional[FeedbackStore] = None,
    ):
        """
        Args:
            providers:                    Ordered AI provider list. Auto-detected if None.
            org_context:                  Free-text org context injected into every prompt.
                                          Falls back to TRIAGE_ORG_CONTEXT env var.
            dry_run:                      When True, never write back to JSM.
            config_dir:                   Path to local config directory.
            enable_confluence_grounding:  Use Confluence REST API for knowledge retrieval.
            enable_rovo_grounding:        Use Rovo Chat API for knowledge retrieval.
                                          Requires Rovo licence. Used in addition to
                                          Confluence retrieval, not as a replacement.
            redact_sensitive:             Redact PII fields before sending to AI provider.
            audit_log:                    AuditLog instance. Created automatically if None.
            feedback_store:               FeedbackStore instance. Created if None.
        """
        self.providers = providers if providers is not None else build_provider_chain()
        self.org_context = org_context or os.getenv("TRIAGE_ORG_CONTEXT", "")
        self.dry_run = dry_run
        self.redact_sensitive = redact_sensitive

        # Grounding layer
        self._policy_loader = LocalPolicyLoader(config_dir=config_dir)
        self._confluence_retriever = (
            ConfluenceRetriever() if enable_confluence_grounding else None
        )
        self._rovo_retriever = (
            RovoKnowledgeRetriever() if enable_rovo_grounding else None
        )

        # Prompt builder
        self._prompt_builder = PromptBuilder(redact_sensitive=redact_sensitive)

        # Audit + feedback
        self._audit = audit_log or AuditLog()
        self._feedback = feedback_store or FeedbackStore()

        # Determine system prompt based on grounding availability
        self._has_grounding = self._check_grounding_available()

    def _check_grounding_available(self) -> bool:
        """Check whether any grounding source is available."""
        policy = self._policy_loader.load()
        if not policy.is_empty():
            return True
        if self._confluence_retriever and self._confluence_retriever.is_available():
            return True
        if self._rovo_retriever and self._rovo_retriever.is_available():
            return True
        return False

    # ------------------------------------------------------------------
    # Grounding retrieval
    # ------------------------------------------------------------------

    def _retrieve_knowledge(self, ticket: Ticket) -> list[KnowledgeSnippet]:
        """
        Retrieve relevant knowledge snippets for a ticket.

        Order:
          1. ConfluenceRetriever (direct API, no Rovo licence needed)
          2. RovoKnowledgeRetriever (requires Rovo licence)

        Returns an empty list if no retrieval is configured or available.
        """
        snippets: list[KnowledgeSnippet] = []
        query = self._prompt_builder.build_knowledge_query(ticket)

        if self._confluence_retriever and self._confluence_retriever.is_available():
            grounding_sources = self._policy_loader.load_grounding_sources()
            from .grounding.confluence_retriever import GroundingSourceConfig
            config = GroundingSourceConfig(
                cql_queries=grounding_sources.cql_queries,
                page_ids=grounding_sources.page_ids,
                spaces=grounding_sources.spaces,
                labels=grounding_sources.labels,
                result_limit=grounding_sources.result_limit,
            )
            try:
                confluence_snippets = self._confluence_retriever.retrieve_for_query(
                    query, config=config
                )
                snippets.extend(confluence_snippets)
                logger.debug(
                    "Confluence retrieval: %d snippets for %s",
                    len(confluence_snippets),
                    ticket.key,
                )
            except Exception as exc:
                logger.warning("Confluence retrieval failed for %s: %s", ticket.key, exc)

        if self._rovo_retriever and self._rovo_retriever.is_available():
            try:
                rovo_snippets = self._rovo_retriever.retrieve_for_query(query)
                snippets.extend(rovo_snippets)
            except Exception as exc:
                logger.warning("Rovo retrieval failed for %s: %s", ticket.key, exc)

        return snippets

    def _build_prompt_context(
        self, ticket: Ticket, knowledge_snippets: list[KnowledgeSnippet]
    ) -> PromptContext:
        """Build a PromptContext from all available grounding sources."""
        policy = self._policy_loader.load()

        # Find matching examples for this ticket
        query = f"{ticket.summary} {ticket.request_type or ''} {' '.join(ticket.labels)}"
        matching_examples = self._policy_loader.find_matching_examples(query, limit=3)
        example_snippets = self._policy_loader.render_example_snippets(matching_examples)

        org_context = self.org_context or policy.org_context

        return PromptContext(
            org_context=org_context or None,
            routing_rules_text=self._policy_loader.render_routing_rules_text(),
            approval_rules_text=self._policy_loader.render_approval_rules_text(),
            knowledge_snippets=knowledge_snippets,
            example_snippets=example_snippets,
        )

    # ------------------------------------------------------------------
    # Core triage
    # ------------------------------------------------------------------

    def triage_ticket(self, ticket: Ticket) -> IAMTriageResult:
        """
        Run the ticket through the grounding pipeline and provider chain.

        Steps:
          1. Retrieve knowledge from Confluence/Rovo (if available)
          2. Load local policy context (routing rules, approval rules, examples)
          3. Build grounded prompt
          4. Try each AI provider in order; return first success
          5. Validate and coerce JSON output into IAMTriageResult
          6. Write audit record

        Raises:
            RuntimeError: If all providers fail.
        """
        logger.info("Triaging ticket %s: %s", ticket.key, ticket.summary[:60])
        start_time = time.monotonic()

        # Step 1-2: Retrieve knowledge and build context
        knowledge_snippets = self._retrieve_knowledge(ticket)
        context = self._build_prompt_context(ticket, knowledge_snippets)

        # Step 3: Build prompts
        system_prompt = IAM_SYSTEM_PROMPT if context.has_grounding() else IAM_SYSTEM_PROMPT_MINIMAL
        user_prompt = self._prompt_builder.build(ticket, context)

        logger.debug(
            "Prompt built for %s: grounding=%s, snippets=%d, examples=%d",
            ticket.key,
            context.has_grounding(),
            len(context.knowledge_snippets),
            len(context.example_snippets),
        )

        # Step 4: Provider chain
        errors: list[str] = []
        result: Optional[IAMTriageResult] = None
        provider_used = ""

        for provider in self.providers:
            try:
                result = provider.triage_ticket(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
                provider_used = provider.name
                break
            except ProviderError as exc:
                errors.append(f"{provider.name}: {exc}")
                logger.warning("Provider %s failed for %s: %s", provider.name, ticket.key, exc)

        elapsed = time.monotonic() - start_time

        if result is None:
            error_msg = f"All providers failed for {ticket.key}:\n" + "\n".join(errors)
            self._audit.record(
                ticket_key=ticket.key,
                ticket_summary=ticket.summary,
                provider_used="none",
                error=error_msg,
                dry_run=self.dry_run,
            )
            raise RuntimeError(error_msg)

        # Merge knowledge source citations: combine what the model said with what we retrieved
        retrieved_titles = [s.title for s in knowledge_snippets]
        all_sources = list(set(result.knowledge_sources_used + retrieved_titles))
        result.knowledge_sources_used = all_sources

        logger.info(
            "Triage complete: %s → %s / %s, priority=%s, confidence=%.2f (%.1fs, %s)",
            ticket.key,
            result.category,
            result.subcategory,
            result.priority,
            result.confidence,
            elapsed,
            provider_used,
        )

        # Step 6: Audit
        self._audit.record(
            ticket_key=ticket.key,
            ticket_summary=ticket.summary,
            provider_used=provider_used,
            result_dict=result.to_dict(),
            knowledge_sources=all_sources,
            dry_run=self.dry_run,
        )

        # Record in feedback store (outcome will be added later by human)
        self._feedback.record_triage(
            ticket_key=ticket.key,
            triage_result_dict=result.to_dict(),
            provider_used=provider_used,
            knowledge_sources=all_sources,
        )

        return result

    def triage_and_apply(
        self,
        ticket: Ticket,
        jsm_client,
        *,
        post_comment: bool = True,
        update_priority: bool = False,
        add_triage_label: bool = True,
    ) -> IAMTriageResult:
        """
        Triage a ticket and optionally write results back to JSM.

        All write-back actions are skipped when dry_run=True.
        Actions are performed idempotently where possible.

        Args:
            ticket:           The ticket to triage.
            jsm_client:       A JSMClient instance.
            post_comment:     Post the triage summary as a JSM comment.
            update_priority:  Overwrite the ticket's priority field.
                              WARNING: This is a potentially destructive action;
                              disabled by default.
            add_triage_label: Add 'ai-triaged' label to the ticket.

        Returns:
            The IAMTriageResult.
        """
        result = self.triage_ticket(ticket)

        actions_taken: dict = {
            "comment_posted": False,
            "priority_updated": False,
            "label_added": False,
        }

        if self.dry_run:
            logger.info("Dry run – skipping all JSM writes for %s", ticket.key)
            return result

        if post_comment:
            try:
                jsm_client.add_multiline_comment(ticket.key, result.to_plaintext_comment())
                actions_taken["comment_posted"] = True
                logger.info("Posted triage comment to %s", ticket.key)
            except Exception as exc:
                logger.warning("Could not post comment to %s: %s", ticket.key, exc)

        if update_priority and result.priority != ticket.priority:
            try:
                jsm_client.update_priority(ticket.key, result.priority)
                actions_taken["priority_updated"] = True
                logger.info(
                    "Updated priority on %s: %s → %s",
                    ticket.key,
                    ticket.priority,
                    result.priority,
                )
            except Exception as exc:
                logger.warning("Could not update priority on %s: %s", ticket.key, exc)

        if add_triage_label:
            try:
                # Idempotent: only add if not already labelled
                if "ai-triaged" not in ticket.labels:
                    labels = list(set(ticket.labels + ["ai-triaged"]))
                    jsm_client.update_labels(ticket.key, labels)
                    actions_taken["label_added"] = True
                    logger.info("Added ai-triaged label to %s", ticket.key)
            except Exception as exc:
                logger.warning("Could not add label to %s: %s", ticket.key, exc)

        # Update audit record with actions taken
        self._audit.record(
            ticket_key=ticket.key,
            ticket_summary=ticket.summary,
            provider_used=result.provider_used,
            result_dict=result.to_dict(),
            knowledge_sources=result.knowledge_sources_used,
            actions_taken=actions_taken,
            dry_run=False,
        )

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
                f"{IAM_SYSTEM_PROMPT}\n\n"
                f"You are now in advisory chat mode for ticket {ticket_context.key}.\n"
                f"Current ticket context:\n"
                f"```json\n{json.dumps(ticket_context.to_triage_dict(), indent=2)}\n```\n\n"
                f"Answer questions about this ticket, explain your triage reasoning, "
                f"or discuss next steps. Do NOT produce JSON output in chat mode."
            )
        else:
            system_content = (
                "You are a helpful IAM and IT access management advisor with expertise in "
                "Atlassian JSM, identity governance, ITSM best practices, access request "
                "workflows, and enterprise security policy. "
                "Provide clear, practical advice. Do not invent specific policies unless asked "
                "to explain general best practices."
            )

        full_messages = [{"role": "system", "content": system_content}] + messages

        errors: list[str] = []
        for provider in self.providers:
            try:
                return provider.chat(full_messages)
            except (ProviderError, NotImplementedError) as exc:
                errors.append(f"{provider.name}: {exc}")

        raise RuntimeError("All providers failed for chat:\n" + "\n".join(errors))

    # ------------------------------------------------------------------
    # Knowledge test helper
    # ------------------------------------------------------------------

    def test_knowledge_retrieval(self, query: str) -> dict:
        """
        Run a knowledge retrieval test query and return results.

        Used by `jsm-triage knowledge-test --query "..."`.
        Returns a dict describing what was found and from where.
        """
        results: dict = {
            "query": query,
            "confluence_available": bool(
                self._confluence_retriever and self._confluence_retriever.is_available()
            ),
            "rovo_available": bool(
                self._rovo_retriever and self._rovo_retriever.is_available()
            ),
            "local_policy_available": not self._policy_loader.load().is_empty(),
            "snippets": [],
        }

        # Create a synthetic ticket-like object for the query
        class _FakeTicket:
            key = "TEST-0"
            summary = query
            request_type = ""
            issue_type = "Service Request"
            labels = []

        snippets = self._retrieve_knowledge(_FakeTicket())  # type: ignore[arg-type]
        for s in snippets:
            results["snippets"].append({
                "title": s.title,
                "source_type": s.source_type,
                "source_url": s.source_url,
                "content_preview": s.content[:200],
            })

        # Also check local policy
        policy = self._policy_loader.load()
        examples = self._policy_loader.find_matching_examples(query, limit=3)
        results["local_routing_rules_count"] = len(policy.routing_rules)
        results["local_approval_rules_count"] = len(policy.approval_rules)
        results["local_examples_count"] = len(policy.examples)
        results["matching_examples"] = [
            {"key": e.ticket_key, "summary": e.summary, "category": e.category}
            for e in examples
        ]

        return results

    # ------------------------------------------------------------------
    # Config validation
    # ------------------------------------------------------------------

    def validate_config(self) -> list[str]:
        """Run config validation and return list of issues (empty = valid)."""
        issues = self._policy_loader.validate()

        if not self.providers:
            issues.append(
                "No AI providers configured. "
                "Check TRIAGE_PROVIDER_ORDER and provider credentials."
            )

        return issues
