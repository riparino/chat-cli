"""Core triage engine – orchestrates retrieval, prompting, inference, parsing, and writeback."""

from __future__ import annotations

import os

from .audit import AuditLogger
from .config import AppConfig, load_app_config
from .jsm.models import Ticket
from .knowledge import KnowledgeRetriever
from .models import TriageResult
from .prompting import DOMAIN_SYSTEM_PROMPT, build_triage_user_prompt
from .providers.base import AIProvider, ProviderError

_PROVIDER_ENV_HINTS = {
    "azure_openai": "AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_DEPLOYMENT",
    "github_copilot": "GITHUB_TOKEN",
    "openai": "OPENAI_API_KEY",
    "ms_copilot": "MS_COPILOT_ENDPOINT",
    "rovo": "ATLASSIAN_DOMAIN + ATLASSIAN_EMAIL + ATLASSIAN_API_TOKEN",
}


def build_provider_chain(preferred_order=None, instances=None) -> list[AIProvider]:
    from .providers.azure_openai import AzureOpenAIProvider
    from .providers.github_copilot import GitHubCopilotProvider
    from .providers.openai_direct import OpenAIProvider
    from .providers.ms_copilot import MSCopilotProvider
    from .providers.rovo import RovoProvider

    default_classes = {
        "azure_openai": AzureOpenAIProvider,
        "github_copilot": GitHubCopilotProvider,
        "openai": OpenAIProvider,
        "ms_copilot": MSCopilotProvider,
        "rovo": RovoProvider,
    }
    if preferred_order is None:
        env_order = os.getenv("TRIAGE_PROVIDER_ORDER", "")
        preferred_order = [p.strip() for p in env_order.split(",") if p.strip()] if env_order else list(default_classes.keys())

    chain = []
    instances = instances or {}
    for name in preferred_order:
        provider = instances.get(name) or default_classes[name]()
        if provider.is_available():
            chain.append(provider)
        else:
            print(f"  Info: {provider.name} not configured ({_PROVIDER_ENV_HINTS.get(name, '')})")
    return chain


class TriageEngine:
    def __init__(self, providers=None, dry_run=False, config: AppConfig | None = None):
        self.providers = providers if providers is not None else build_provider_chain()
        self.config = config or load_app_config()
        self.dry_run = dry_run if dry_run else self.config.feature_flags.dry_run_default
        self.audit = AuditLogger()

    def _rovo_provider(self):
        for p in self.providers:
            if p.name == "Atlassian Rovo":
                return p
        return None

    def triage_ticket(self, ticket: Ticket) -> TriageResult:
        retriever = KnowledgeRetriever(self.config, rovo_provider=self._rovo_provider())
        snippets = retriever.retrieve(ticket)
        user_prompt = build_triage_user_prompt(ticket, self.config, snippets)
        errors = []

        for provider in self.providers:
            try:
                result = provider.triage_ticket(DOMAIN_SYSTEM_PROMPT, user_prompt)
                if not result.knowledge_sources_used:
                    result.knowledge_sources_used = [s.source_id for s in snippets]
                self.audit.log(
                    {
                        "ticket": ticket.key,
                        "provider": provider.name,
                        "sources": result.knowledge_sources_used,
                        "category": result.category,
                        "priority": result.priority,
                        "rationale": result.rationale,
                    }
                )
                return result
            except ProviderError as exc:
                errors.append(f"{provider.name}: {exc}")

        raise RuntimeError(f"All providers failed for {ticket.key}: {'; '.join(errors)}")

    def triage_and_apply(self, ticket: Ticket, jsm_client, *, post_comment=True, update_priority=False, add_triage_label=True) -> TriageResult:
        result = self.triage_ticket(ticket)
        if self.dry_run:
            return result

        if post_comment and self.config.feature_flags.allow_comment_posting:
            jsm_client.add_multiline_comment(ticket.key, result.to_plaintext_comment())

        if update_priority and self.config.feature_flags.allow_priority_updates and result.priority != ticket.priority:
            jsm_client.update_priority(ticket.key, result.priority)

        if add_triage_label and self.config.feature_flags.allow_label_updates:
            labels = list(set(ticket.labels + ["ai-triaged"]))
            jsm_client.update_labels(ticket.key, labels)

        return result

    def chat(self, messages: list[dict], ticket_context: Ticket | None = None) -> str:
        for provider in self.providers:
            try:
                return provider.chat(messages)
            except Exception:
                continue
        raise RuntimeError("All providers failed for chat")
