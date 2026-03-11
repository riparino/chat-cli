"""Knowledge retrieval for Confluence/Rovo and local curated policies."""

from __future__ import annotations

from .config import AppConfig
from .jsm.models import Ticket
from .models import KnowledgeSnippet


class KnowledgeRetriever:
    def __init__(self, config: AppConfig, rovo_provider=None):
        self.config = config
        self.rovo_provider = rovo_provider

    def retrieve(self, ticket: Ticket) -> list[KnowledgeSnippet]:
        snippets: list[KnowledgeSnippet] = []
        # Local curated rules as first-class grounding.
        for rule in self.config.routing_rules.rules[:3]:
            snippets.append(
                KnowledgeSnippet(
                    source_id=f"routing-rule:{rule.get('category','unknown')}",
                    title=f"Routing rule for {rule.get('category', 'unknown')}",
                    excerpt=f"assignment_group={rule.get('assignment_group')} ; team={rule.get('fulfilling_team')}",
                    source_type="local_rule",
                )
            )

        if self.rovo_provider and getattr(self.rovo_provider, "retrieve_knowledge", None):
            query = f"{ticket.summary} {ticket.description[:400]}"
            snippets.extend(
                self.rovo_provider.retrieve_knowledge(
                    query=query,
                    curated_queries=self.config.grounding.confluence_queries,
                    max_snippets=self.config.grounding.max_snippets,
                )
            )

        return snippets[: self.config.grounding.max_snippets]
