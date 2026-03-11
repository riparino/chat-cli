"""
Prompt construction pipeline for IAM triage.

The PromptBuilder assembles the full user prompt for a triage request by combining:
  1. Ticket content (from the Ticket model)
  2. Org context (from env/config)
  3. Local routing rules and approval rules (from config files)
  4. Relevant Confluence/Rovo knowledge snippets (from grounding layer)
  5. Reviewed example tickets (from triage_examples.jsonl)

The system prompt is handled separately in iam_system_prompt.py.

Design principles:
- Grounding context is injected explicitly; nothing is hidden or inferred silently.
- Every grounding source is labeled so the model can cite it.
- The builder degrades gracefully when grounding is unavailable.
- Sensitive fields can be redacted before sending to external providers.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from ..jsm.models import Ticket

logger = logging.getLogger(__name__)

# Maximum lengths to prevent prompt bloat
MAX_DESCRIPTION_CHARS = 3000
MAX_KNOWLEDGE_SNIPPET_CHARS = 800
MAX_EXAMPLE_SNIPPET_CHARS = 600
MAX_ROUTING_RULES_CHARS = 2000
MAX_EXAMPLES_TO_INJECT = 3


# Fields that may contain PII or sensitive data and can be redacted
_REDACTABLE_FIELDS = {"reporter", "assignee", "description"}


@dataclass
class KnowledgeSnippet:
    """A single retrieved knowledge item (Confluence page, policy doc, etc.)."""
    title: str
    content: str
    source_url: Optional[str] = None
    source_type: str = "confluence"  # "confluence" | "local_policy" | "example"

    def to_prompt_block(self) -> str:
        url_note = f" ({self.source_url})" if self.source_url else ""
        content_truncated = self.content[:MAX_KNOWLEDGE_SNIPPET_CHARS]
        if len(self.content) > MAX_KNOWLEDGE_SNIPPET_CHARS:
            content_truncated += "... [truncated]"
        return f"[KNOWLEDGE: {self.title}{url_note}]\n{content_truncated}"


@dataclass
class PromptContext:
    """All grounding context to inject into a triage prompt."""
    org_context: Optional[str] = None
    routing_rules_text: Optional[str] = None
    approval_rules_text: Optional[str] = None
    knowledge_snippets: list[KnowledgeSnippet] = field(default_factory=list)
    example_snippets: list[str] = field(default_factory=list)

    def has_grounding(self) -> bool:
        return bool(
            self.routing_rules_text
            or self.approval_rules_text
            or self.knowledge_snippets
            or self.example_snippets
        )


class PromptBuilder:
    """
    Assembles the user-facing triage prompt.

    Usage:
        builder = PromptBuilder(redact_sensitive=True)
        prompt = builder.build(ticket, context)
    """

    def __init__(self, redact_sensitive: bool = False):
        self.redact_sensitive = redact_sensitive

    def build(
        self,
        ticket: Ticket,
        context: Optional[PromptContext] = None,
    ) -> str:
        """
        Build the complete user prompt for a single ticket triage request.

        Args:
            ticket:  The ticket to triage.
            context: Optional grounding context (rules, knowledge, examples).

        Returns:
            A formatted string to use as the user message.
        """
        ctx = context or PromptContext()
        parts: list[str] = []

        # --- Section 1: Task instruction --------------------------------
        parts.append("Triage the following IT service request ticket.")

        # --- Section 2: Ticket data -------------------------------------
        ticket_data = ticket.to_triage_dict()
        if self.redact_sensitive:
            ticket_data = _redact_ticket(ticket_data)

        # Truncate description
        if ticket_data.get("description"):
            desc = ticket_data["description"]
            if len(desc) > MAX_DESCRIPTION_CHARS:
                ticket_data["description"] = desc[:MAX_DESCRIPTION_CHARS] + "\n... [description truncated]"

        parts.append(
            "TICKET DATA:\n```json\n"
            + json.dumps(ticket_data, indent=2, ensure_ascii=False)
            + "\n```"
        )

        # --- Section 3: Org context -------------------------------------
        if ctx.org_context:
            parts.append(f"ORGANISATION CONTEXT:\n{ctx.org_context}")

        # --- Section 4: Routing rules -----------------------------------
        if ctx.routing_rules_text:
            rules_truncated = ctx.routing_rules_text[:MAX_ROUTING_RULES_CHARS]
            if len(ctx.routing_rules_text) > MAX_ROUTING_RULES_CHARS:
                rules_truncated += "\n... [routing rules truncated]"
            parts.append(f"ROUTING RULES (admin-curated):\n{rules_truncated}")

        # --- Section 5: Approval rules ----------------------------------
        if ctx.approval_rules_text:
            rules_truncated = ctx.approval_rules_text[:MAX_ROUTING_RULES_CHARS]
            parts.append(f"APPROVAL RULES (admin-curated):\n{rules_truncated}")

        # --- Section 6: Knowledge snippets ------------------------------
        if ctx.knowledge_snippets:
            snippet_blocks = []
            for snippet in ctx.knowledge_snippets:
                snippet_blocks.append(snippet.to_prompt_block())
            parts.append(
                "RELEVANT KNOWLEDGE (retrieved from Confluence/policy docs):\n"
                + "\n\n".join(snippet_blocks)
            )

        # --- Section 7: Reviewed examples -------------------------------
        if ctx.example_snippets:
            examples_text = "\n\n".join(
                ctx.example_snippets[:MAX_EXAMPLES_TO_INJECT]
            )
            parts.append(
                f"REVIEWED EXAMPLES (from approved historical tickets):\n{examples_text}"
            )

        # --- Section 8: Grounding notice --------------------------------
        if not ctx.has_grounding():
            parts.append(
                "NOTE: No internal policy context or knowledge was available for this request. "
                "Base your analysis on general IT/IAM best practices. "
                "Do not assume specific internal policies exist."
            )

        # --- Section 9: Output instruction ------------------------------
        parts.append(
            "Respond with a JSON triage object exactly matching the schema in your instructions. "
            "No markdown. No prose outside the JSON object."
        )

        return "\n\n".join(parts)

    def build_knowledge_query(self, ticket: Ticket) -> str:
        """
        Build a targeted search query for retrieving relevant Confluence knowledge.

        The query is used to search Confluence or ask Rovo for relevant guidance
        before constructing the full triage prompt.
        """
        # Combine key ticket signals into a search query
        parts = []
        if ticket.summary:
            parts.append(ticket.summary[:100])
        if ticket.request_type:
            parts.append(ticket.request_type)
        if ticket.issue_type and ticket.issue_type not in ("Service Request", "Task"):
            parts.append(ticket.issue_type)
        if ticket.labels:
            parts.extend(ticket.labels[:3])

        query = " ".join(parts) if parts else ticket.summary
        return query[:300]


def _redact_ticket(ticket_data: dict) -> dict:
    """
    Redact potentially sensitive fields before sending to external AI providers.

    The ticket key and structural fields are preserved; PII fields are masked.
    Redaction is applied at the prompt level, not to the stored ticket.
    """
    redacted = dict(ticket_data)
    for field_name in _REDACTABLE_FIELDS:
        if field_name in redacted and redacted[field_name]:
            val = redacted[field_name]
            if isinstance(val, str) and len(val) > 0:
                redacted[field_name] = "[REDACTED]"
    # Redact comment bodies too
    if "recent_comments" in redacted:
        redacted["recent_comments"] = [
            {**c, "body": "[REDACTED]", "author": "[REDACTED]"}
            for c in redacted.get("recent_comments", [])
        ]
    logger.debug("Sensitive fields redacted before sending to AI provider")
    return redacted
