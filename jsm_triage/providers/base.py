"""Base classes and shared data models for AI providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


class ProviderError(Exception):
    """Raised when an AI provider fails to produce a response."""
    pass


@dataclass
class TriageResult:
    """Structured output from the triage AI."""

    # Core classification
    priority: str           # Critical / High / Medium / Low
    category: str           # e.g. "Access Request", "Hardware Issue"
    subcategory: str        # e.g. "Password Reset", "Laptop Replacement"

    # Routing
    suggested_team: Optional[str]       # e.g. "IT Support L1"
    suggested_assignee: Optional[str]   # specific person if known

    # Triage guidance
    summary: str                        # 1-2 sentence triage summary
    suggested_actions: list[str] = field(default_factory=list)   # step-by-step
    escalate: bool = False              # flag for immediate escalation
    escalation_reason: Optional[str] = None

    # SLA hint
    estimated_resolution: Optional[str] = None   # e.g. "4 hours", "1-2 days"

    # Meta
    confidence: float = 0.0            # 0.0 – 1.0
    provider_used: str = ""
    raw_response: str = ""

    def to_jira_comment(self) -> str:
        """Format as a Jira-compatible comment (wiki markup)."""
        lines = [
            "h3. AI Triage Analysis",
            f"*Provider:* {self.provider_used}  |  *Confidence:* {self.confidence:.0%}",
            "",
            f"*Priority:* {self.priority}",
            f"*Category:* {self.category} / {self.subcategory}",
        ]
        if self.suggested_team:
            lines.append(f"*Suggested Team:* {self.suggested_team}")
        if self.suggested_assignee:
            lines.append(f"*Suggested Assignee:* {self.suggested_assignee}")
        if self.estimated_resolution:
            lines.append(f"*Est. Resolution:* {self.estimated_resolution}")
        lines += ["", f"*Summary:* {self.summary}", ""]
        if self.suggested_actions:
            lines.append("*Suggested Actions:*")
            for i, action in enumerate(self.suggested_actions, 1):
                lines.append(f"# {action}")
        if self.escalate:
            lines += ["", f"{{color:red}}*ESCALATION RECOMMENDED:* {self.escalation_reason}{{color}}"]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "priority": self.priority,
            "category": self.category,
            "subcategory": self.subcategory,
            "suggested_team": self.suggested_team,
            "suggested_assignee": self.suggested_assignee,
            "summary": self.summary,
            "suggested_actions": self.suggested_actions,
            "escalate": self.escalate,
            "escalation_reason": self.escalation_reason,
            "estimated_resolution": self.estimated_resolution,
            "confidence": self.confidence,
            "provider_used": self.provider_used,
        }


class AIProvider(ABC):
    """Abstract base class for all AI triage providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this provider is configured and reachable."""

    @abstractmethod
    def triage_ticket(self, ticket_data: dict, system_prompt: str, user_prompt: str) -> TriageResult:
        """
        Analyse a ticket and return a structured TriageResult.

        Args:
            ticket_data: Raw ticket fields from JSM.
            system_prompt: The triage system prompt.
            user_prompt: The per-ticket user prompt.

        Returns:
            TriageResult with structured triage output.

        Raises:
            ProviderError: If the provider cannot complete the request.
        """

    def chat(self, messages: list[dict], **kwargs) -> str:
        """
        Raw chat completion.  Providers may override for custom behaviour.
        Used by the interactive CLI mode.
        """
        raise NotImplementedError(f"{self.name} does not support raw chat mode")
