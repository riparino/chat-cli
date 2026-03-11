"""Base classes, shared data models, and shared utilities for AI providers."""

import json
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
    suggested_actions: list[str] = field(default_factory=list)
    escalate: bool = False
    escalation_reason: Optional[str] = None

    # SLA hint
    estimated_resolution: Optional[str] = None   # e.g. "4 hours", "1-2 days"

    # Meta
    confidence: float = 0.0
    provider_used: str = ""
    raw_response: str = ""

    def to_plaintext_comment(self) -> str:
        """Format as plain text suitable for posting to JSM via the ADF API."""
        lines = [
            "=== AI Triage Analysis ===",
            f"Provider: {self.provider_used}  |  Confidence: {self.confidence:.0%}",
            "",
            f"Priority: {self.priority}",
            f"Category: {self.category} / {self.subcategory}",
        ]
        if self.suggested_team:
            lines.append(f"Suggested Team: {self.suggested_team}")
        if self.suggested_assignee:
            lines.append(f"Suggested Assignee: {self.suggested_assignee}")
        if self.estimated_resolution:
            lines.append(f"Est. Resolution: {self.estimated_resolution}")
        lines += ["", f"Summary: {self.summary}", ""]
        if self.suggested_actions:
            lines.append("Suggested Actions:")
            for i, action in enumerate(self.suggested_actions, 1):
                lines.append(f"  {i}. {action}")
        if self.escalate:
            lines += ["", f"*** ESCALATION RECOMMENDED: {self.escalation_reason} ***"]
        lines += ["", "(This comment was generated automatically by the AI Triage Tool)"]
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


def parse_triage_json(raw: str, provider_name: str) -> TriageResult:
    """Parse a JSON string returned by any provider into a TriageResult."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Model returned invalid JSON: {exc}\nRaw: {raw[:500]}") from exc

    return TriageResult(
        priority=data.get("priority", "Medium"),
        category=data.get("category", "General"),
        subcategory=data.get("subcategory", ""),
        suggested_team=data.get("suggested_team"),
        suggested_assignee=data.get("suggested_assignee"),
        summary=data.get("summary", ""),
        suggested_actions=data.get("suggested_actions", []),
        escalate=data.get("escalate", False),
        escalation_reason=data.get("escalation_reason"),
        estimated_resolution=data.get("estimated_resolution"),
        confidence=float(data.get("confidence", 0.5)),
        provider_used=provider_name,
        raw_response=raw,
    )


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
    def triage_ticket(self, system_prompt: str, user_prompt: str) -> TriageResult:
        """
        Analyse a ticket and return a structured TriageResult.

        Raises:
            ProviderError: If the provider cannot complete the request.
        """

    def chat(self, messages: list[dict], **kwargs) -> str:
        """
        Raw chat completion.  Providers may override for custom behaviour.
        Used by the interactive CLI mode.
        """
        raise NotImplementedError(f"{self.name} does not support raw chat mode")


class OpenAICompatibleProvider(AIProvider):
    """
    Shared implementation for providers that use the OpenAI Python SDK.

    Concrete subclasses implement only ``name``, ``is_available``, and
    ``_build_client`` (which sets ``self._client`` and ``self._model``).
    """

    def __init__(self):
        self._client = None
        self._model: str = ""

    @abstractmethod
    def _build_client(self) -> None:
        """Initialise ``self._client`` (openai.OpenAI / AzureOpenAI) and ``self._model``."""

    def triage_ticket(self, system_prompt: str, user_prompt: str) -> TriageResult:
        if not self._client:
            self._build_client()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=1024,
            )
            return parse_triage_json(response.choices[0].message.content, self.name)
        except Exception as exc:
            raise ProviderError(f"{self.name} triage failed: {exc}") from exc

    def chat(self, messages: list[dict], **kwargs) -> str:
        if not self._client:
            self._build_client()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 2048),
            )
            return response.choices[0].message.content
        except Exception as exc:
            raise ProviderError(f"{self.name} chat failed: {exc}") from exc
