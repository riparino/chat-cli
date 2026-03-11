"""Base classes, shared data models, and shared utilities for AI providers.

This module defines:
- IAMTriageResult: the domain-specific structured output for IAM/access triage
- TriageResult: backward-compatible alias for IAMTriageResult
- parse_triage_json: robust JSON → IAMTriageResult parser
- AIProvider / OpenAICompatibleProvider: provider abstraction
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


class ProviderError(Exception):
    """Raised when an AI provider fails to produce a response."""
    pass


# ---------------------------------------------------------------------------
# IAM-specific triage result
# ---------------------------------------------------------------------------

# Valid enumerated values – used for validation and rendering
VALID_CATEGORIES = {
    "New Access Request",
    "Access Change",
    "Access Removal",
    "Onboarding",
    "Offboarding",
    "Privileged Access",
    "Shared Mailbox / Distribution List",
    "Group Membership",
    "License / Entitlement",
    "Authentication / MFA",
    "Password / Account Recovery",
    "Application Access",
    "Cloud / Infrastructure Access",
    "Developer Tooling Access",
    "Insufficient Information",
    "Policy Exception / Special Handling",
}

VALID_PRIORITIES = {"Critical", "High", "Medium", "Low"}
VALID_URGENCIES = {"Immediate", "High", "Standard", "Low"}
VALID_BUSINESS_IMPACTS = {"Critical", "High", "Medium", "Low"}
VALID_NEXT_STEPS = {
    "Return for Info",
    "Fulfill",
    "Route to Team",
    "Escalate",
    "Reject",
    "Pending Approval",
}


@dataclass
class IAMTriageResult:
    """
    Structured output from the IAM/access-focused triage AI.

    Every field is explicitly typed. Fields map 1:1 to the JSON schema the
    model is instructed to produce. All routing, approval, and escalation
    recommendations are advisory – they must be reviewed by a human.
    """

    # ---- Classification -----------------------------------------------
    request_type: str = ""          # free-text description of the specific request
    category: str = "Insufficient Information"
    subcategory: str = ""

    # ---- Impact / Priority --------------------------------------------
    business_impact: str = "Medium"     # Critical|High|Medium|Low
    urgency: str = "Standard"           # Immediate|High|Standard|Low
    priority: str = "Medium"            # Critical|High|Medium|Low

    # ---- Approval -------------------------------------------------------
    requires_approval: bool = False
    approval_type: Optional[str] = None  # e.g. "Manager Approval"

    # ---- Information Completeness -------------------------------------
    required_information_missing: bool = False
    missing_fields: list[str] = field(default_factory=list)

    # ---- Routing -------------------------------------------------------
    likely_fulfilling_team: Optional[str] = None
    likely_assignment_group: Optional[str] = None

    # ---- Actions / Next Step ------------------------------------------
    suggested_actions: list[str] = field(default_factory=list)
    recommended_next_step: str = "Route to Team"  # one of VALID_NEXT_STEPS

    # ---- Escalation ----------------------------------------------------
    escalation_required: bool = False
    escalation_reason: Optional[str] = None

    # ---- Confidence + Reasoning ----------------------------------------
    confidence: float = 0.0
    rationale: str = ""

    # ---- Knowledge Citations -------------------------------------------
    policy_references: list[str] = field(default_factory=list)
    knowledge_sources_used: list[str] = field(default_factory=list)

    # ---- Meta (not from model, set by engine) --------------------------
    provider_used: str = ""
    raw_response: str = ""

    # ---- Backward-compat properties ------------------------------------

    @property
    def suggested_team(self) -> Optional[str]:
        """Backward-compatible alias for likely_fulfilling_team."""
        return self.likely_fulfilling_team

    @property
    def suggested_assignee(self) -> Optional[str]:
        """Legacy field – we do not auto-assign individuals; always None."""
        return None

    @property
    def summary(self) -> str:
        """Backward-compatible alias for rationale."""
        return self.rationale

    @property
    def escalate(self) -> bool:
        """Backward-compatible alias for escalation_required."""
        return self.escalation_required

    @property
    def estimated_resolution(self) -> Optional[str]:
        """Not in new schema – returns None for backward compat."""
        return None

    # ---- Serialisation -------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "request_type": self.request_type,
            "category": self.category,
            "subcategory": self.subcategory,
            "business_impact": self.business_impact,
            "urgency": self.urgency,
            "priority": self.priority,
            "requires_approval": self.requires_approval,
            "approval_type": self.approval_type,
            "required_information_missing": self.required_information_missing,
            "missing_fields": self.missing_fields,
            "likely_fulfilling_team": self.likely_fulfilling_team,
            "likely_assignment_group": self.likely_assignment_group,
            "suggested_actions": self.suggested_actions,
            "recommended_next_step": self.recommended_next_step,
            "escalation_required": self.escalation_required,
            "escalation_reason": self.escalation_reason,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "policy_references": self.policy_references,
            "knowledge_sources_used": self.knowledge_sources_used,
            "provider_used": self.provider_used,
        }

    def to_plaintext_comment(self) -> str:
        """Format as plain text suitable for posting to JSM via the ADF API.

        This comment is explicitly marked as AI-generated and advisory.
        """
        lines = [
            "=== AI Triage Analysis (Advisory) ===",
            f"Provider: {self.provider_used}  |  Confidence: {self.confidence:.0%}",
            f"IMPORTANT: This is AI-generated analysis for human review only.",
            "",
            f"Priority:      {self.priority}",
            f"Urgency:       {self.urgency}",
            f"Business Impact: {self.business_impact}",
            f"Category:      {self.category}",
            f"Subcategory:   {self.subcategory}",
            f"Request Type:  {self.request_type}",
        ]
        if self.likely_fulfilling_team:
            lines.append(f"Suggested Team: {self.likely_fulfilling_team}")
        if self.likely_assignment_group:
            lines.append(f"Assignment Group: {self.likely_assignment_group}")
        lines += [
            "",
            f"Recommended Next Step: {self.recommended_next_step}",
            "",
            f"Rationale: {self.rationale}",
        ]

        if self.requires_approval:
            lines += [
                "",
                f"⚠ Approval Required: {self.approval_type or 'Yes'}",
            ]

        if self.required_information_missing and self.missing_fields:
            lines += [
                "",
                "Missing Information:",
            ]
            for f_name in self.missing_fields:
                lines.append(f"  • {f_name}")

        if self.suggested_actions:
            lines += ["", "Suggested Actions:"]
            for i, action in enumerate(self.suggested_actions, 1):
                lines.append(f"  {i}. {action}")

        if self.escalation_required:
            lines += [
                "",
                f"*** ESCALATION RECOMMENDED: {self.escalation_reason} ***",
            ]

        if self.policy_references:
            lines += ["", "Policy References:"]
            for ref in self.policy_references:
                lines.append(f"  • {ref}")

        if self.knowledge_sources_used:
            lines += ["", "Knowledge Sources Used:"]
            for src in self.knowledge_sources_used:
                lines.append(f"  • {src}")

        lines += [
            "",
            "(This comment was generated automatically by the JSM AI Triage Tool.)",
            "(All recommendations are advisory and require human review before action.)",
        ]
        return "\n".join(lines)


# Backward-compatible alias – existing code that imports TriageResult continues to work
TriageResult = IAMTriageResult


# ---------------------------------------------------------------------------
# JSON → IAMTriageResult parser
# ---------------------------------------------------------------------------

def _strip_json_fences(raw: str) -> str:
    """Remove markdown code fences if the model wrapped its JSON."""
    return re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()


def _coerce_list(val) -> list[str]:
    """Accept a list, a single string, or None; always return list[str]."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val] if val else []
    return []


def parse_triage_json(raw: str, provider_name: str) -> IAMTriageResult:
    """
    Parse a JSON string returned by any provider into an IAMTriageResult.

    Handles:
    - Markdown fences wrapping JSON
    - Missing or None fields (all have safe defaults)
    - Type coercion for lists and booleans
    - Invalid enum values (logged, not raised)

    Raises:
        ProviderError: If the string cannot be parsed as JSON at all.
    """
    clean = _strip_json_fences(raw)
    try:
        data = json.loads(clean)
    except json.JSONDecodeError as exc:
        # Try to extract a JSON object from within a larger string
        match = re.search(r"\{[\s\S]+\}", clean)
        if match:
            try:
                data = json.loads(match.group(0))
            except json.JSONDecodeError:
                raise ProviderError(
                    f"Model returned invalid JSON: {exc}\nRaw (first 500): {raw[:500]}"
                ) from exc
        else:
            raise ProviderError(
                f"Model returned invalid JSON: {exc}\nRaw (first 500): {raw[:500]}"
            ) from exc

    if not isinstance(data, dict):
        raise ProviderError(f"Expected JSON object, got {type(data).__name__}")

    # Validate and normalise enum fields
    category = data.get("category", "Insufficient Information")
    if category not in VALID_CATEGORIES:
        logger.warning("Unknown category '%s' from %s – using 'Insufficient Information'",
                       category, provider_name)
        category = "Insufficient Information"

    priority = data.get("priority", "Medium")
    if priority not in VALID_PRIORITIES:
        logger.warning("Unknown priority '%s' from %s – using 'Medium'", priority, provider_name)
        priority = "Medium"

    urgency = data.get("urgency", "Standard")
    if urgency not in VALID_URGENCIES:
        urgency = "Standard"

    business_impact = data.get("business_impact", "Medium")
    if business_impact not in VALID_BUSINESS_IMPACTS:
        business_impact = "Medium"

    next_step = data.get("recommended_next_step", "Route to Team")
    if next_step not in VALID_NEXT_STEPS:
        logger.warning("Unknown recommended_next_step '%s' – using 'Route to Team'", next_step)
        next_step = "Route to Team"

    confidence = float(data.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    return IAMTriageResult(
        request_type=str(data.get("request_type", "") or ""),
        category=category,
        subcategory=str(data.get("subcategory", "") or ""),
        business_impact=business_impact,
        urgency=urgency,
        priority=priority,
        requires_approval=bool(data.get("requires_approval", False)),
        approval_type=data.get("approval_type") or None,
        required_information_missing=bool(data.get("required_information_missing", False)),
        missing_fields=_coerce_list(data.get("missing_fields")),
        likely_fulfilling_team=data.get("likely_fulfilling_team") or None,
        likely_assignment_group=data.get("likely_assignment_group") or None,
        suggested_actions=_coerce_list(data.get("suggested_actions")),
        recommended_next_step=next_step,
        escalation_required=bool(data.get("escalation_required", False)),
        escalation_reason=data.get("escalation_reason") or None,
        confidence=confidence,
        rationale=str(data.get("rationale", "") or ""),
        policy_references=_coerce_list(data.get("policy_references")),
        knowledge_sources_used=_coerce_list(data.get("knowledge_sources_used")),
        provider_used=provider_name,
        raw_response=raw,
    )


# ---------------------------------------------------------------------------
# Provider ABCs
# ---------------------------------------------------------------------------

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
    def triage_ticket(self, system_prompt: str, user_prompt: str) -> IAMTriageResult:
        """
        Analyse a ticket and return a structured IAMTriageResult.

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

    def triage_ticket(self, system_prompt: str, user_prompt: str) -> IAMTriageResult:
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
                temperature=0.1,    # lower temperature for deterministic triage
                max_tokens=2048,    # increased for richer IAM schema output
            )
            raw = response.choices[0].message.content
            result = parse_triage_json(raw, self.name)
            logger.debug("Triage by %s: category=%s priority=%s confidence=%.2f",
                         self.name, result.category, result.priority, result.confidence)
            return result
        except ProviderError:
            raise
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
