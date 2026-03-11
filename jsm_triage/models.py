"""Typed models for IAM/JSM triage results and grounded knowledge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ALLOWED_PRIORITIES = {"Critical", "High", "Medium", "Low"}
ALLOWED_URGENCY = {"Critical", "High", "Medium", "Low"}
ALLOWED_IMPACT = {"Critical", "High", "Medium", "Low"}


@dataclass
class KnowledgeSnippet:
    source_id: str
    title: str
    excerpt: str
    source_type: str = "confluence"
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "title": self.title,
            "excerpt": self.excerpt,
            "source_type": self.source_type,
            "url": self.url,
        }


@dataclass
class TriageResult:
    request_type: str
    category: str
    subcategory: str
    business_impact: str
    urgency: str
    priority: str
    requires_approval: bool
    approval_type: str | None
    required_information_missing: bool
    missing_fields: list[str] = field(default_factory=list)
    likely_fulfilling_team: str | None = None
    likely_assignment_group: str | None = None
    suggested_actions: list[str] = field(default_factory=list)
    recommended_next_step: str = "request_more_info"
    escalation_required: bool = False
    escalation_reason: str | None = None
    confidence: float = 0.0
    rationale: str = ""
    policy_references: list[str] = field(default_factory=list)
    knowledge_sources_used: list[str] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    inferences: list[str] = field(default_factory=list)
    provider_used: str = ""
    raw_response: str = ""

    def validate(self) -> None:
        if self.priority not in ALLOWED_PRIORITIES:
            self.priority = "Medium"
        if self.urgency not in ALLOWED_URGENCY:
            self.urgency = "Medium"
        if self.business_impact not in ALLOWED_IMPACT:
            self.business_impact = "Medium"
        self.confidence = max(0.0, min(1.0, float(self.confidence or 0)))

    def to_dict(self) -> dict[str, Any]:
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
            "facts": self.facts,
            "inferences": self.inferences,
            "provider_used": self.provider_used,
        }

    def to_plaintext_comment(self) -> str:
        lines = [
            "=== AI IAM Triage Recommendation (Advisory) ===",
            f"Provider: {self.provider_used} | Confidence: {self.confidence:.0%}",
            f"Category: {self.category} / {self.subcategory}",
            f"Priority: {self.priority} | Urgency: {self.urgency} | Impact: {self.business_impact}",
            f"Approval required: {'Yes' if self.requires_approval else 'No'}",
            f"Next step: {self.recommended_next_step}",
            "",
            f"Rationale: {self.rationale}",
        ]
        if self.missing_fields:
            lines.append(f"Missing information: {', '.join(self.missing_fields)}")
        if self.suggested_actions:
            lines.append("Suggested actions:")
            lines.extend([f"  - {a}" for a in self.suggested_actions])
        if self.policy_references:
            lines.append(f"Policy references: {', '.join(self.policy_references)}")
        if self.knowledge_sources_used:
            lines.append(f"Knowledge sources: {', '.join(self.knowledge_sources_used)}")
        lines.append("(AI-generated advisory output. Human review required.)")
        return "\n".join(lines)
