"""Tests for IAMTriageResult model and parse_triage_json."""

import json
import pytest

from jsm_triage.providers.base import (
    IAMTriageResult,
    TriageResult,
    parse_triage_json,
    ProviderError,
    VALID_CATEGORIES,
    VALID_PRIORITIES,
    VALID_NEXT_STEPS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _minimal_valid_json(**overrides) -> str:
    base = {
        "request_type": "GitHub org access for new engineer",
        "category": "Developer Tooling Access",
        "subcategory": "GitHub org access",
        "business_impact": "Medium",
        "urgency": "Standard",
        "priority": "Medium",
        "requires_approval": False,
        "approval_type": None,
        "required_information_missing": False,
        "missing_fields": [],
        "likely_fulfilling_team": "Developer Platform Team",
        "likely_assignment_group": "Dev Platform - GitHub",
        "suggested_actions": ["Add user to GitHub org", "Assign to relevant teams"],
        "recommended_next_step": "Fulfill",
        "escalation_required": False,
        "escalation_reason": None,
        "confidence": 0.9,
        "rationale": "Facts: Standard GitHub access request with manager approval.",
        "policy_references": [],
        "knowledge_sources_used": [],
    }
    base.update(overrides)
    return json.dumps(base)


# ---------------------------------------------------------------------------
# parse_triage_json – happy path
# ---------------------------------------------------------------------------

class TestParseTriageJsonValid:

    def test_minimal_valid(self):
        raw = _minimal_valid_json()
        result = parse_triage_json(raw, "TestProvider")
        assert result.category == "Developer Tooling Access"
        assert result.priority == "Medium"
        assert result.recommended_next_step == "Fulfill"
        assert result.confidence == 0.9
        assert result.provider_used == "TestProvider"

    def test_all_fields_preserved(self):
        raw = _minimal_valid_json(
            requires_approval=True,
            approval_type="Manager Approval",
            required_information_missing=True,
            missing_fields=["business_justification"],
            escalation_required=True,
            escalation_reason="VIP user blocked",
            policy_references=["Access Request Policy"],
            knowledge_sources_used=["IT Access Policy - Confluence"],
        )
        result = parse_triage_json(raw, "Azure OpenAI")
        assert result.requires_approval is True
        assert result.approval_type == "Manager Approval"
        assert result.required_information_missing is True
        assert result.missing_fields == ["business_justification"]
        assert result.escalation_required is True
        assert result.escalation_reason == "VIP user blocked"
        assert result.policy_references == ["Access Request Policy"]
        assert result.knowledge_sources_used == ["IT Access Policy - Confluence"]

    def test_strips_markdown_fences(self):
        raw = "```json\n" + _minimal_valid_json() + "\n```"
        result = parse_triage_json(raw, "TestProvider")
        assert result.category == "Developer Tooling Access"

    def test_extracts_json_from_prose(self):
        json_obj = _minimal_valid_json()
        raw = f"Here is my analysis:\n{json_obj}\nHope this helps."
        result = parse_triage_json(raw, "TestProvider")
        assert result.category == "Developer Tooling Access"

    def test_confidence_clamped_to_range(self):
        result = parse_triage_json(_minimal_valid_json(confidence=1.5), "P")
        assert result.confidence == 1.0

        result = parse_triage_json(_minimal_valid_json(confidence=-0.1), "P")
        assert result.confidence == 0.0

    def test_list_coercion_single_string(self):
        """A single string should be coerced to a list."""
        raw = _minimal_valid_json(missing_fields="business_justification")
        result = parse_triage_json(raw, "P")
        assert isinstance(result.missing_fields, list)

    def test_list_coercion_none(self):
        raw = _minimal_valid_json(suggested_actions=None, missing_fields=None)
        result = parse_triage_json(raw, "P")
        assert result.suggested_actions == []
        assert result.missing_fields == []

    def test_raw_response_preserved(self):
        raw = _minimal_valid_json()
        result = parse_triage_json(raw, "P")
        assert result.raw_response == raw

    def test_triageresult_alias(self):
        """TriageResult must be the same class as IAMTriageResult."""
        assert TriageResult is IAMTriageResult


# ---------------------------------------------------------------------------
# parse_triage_json – invalid input handling
# ---------------------------------------------------------------------------

class TestParseTriageJsonInvalid:

    def test_raises_on_pure_prose(self):
        with pytest.raises(ProviderError, match="invalid JSON"):
            parse_triage_json("This is not JSON at all.", "P")

    def test_invalid_category_defaults(self):
        raw = _minimal_valid_json(category="Made Up Category")
        result = parse_triage_json(raw, "P")
        assert result.category == "Insufficient Information"

    def test_invalid_priority_defaults(self):
        raw = _minimal_valid_json(priority="EXTREME")
        result = parse_triage_json(raw, "P")
        assert result.priority == "Medium"

    def test_invalid_urgency_defaults(self):
        raw = _minimal_valid_json(urgency="ASAP")
        result = parse_triage_json(raw, "P")
        assert result.urgency == "Standard"

    def test_invalid_next_step_defaults(self):
        raw = _minimal_valid_json(recommended_next_step="Just Do It")
        result = parse_triage_json(raw, "P")
        assert result.recommended_next_step == "Route to Team"

    def test_missing_fields_have_defaults(self):
        raw = json.dumps({})  # completely empty object
        result = parse_triage_json(raw, "P")
        assert result.category == "Insufficient Information"
        assert result.priority == "Medium"
        assert result.confidence == 0.5
        assert result.suggested_actions == []


# ---------------------------------------------------------------------------
# IAMTriageResult – model behaviour
# ---------------------------------------------------------------------------

class TestIAMTriageResult:

    def test_to_dict_contains_all_fields(self):
        result = IAMTriageResult(
            category="New Access Request",
            priority="High",
            recommended_next_step="Pending Approval",
        )
        d = result.to_dict()
        assert "request_type" in d
        assert "category" in d
        assert "business_impact" in d
        assert "urgency" in d
        assert "requires_approval" in d
        assert "missing_fields" in d
        assert "recommended_next_step" in d
        assert "knowledge_sources_used" in d

    def test_to_plaintext_comment_advisory_marker(self):
        result = IAMTriageResult(
            category="New Access Request",
            priority="High",
            recommended_next_step="Pending Approval",
        )
        comment = result.to_plaintext_comment()
        assert "AI Triage Analysis" in comment
        assert "Advisory" in comment or "advisory" in comment
        assert "human review" in comment.lower()

    def test_to_plaintext_comment_missing_fields(self):
        result = IAMTriageResult(
            category="New Access Request",
            required_information_missing=True,
            missing_fields=["business_justification", "manager_approval"],
        )
        comment = result.to_plaintext_comment()
        assert "business_justification" in comment
        assert "manager_approval" in comment

    def test_backward_compat_suggested_team(self):
        result = IAMTriageResult(likely_fulfilling_team="IAM Team")
        assert result.suggested_team == "IAM Team"

    def test_backward_compat_escalate(self):
        result = IAMTriageResult(escalation_required=True)
        assert result.escalate is True

    def test_backward_compat_suggested_assignee_is_none(self):
        """We never auto-assign individuals."""
        result = IAMTriageResult()
        assert result.suggested_assignee is None

    def test_backward_compat_summary(self):
        result = IAMTriageResult(rationale="Test rationale")
        assert result.summary == "Test rationale"


# ---------------------------------------------------------------------------
# Valid enum sets
# ---------------------------------------------------------------------------

class TestEnumSets:

    def test_all_categories_non_empty(self):
        for cat in VALID_CATEGORIES:
            assert cat and isinstance(cat, str)

    def test_all_priorities(self):
        assert VALID_PRIORITIES == {"Critical", "High", "Medium", "Low"}

    def test_all_next_steps(self):
        assert "Return for Info" in VALID_NEXT_STEPS
        assert "Fulfill" in VALID_NEXT_STEPS
        assert "Escalate" in VALID_NEXT_STEPS
        assert "Reject" in VALID_NEXT_STEPS
