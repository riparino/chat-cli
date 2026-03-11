import json

from jsm_triage.config import load_app_config, validate_config
from jsm_triage.providers.base import parse_triage_json


def test_parse_triage_json_domain_schema():
    raw = json.dumps(
        {
            "request_type": "access_request",
            "category": "Application Access",
            "subcategory": "Atlassian project access",
            "business_impact": "High",
            "urgency": "Medium",
            "priority": "High",
            "requires_approval": True,
            "approval_type": "manager",
            "required_information_missing": False,
            "missing_fields": [],
            "likely_fulfilling_team": "IAM Ops",
            "likely_assignment_group": "IAM-L1",
            "suggested_actions": ["validate manager approval"],
            "recommended_next_step": "fulfill",
            "escalation_required": False,
            "escalation_reason": None,
            "confidence": 0.8,
            "rationale": "Looks complete",
            "policy_references": ["IAM-001"],
            "knowledge_sources_used": ["routing-rule:Application Access"],
            "facts": ["request contains app name"],
            "inferences": ["likely low risk"],
        }
    )
    result = parse_triage_json(raw, "test")
    assert result.category == "Application Access"
    assert result.requires_approval is True


def test_validate_config_examples():
    config = load_app_config("config")
    issues = validate_config(config)
    assert issues == []
