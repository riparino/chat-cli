"""Prompt construction for IAM-focused JSM triage."""

from __future__ import annotations

import json
from textwrap import dedent

from .config import AppConfig
from .jsm.models import Ticket
from .models import KnowledgeSnippet


DOMAIN_SYSTEM_PROMPT = dedent(
    """
    You are an enterprise IAM/JSM triage analyst assistant for service desk workflows.
    You are NOT a SecOps incident response tool.
    Generate deterministic, policy-grounded advisory triage recommendations for human analysts.

    Rules:
    - Return ONE valid JSON object only.
    - Separate observed facts from inferences.
    - If evidence is insufficient, state so and mark required_information_missing=true.
    - Never invent policy references; only cite provided policy/routing/knowledge sources.
    - Treat output as advisory and safe-by-default.

    Required JSON fields:
    request_type, category, subcategory, business_impact, urgency, priority,
    requires_approval, approval_type, required_information_missing, missing_fields,
    likely_fulfilling_team, likely_assignment_group, suggested_actions,
    recommended_next_step, escalation_required, escalation_reason,
    confidence, rationale, policy_references, knowledge_sources_used, facts, inferences.
    """
).strip()


def build_triage_user_prompt(ticket: Ticket, config: AppConfig, snippets: list[KnowledgeSnippet]) -> str:
    payload = ticket.to_triage_dict()
    snippets_block = [s.to_dict() for s in snippets]
    context = {
        "ticket": payload,
        "triage_policy": {
            "categories": config.triage_policy.categories,
            "required_fields_by_category": config.triage_policy.required_fields_by_category,
            "vip_keywords": config.triage_policy.vip_keywords,
            "urgent_termination_keywords": config.triage_policy.urgent_termination_keywords,
        },
        "routing_rules": config.routing_rules.rules,
        "approval_rules": config.approval_rules.rules,
        "reviewed_examples": config.examples[:8],
        "knowledge_snippets": snippets_block,
    }
    return (
        "Analyse this IAM/JSM request and return strict JSON.\n"
        "Detect missing manager approval, missing app/system, missing justification, missing privileged expiry, unclear identity target, duplicates/conflicts.\n"
        "Recommend fulfill/return_for_info/reroute/escalate/reject as recommended_next_step.\n\n"
        f"```json\n{json.dumps(context, ensure_ascii=False, indent=2)}\n```"
    )
