# Migration Guide: v1.0 → v2.0

## Overview

Version 2.0 refactors jsm_triage from a generic helpdesk triage prototype into a production-ready IAM/access management triage tool. This document explains what changed and what you need to do to upgrade.

---

## Breaking Changes

### 1. New TriageResult schema (IAMTriageResult)

The triage JSON schema has been completely replaced. The old generic schema is gone.

**Old schema (v1.0):**
```json
{
  "priority": "High",
  "category": "Access & Permissions",
  "subcategory": "Password Reset",
  "suggested_team": "IT Support L1",
  "suggested_assignee": "Jane Doe",
  "summary": "Brief summary",
  "suggested_actions": ["..."],
  "escalate": false,
  "escalation_reason": null,
  "estimated_resolution": "4 hours",
  "confidence": 0.85
}
```

**New schema (v2.0):**
```json
{
  "request_type": "Azure Owner role for production subscription",
  "category": "Cloud / Infrastructure Access",
  "subcategory": "Azure RBAC role",
  "business_impact": "High",
  "urgency": "Standard",
  "priority": "High",
  "requires_approval": true,
  "approval_type": "Security Team Approval",
  "required_information_missing": false,
  "missing_fields": [],
  "likely_fulfilling_team": "Cloud Platform Team",
  "likely_assignment_group": "Cloud - Azure",
  "suggested_actions": ["..."],
  "recommended_next_step": "Pending Approval",
  "escalation_required": false,
  "escalation_reason": null,
  "confidence": 0.88,
  "rationale": "Facts: ... Classification: ... Gaps: ...",
  "policy_references": [],
  "knowledge_sources_used": []
}
```

**Backward-compatible aliases** (code using old field names still works):
- `result.suggested_team` → maps to `result.likely_fulfilling_team`
- `result.escalate` → maps to `result.escalation_required`
- `result.summary` → maps to `result.rationale`
- `result.suggested_assignee` → always returns `None` (never auto-assigns individuals)
- `result.estimated_resolution` → always returns `None`

### 2. System prompt replaced

The generic helpdesk system prompt has been replaced with an IAM-specific prompt in `src/jsm_triage/prompts/iam_system_prompt.py`. The prompt is significantly more detailed and IAM-focused.

### 3. Python version requirement

v2.0 requires Python 3.10+ (uses `list[str]` type hints without `from __future__ import annotations`).

### 4. New required dependency: pyyaml

```bash
pip install pyyaml>=6.0
```

Or reinstall the package:
```bash
cd jsm_triage && pip install -e ".[test]"
```

### 5. Package structure

Source code moved to `src/jsm_triage/` layout (was `jsm_triage/` flat layout). If you installed via `pip install -e .`, reinstall:
```bash
cd jsm_triage && pip install -e .
```

---

## New Features

### New CLI commands

```bash
# Show detailed triage reasoning (re-triages ticket, shows full explanation)
jsm-triage explain IT-42

# Record a human outcome for a triaged ticket
jsm-triage feedback IT-42

# Validate all local config files
jsm-triage validate-config

# Test knowledge retrieval with a query
jsm-triage knowledge-test --query "urgent termination access removal"

# Export approved feedback examples for grounding
jsm-triage export-examples

# Show staged candidate routing rules for admin review
jsm-triage review-rules
```

### New global flags

```bash
# Path to policy config directory
jsm-triage --config-dir /path/to/config triage IT-42

# Redact PII before sending to AI provider
jsm-triage --redact triage IT-42

# Disable Confluence knowledge retrieval
jsm-triage --no-confluence triage IT-42

# Enable Rovo-based knowledge retrieval (requires Rovo licence)
jsm-triage --rovo-grounding triage IT-42
```

### Local policy configuration

Create config files in one of:
- `TRIAGE_CONFIG_DIR` (env var)
- `~/.jsm_triage/config/`
- `jsm_triage/config/` (bundled examples, copy and customise)

Files:
- `triage_policy.yaml` – org context, VIP indicators, policy summary
- `routing_rules.yaml` – category → team routing
- `approval_rules.yaml` – when approval is required
- `grounding_sources.yaml` – Confluence spaces/pages to search
- `triage_examples.jsonl` – reviewed example tickets

### Grounding modes

**Mode A (Confluence REST API):** Enabled by default when `ATLASSIAN_DOMAIN`, `ATLASSIAN_EMAIL`, and `ATLASSIAN_API_TOKEN` are set and `grounding_sources.yaml` is configured. No additional licensing required.

**Mode B (local policy files):** Works offline using config files in the config directory.

**Mode C (Rovo):** Optional, enabled with `--rovo-grounding`. Requires Atlassian Rovo/Guard licence.

### Audit logging

All triage operations are now logged to `~/.jsm_triage/audit.jsonl`. Each record includes provider, sources, category, priority, and actions taken.

### Feedback store

Human outcomes are stored in `~/.jsm_triage/feedback.jsonl`. Approved examples can be exported to `triage_examples.jsonl` for future grounding.

---

## Migration Steps

1. **Update dependencies:**
   ```bash
   pip install pyyaml>=6.0
   # or
   cd jsm_triage && pip install -e ".[test]"
   ```

2. **Copy and customise config files:**
   ```bash
   cp -r config/ ~/.jsm_triage/config/
   # Edit config files to match your org
   ```

3. **Validate your config:**
   ```bash
   jsm-triage validate-config
   ```

4. **Test knowledge retrieval (optional):**
   ```bash
   jsm-triage knowledge-test --query "access request policy"
   ```

5. **Update any code that serialises TriageResult:**
   - `result.to_dict()` now includes all new fields
   - `result.to_plaintext_comment()` format has changed
   - Old field names still work via backward-compat properties

6. **Review JSM write behaviour:**
   - `--dry-run` is now the recommended default for new deployments
   - `--update-priority` is still disabled by default
   - Comments now include explicit advisory markers

---

## What Did NOT Change

- OAuth flows (Atlassian, Azure, GitHub) are unchanged
- JSM client (`jsm/client.py`) is unchanged
- Provider chain behaviour (fallback order) is unchanged
- `--dry-run`, `--provider`, `--verbose` flags unchanged
- `watch` mode behaviour is unchanged
- `chat` mode behaviour is unchanged
- Auth commands are unchanged
- `triage` command accepts same arguments (ticket keys, `--jql`, `--service-desk`, `--queue`)

---

## Known Limitations

- Confluence retrieval uses keyword/CQL search, not semantic vector search.
  Relevance depends on Confluence's built-in search ranking.
- Rovo retrieval returns generated text, not structured page references.
  Source URLs may not be available for Rovo-retrieved knowledge.
- The feedback loop does not perform automatic model fine-tuning or policy updates.
  All improvements require explicit admin review and manual config file updates.
- The system is not designed for high-throughput automated processing.
  It is a decision-support tool for human analysts.
