# JSM AI Triage Tool — IAM/Access Management Edition

An enterprise-grade CLI that uses multiple AI backends to triage Atlassian Jira Service Management (JSM) tickets for **IAM, access management, and identity-related workflows**.

This is a **decision-support and triage-acceleration tool for human analysts and queue managers**. All recommendations are advisory and require human review before action.

## What it does

- Classifies access requests (New Access, Access Change, Offboarding, Privileged Access, GitHub access, AWS IAM, Entra groups, shared mailboxes, licenses, MFA, etc.)
- Detects missing information (manager approval, business justification, access duration, target identity)
- Determines whether approval is required and what type
- Recommends the likely fulfilling team and assignment group
- Recommends the next step (Fulfill / Return for Info / Escalate / Reject / Pending Approval)
- Explains reasoning with explicit fact/inference separation
- Grounds decisions in Confluence documentation and local policy files
- Improves over time through human-reviewed feedback (no autonomous policy mutation)
- Audits every decision for traceability

---

## Features

- **IAM-specific triage**: domain-tuned prompt and schema for access/identity workflows
- **Multi-provider AI**: Azure OpenAI · GitHub Copilot · OpenAI/ChatGPT · Microsoft Copilot · Atlassian Rovo
- **Automatic failover**: if the primary provider fails, the next one is tried
- **Confluence grounding**: retrieve relevant policy pages at triage time (no Rovo licence needed)
- **Local policy config**: routing rules, approval rules, reviewed examples – all admin-curated
- **Feedback loop**: capture human outcomes, export approved examples for future grounding
- **Audit log**: every triage decision recorded at `~/.jsm_triage/audit.jsonl`
- **Safe by default**: dry-run mode, no auto-assign, no auto-priority, explicit feature flags
- **OAuth 2.0**: Atlassian (auth code + PKCE), Azure (MSAL device flow), GitHub (device flow)
- **Full JSM integration**: read tickets, post comments, update priority, add labels
- **Batch & JQL support**: triage queues or JQL result sets

---

## Quick Start

```bash
cd jsm_triage
pip install -e ".[test]"      # install with test dependencies
cp .env.example .env          # fill in your credentials

# Authenticate (OAuth 2.0 – recommended)
jsm-triage auth atlassian     # opens browser for OAuth
jsm-triage auth github        # device flow
jsm-triage auth azure         # MSAL device flow

# Check everything is connected
jsm-triage status

# Validate your config files
jsm-triage validate-config

# Triage a single ticket (dry run by default is recommended for initial setup)
jsm-triage --dry-run triage IT-42

# Triage with JSM write-back
jsm-triage triage IT-42

# Triage by JQL
jsm-triage triage \
  --jql "project=IT AND status=Open AND labels!=ai-triaged" \
  --limit 50

# Watch a queue in real-time
jsm-triage watch --service-desk 1 --queue 3 --interval 30

# Show detailed triage reasoning
jsm-triage explain IT-42

# Test knowledge retrieval
jsm-triage knowledge-test --query "urgent termination access removal"

# Interactive chat
jsm-triage chat
jsm-triage chat --ticket IT-42
```

> **Without installing:** `python -m jsm_triage <command>` works identically.

---

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and fill in your values.

**Atlassian JSM (required for ticket access):**
```bash
ATLASSIAN_DOMAIN=your-org.atlassian.net
# OAuth 2.0 (recommended):
ATLASSIAN_CLIENT_ID=...
ATLASSIAN_CLIENT_SECRET=...
# Or API token (simpler, no OAuth):
ATLASSIAN_EMAIL=service-account@example.com
ATLASSIAN_API_TOKEN=...
```

**AI Providers (at least one required):**
```bash
# Azure OpenAI (preferred for enterprise)
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_KEY=...  # optional, uses Entra ID if omitted

# GitHub Copilot / GitHub Models
GITHUB_TOKEN=ghp_...
GITHUB_MODEL=gpt-4o  # optional

# OpenAI
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o  # optional

# Microsoft Copilot
MS_COPILOT_ENDPOINT=https://...
MS_COPILOT_API_KEY=...

# Atlassian Rovo (uses Atlassian credentials above)
# Requires Rovo/Guard licence
ROVO_AGENT_ID=...  # optional
```

**Triage behaviour:**
```bash
TRIAGE_ORG_CONTEXT="Brief description of your org and systems"
TRIAGE_PROVIDER_ORDER=azure_openai,github_copilot,openai,ms_copilot,rovo
TRIAGE_CONFIG_DIR=/path/to/config  # or use ~/.jsm_triage/config/
```

### Local Policy Configuration

Copy the bundled examples and customise them:

```bash
cp -r jsm_triage/config/ ~/.jsm_triage/config/
```

| File | Purpose |
|------|---------|
| `triage_policy.yaml` | Org context, VIP indicators, policy summary |
| `routing_rules.yaml` | Category → team routing rules |
| `approval_rules.yaml` | When approval is required and type |
| `grounding_sources.yaml` | Confluence spaces/pages to search |
| `triage_examples.jsonl` | Reviewed historical tickets for grounding |

Validate your config:
```bash
jsm-triage validate-config
```

---

## Grounding Modes

### Mode A: Confluence REST API (recommended)

Configured via `grounding_sources.yaml`. Retrieves relevant Confluence pages at triage time using CQL search. Uses the same API token as JSM — no additional licensing required.

```yaml
# grounding_sources.yaml
spaces: ["IT", "SECURITY"]
labels: ["access-policy", "iam-procedure"]
page_ids: ["123456789"]  # specific authoritative pages
result_limit: 5
```

Test it:
```bash
jsm-triage knowledge-test --query "AWS IAM role provisioning policy"
```

### Mode B: Local policy files (always available)

Routing rules, approval rules, and reviewed examples are loaded from config files and injected into every triage prompt. Works offline without Confluence access.

### Mode C: Rovo (optional, requires licence)

Enable with `--rovo-grounding`. Asks Rovo to find relevant guidance in Confluence. Useful when direct Confluence API access is restricted.

```bash
jsm-triage --rovo-grounding triage IT-42
```

---

## CLI Reference

```
jsm-triage [GLOBAL FLAGS] COMMAND [OPTIONS]

Global flags:
  --provider NAME     Override AI provider order (comma-separated)
  --dry-run           Analyse only, no JSM writes
  --verbose           Show raw JSON and debug output
  --config-dir PATH   Override config directory
  --redact            Redact PII before sending to AI provider
  --no-confluence     Disable Confluence knowledge retrieval
  --rovo-grounding    Enable Rovo knowledge retrieval (requires licence)

Commands:
  auth atlassian/azure/github   OAuth 2.0 login
  auth logout                   Logout (all providers or --provider-name)
  auth status                   Show OAuth session state

  status                        Show providers, config, and JSM connection

  triage [TICKET...]            Triage one or more tickets by key
  triage --jql "..."            Triage tickets matching JQL
  triage --service-desk ID      Triage tickets from a queue
         --queue ID
  triage --output-json FILE     Save results as JSON
  triage --no-comment           Skip posting AI comment
  triage --no-label             Skip adding ai-triaged label
  triage --update-priority      Overwrite ticket priority (use with care)

  watch --service-desk ID       Watch queue and auto-triage new tickets
        --queue ID
        --interval SECONDS      Poll interval (default: 60)

  explain TICKET                Show full triage reasoning for a ticket

  feedback TICKET               Record human outcome for a triaged ticket
  feedback --outcome accepted/corrected/rejected

  validate-config               Validate local policy config files

  knowledge-test --query "..."  Test knowledge retrieval

  export-examples [--output FILE]   Export approved examples to JSONL

  review-rules                  Show staged rule candidates for admin review

  chat                          Interactive chat mode
  chat --ticket TICKET          Chat anchored to a ticket
```

---

## Triage Schema

Every triage result includes:

| Field | Description |
|-------|-------------|
| `request_type` | Specific description of the request |
| `category` | IAM category (e.g. New Access Request, Offboarding) |
| `subcategory` | Specific subcategory (e.g. GitHub org access, AWS IAM role) |
| `business_impact` | Critical / High / Medium / Low |
| `urgency` | Immediate / High / Standard / Low |
| `priority` | Critical / High / Medium / Low |
| `requires_approval` | Whether approval is needed |
| `approval_type` | What type of approval (Manager / Security Team / etc.) |
| `required_information_missing` | Whether info is missing |
| `missing_fields` | Which specific fields are missing |
| `likely_fulfilling_team` | Recommended team |
| `likely_assignment_group` | Recommended JSM assignment group |
| `suggested_actions` | Step-by-step actions |
| `recommended_next_step` | Fulfill / Return for Info / Escalate / Reject / Pending Approval |
| `escalation_required` | Whether immediate escalation is needed |
| `escalation_reason` | Why |
| `confidence` | 0.0–1.0 |
| `rationale` | Structured reasoning (facts / classification / routing / gaps) |
| `policy_references` | Policy documents cited |
| `knowledge_sources_used` | Confluence pages or sources used |

---

## Feedback Loop

The feedback loop is explicit and human-controlled. No autonomous policy changes.

```bash
# After reviewing a triage result:
jsm-triage feedback IT-42
# Choose: accepted / corrected / rejected
# Optionally approve as a grounding example

# Export approved examples for future grounding:
jsm-triage export-examples --output config/triage_examples.jsonl

# Review proposed rule changes (must be manually applied):
jsm-triage review-rules
```

Feedback is stored at `~/.jsm_triage/feedback.jsonl`. It is never applied automatically.

---

## Audit Log

Every triage operation is logged to `~/.jsm_triage/audit.jsonl`:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "ticket_key": "IT-42",
  "ticket_summary": "New GitHub org access for contractor...",
  "provider_used": "Azure OpenAI",
  "dry_run": false,
  "knowledge_sources_used": ["IT Access Policy"],
  "actions_taken": {"comment_posted": true, "label_added": true},
  "result": {
    "category": "Developer Tooling Access",
    "priority": "Medium",
    "recommended_next_step": "Fulfill",
    "confidence": 0.88
  }
}
```

---

## Running Tests

```bash
cd jsm_triage
pip install -e ".[test]"
pytest tests/ -v
```

Tests cover:
- `IAMTriageResult` model validation and backward compatibility
- `parse_triage_json` parsing, defaults, and error handling
- `PromptBuilder` prompt construction and redaction
- `LocalPolicyLoader` config loading and validation
- `FeedbackStore` record creation, querying, and export

---

## Architecture

```
cli.py              – Entry point, all commands, Rich TUI
triage_engine.py    – Orchestration: grounding → prompt → providers → audit
prompts/
  iam_system_prompt.py – Domain-specific system prompt for IAM triage
  builder.py           – PromptBuilder assembles grounded user prompt
grounding/
  confluence_retriever.py – Confluence REST API + Rovo knowledge retrieval
  local_policy.py         – YAML/JSONL policy file loader
feedback/
  store.py             – Feedback store (outcomes, examples, staged rules)
audit.py             – Structured audit logging + logging configuration
providers/
  base.py              – IAMTriageResult, parse_triage_json, AIProvider ABC
  azure_openai.py      – Azure OpenAI provider
  github_copilot.py    – GitHub Models/Copilot provider
  openai_direct.py     – OpenAI/ChatGPT provider
  ms_copilot.py        – Microsoft Copilot provider
  rovo.py              – Atlassian Rovo provider (triage + knowledge)
jsm/
  client.py            – Atlassian JSM REST API client
  models.py            – Ticket, TicketComment, ServiceDesk, Queue models
auth/
  atlassian_oauth.py   – Atlassian OAuth 2.0 3LO + PKCE
  azure_oauth.py       – Azure MSAL device flow
  github_oauth.py      – GitHub device flow
  token_store.py       – Secure token persistence (~/.jsm_triage/tokens.json)
config/
  triage_policy.yaml       – Example: org context, VIP indicators
  routing_rules.yaml       – Example: category → team routing
  approval_rules.yaml      – Example: approval requirements
  grounding_sources.yaml   – Example: Confluence spaces/pages
  triage_examples.jsonl    – Example: reviewed historical tickets
```

---

## Explicit Limitations

- **No semantic search**: Confluence retrieval uses CQL keyword matching, not vector similarity.
- **No continuous indexing**: Knowledge is retrieved on-demand per triage request.
- **Rovo text only**: Rovo retrieval returns generated text, not structured page references.
- **No autonomous improvement**: Policy files only change when an admin manually updates them.
- **No auto-assignment**: Individual humans are never auto-assigned. Only teams are suggested.
- **Advisory only by default**: All recommendations require human review before action.

---

## Migration from v1.0

See [MIGRATION.md](MIGRATION.md) for a complete migration guide.
