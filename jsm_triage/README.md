# JSM AI Triage Tool

An enterprise-grade CLI that uses multiple AI backends to automatically triage
Atlassian Jira Service Management (JSM) helpdesk tickets.

## Features

- **Multi-provider AI**: Azure OpenAI · GitHub Copilot · OpenAI/ChatGPT · Microsoft Copilot · Atlassian Rovo
- **Automatic failover**: if the primary provider is unavailable, the next one in the chain is used
- **OAuth 2.0 (3LO)**: browser-based login for Atlassian (auth code + PKCE), Azure (MSAL device flow), GitHub (device flow) – no hard-coded secrets
- **Full JSM integration**: read tickets, post triage comments, update priority, add labels, transition workflow
- **Four run modes**: triage · watch (queue poller) · chat · status
- **Batch & JQL support**: triage whole queues or arbitrary JQL result sets
- **Dry-run mode**: analyse tickets without writing anything back to JSM

---

## Quick Start

```bash
cd jsm_triage
pip install -e .            # installs the jsm-triage command
cp .env.example .env        # fill in your credentials

# Authenticate (OAuth 2.0 – recommended)
jsm-triage auth atlassian   # opens browser
jsm-triage auth github      # device flow
jsm-triage auth azure       # MSAL device flow

# Check everything is connected
jsm-triage status

# Triage a single ticket
jsm-triage triage IT-42

# Triage all open, un-triaged tickets
jsm-triage triage \
  --jql "project=IT AND status=Open AND labels!=ai-triaged" \
  --limit 50

# Watch a queue in real-time
jsm-triage watch --service-desk 1 --queue 3 --interval 30

# Interactive chat
jsm-triage chat
jsm-triage chat --ticket IT-42
```

> **Without installing:** `python -m jsm_triage <command>` works identically.

---

## Authentication

### Atlassian JSM – OAuth 2.0 (recommended)

1. Go to <https://developer.atlassian.com/console/myapps/> → **Create app → OAuth 2.0**
2. Add callback URL: `http://localhost:8765/callback`
3. Add scopes:
   - `read:jira-work` `write:jira-work`
   - `read:jira-user`
   - `read:servicedesk-request` `write:servicedesk-request`
   - `offline_access` (enables refresh tokens)
4. Copy **Client ID** and **Secret** into `.env`
5. Run `jsm-triage auth atlassian` – browser opens, tokens stored in `~/.jsm_triage/tokens.json`

### Atlassian JSM – Basic auth (simpler)

Set `ATLASSIAN_EMAIL` and `ATLASSIAN_API_TOKEN` in `.env`.
Generate an API token at <https://id.atlassian.com/manage-profile/security/api-tokens>.

### GitHub Copilot

**Device flow (3LO):**

1. Create an OAuth App at <https://github.com/settings/developers> – enable **Device Flow**
2. Set `GITHUB_CLIENT_ID` in `.env`
3. Run `jsm-triage auth github`

**Personal Access Token:**  Set `GITHUB_TOKEN` in `.env` or export it as an environment variable.

The tool uses GitHub Models (`https://models.inference.ai.azure.com`) which is
OpenAI-API-compatible and provides access to GPT-4o and many other models via
your GitHub Copilot subscription.

### Azure OpenAI

| Method | Configuration |
|--------|--------------|
| API key | Set `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_KEY` |
| Entra ID (az login) | Set endpoint + deployment; omit API key |
| MSAL device flow | Set `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`; run `jsm-triage auth azure` |

### Microsoft Copilot (Azure AI Inference)

Set `MS_COPILOT_ENDPOINT` (your Azure AI Foundry endpoint).
Auth follows the same pattern as Azure OpenAI.

### OpenAI / ChatGPT

Set `OPENAI_API_KEY`.  Optionally set `OPENAI_MODEL` (default `gpt-4o`).

---

## Provider Fallback Chain

By default providers are tried in this order:

```
azure_openai → github_copilot → openai → ms_copilot → rovo
```

Override at runtime:

```bash
jsm-triage --provider github_copilot,openai triage IT-42
```

Or persistently via `.env`:

```
TRIAGE_PROVIDER_ORDER=github_copilot,azure_openai,openai
```

---

## Triage Output

For each ticket the AI produces:

| Field | Description |
|-------|-------------|
| `priority` | Critical / High / Medium / Low |
| `category` | Top-level category (see examples below) |
| `subcategory` | Specific sub-category |
| `suggested_team` | Routing recommendation (e.g. *IT Support L1*, *HR Ops*, *Facilities*) |
| `suggested_assignee` | Individual assignee if deterministic |
| `summary` | 1-2 sentence triage summary |
| `suggested_actions` | Step-by-step resolution guide |
| `escalate` | Boolean flag for immediate escalation |
| `escalation_reason` | Why escalation is recommended |
| `estimated_resolution` | SLA estimate (e.g. *4 hours*, *1-2 business days*) |
| `confidence` | 0–100% confidence score |

### Category examples

The AI adapts categories to your organisation context.  Out-of-the-box examples:

| Category | Example subcategories |
|----------|-----------------------|
| Access & Permissions | Password Reset, Account Lockout, VPN Access, Role Change |
| Hardware | Laptop Issue, Printer, Peripheral, Equipment Request |
| Software / Applications | Installation, Licence, Bug / Crash, Upgrade |
| Network & Connectivity | Wi-Fi, VPN, DNS, Proxy |
| Email & Collaboration | Mailbox Full, Calendar Sync, Teams / Slack, Shared Mailbox |
| Security Incident | Phishing, Data Loss, Malware, Suspicious Activity |
| Data & Storage | File Recovery, Backup, Cloud Storage, Permissions |
| Onboarding / Offboarding | New Starter Setup, Leaver Process, Equipment Return |
| HR Systems | Payroll Query, Leave Request, HRIS Access |
| Finance Systems | Expense Tool, Procurement, ERP Access |
| Facilities | Building Access, Desk Booking, AV / Meeting Room |
| General Enquiry | Policy Question, How-To, Information Request |

Results are posted as a comment on the ticket and the `ai-triaged` label is added.

---

## Reference

### CLI flags

```
jsm-triage [--provider NAME] [--dry-run] [--verbose] <command>

Commands:
  auth     atlassian | azure | github | logout | status
  triage   [TICKET…] [--jql JQL] [--queue ID --service-desk ID]
           [--limit N] [--no-comment] [--no-label] [--update-priority]
           [--output-json FILE]
  watch    --service-desk ID --queue ID [--interval SEC] [--limit N]
  chat     [--ticket KEY]
  status
```

### File structure

```
jsm_triage/
├── auth/
│   ├── atlassian_oauth.py   OAuth 2.0 auth-code + PKCE (3LO)
│   ├── azure_oauth.py       MSAL device flow
│   ├── github_oauth.py      GitHub device flow
│   └── token_store.py       Secure local token cache
├── jsm/
│   ├── client.py            Atlassian REST API client
│   └── models.py            Ticket / ServiceDesk / Queue data models
├── providers/
│   ├── azure_openai.py
│   ├── github_copilot.py
│   ├── ms_copilot.py
│   ├── openai_direct.py
│   └── rovo.py
├── cli.py                   Entry point (argparse)
├── triage_engine.py         Provider orchestration + prompt building
├── requirements.txt
└── .env.example
```

---

## Organisation Context

Inject free-text context about your org into every triage prompt to improve
team routing and priority decisions:

```env
# Generic example
TRIAGE_ORG_CONTEXT=We are a 500-person company with three helpdesk tiers: \
L1 (first-line support), L2 (systems & infrastructure), L3 (specialist/vendor). \
VIP users include the executive team and board members. \
Core systems: Microsoft 365, Okta, Zoom, Jira, Confluence.
```

Tailor it to your environment — the more detail you provide, the better the
routing and priority decisions:

```env
# Finance sector example
TRIAGE_ORG_CONTEXT=We are a 1000-person financial services firm. \
IT support tiers: L1 Helpdesk, L2 Infrastructure, L3 Security/Compliance. \
Regulated systems include Bloomberg Terminal, Salesforce, and Workday. \
VIPs: CFO, CTO, and board members always receive Critical or High priority.
```

```env
# Higher education example
TRIAGE_ORG_CONTEXT=University IT helpdesk supporting 20,000 students and 3,000 staff. \
Teams: Desktop Support, Network, Research Computing, AV & Teaching Tech, Identity. \
Student tickets are Medium unless exam-related; staff tickets follow standard SLA.
```

---

## Token Storage

OAuth tokens are stored in `~/.jsm_triage/tokens.json` with `0600` permissions
(owner-read-write only).  Refresh tokens are used automatically to keep sessions
alive without re-authenticating.

Run `jsm-triage auth logout` to clear all stored tokens.


## IAM/Access Triage Grounding

The production triage flow is explicitly grounded via:

1. **Local curated policy/rules/examples** from:
   - `config/triage_policy.yaml`
   - `config/routing_rules.yaml`
   - `config/approval_rules.yaml`
   - `config/triage_examples.jsonl`
2. **Optional Rovo retrieval** using curated Confluence query seeds in `config/grounding.yaml`.

Rovo grounding is adapter-based and depends on Atlassian licensing/API availability. If unavailable, triage still runs using local curated files.

### New operations commands

```bash
jsm-triage validate-config
jsm-triage knowledge-test --query "urgent termination access removal"
jsm-triage feedback IT-42 --outcome corrected --final-category Offboarding --final-assignment-group IAM-L2
jsm-triage review-rules
jsm-triage export-examples --output config/triage_examples.generated.jsonl
```

## Safety defaults

- Recommendation-first and dry-run by default.
- Priority/comment/label writeback are disabled by default until feature flags are enabled.
- AI output is advisory and requires human analyst review.
