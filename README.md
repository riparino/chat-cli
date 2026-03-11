# chat-cli

Azure-first command-line tools for Atlassian JSM triage and Azure OpenAI chat workflows.

---

## Tools

### jsm_triage - AI JSM Ticket Triage

An enterprise-grade CLI that uses multiple AI backends to triage Atlassian Jira Service Management (JSM) tickets for IAM, access management, and Microsoft/Azure-centric service requests.

The bundled sample policy pack assumes an Azure-first environment built around Entra ID, Microsoft 365, Azure subscriptions, GitHub Enterprise, and Atlassian.

See **[jsm_triage/README.md](jsm_triage/README.md)** for full documentation.

**Quick start:**

```bash
cd jsm_triage
pip install -e ".[test]"
cp .env.example .env

jsm-triage auth atlassian
jsm-triage auth azure
jsm-triage status
jsm-triage validate-config
jsm-triage --dry-run triage IT-42
```

Supported AI providers: Azure OpenAI · GitHub Copilot · OpenAI/ChatGPT · Microsoft Copilot · Atlassian Rovo

---

### assistant.py - Azure OpenAI Security Assistant

A lightweight persistent CLI for security incident triage backed by the Azure OpenAI Assistants API. Useful as a standalone security assistant or as a reference for Azure OpenAI Entra ID authentication patterns.

**Quick start:**

```bash
pip install -r requirements.txt
cp .env.example .env    # set ENDPOINT_URL and DEPLOYMENT_NAME
python run_assistant.py
```

#### Configuration

```env
ENDPOINT_URL=https://your-resource.openai.azure.com/
DEPLOYMENT_NAME=your_model_deployment_name
ASSISTANT_RUN_TIMEOUT_SECONDS=180   # optional
```

#### Interactive commands

| Command | Description |
|---------|-------------|
| `help` | Show command help |
| `new` | Start a new conversation thread |
| `status` | Show current config/session metadata |
| `quit` / `exit` | Save session and close |

#### Notes

- Requires Python 3.9+ and an Azure OpenAI resource with Entra ID auth (`az login`, service principal, or managed identity)
- Session metadata is stored at `~/.security_assistant_session.json` with best-effort user-only permissions

---

## Project structure

```text
chat-cli/
├── jsm_triage/
│   ├── config/                  # Sample Azure-first policy pack and grounding config
│   ├── src/jsm_triage/
│   │   ├── auth/                # OAuth 2.0 helpers (Atlassian, Azure, GitHub)
│   │   ├── feedback/            # Human review outcomes and example export
│   │   ├── grounding/           # Local policy + Confluence/Rovo retrieval
│   │   ├── jsm/                 # Atlassian REST API client + data models
│   │   ├── prompts/             # IAM triage system/user prompt builders
│   │   ├── providers/           # AI provider backends
│   │   ├── cli.py               # Entry point (Rich CLI)
│   │   └── triage_engine.py     # Provider orchestration + audit + feedback
│   ├── tests/
│   ├── .env.example
│   ├── MIGRATION.md
│   └── README.md
├── assistant.py                 # Azure OpenAI security assistant runtime
├── run_assistant.py             # Preflight checks + launcher
├── requirements.txt             # assistant.py dependencies
└── .env.example                 # Assistant environment template
```
