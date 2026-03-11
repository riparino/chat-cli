# chat-cli

A collection of AI-powered command-line tools for helpdesk and chat workflows.

---

## Tools

### jsm_triage — AI Helpdesk Ticket Triage

An enterprise-grade CLI that uses multiple AI backends to automatically triage
Atlassian Jira Service Management (JSM) helpdesk tickets across IT, HR,
Facilities, Finance, and any other service desk.

See **[jsm_triage/README.md](jsm_triage/README.md)** for full documentation.

**Quick start:**

```bash
cd jsm_triage
pip install -r requirements.txt
cp .env.example .env

python -m jsm_triage auth atlassian   # OAuth login
python -m jsm_triage status           # verify connections
python -m jsm_triage triage IT-42     # triage a ticket
python -m jsm_triage chat             # interactive assistant
```

Supported AI providers: Azure OpenAI · GitHub Copilot · OpenAI/ChatGPT · Microsoft Copilot · Atlassian Rovo

---

### assistant.py — Azure OpenAI Chat Assistant

A lightweight persistent chat assistant backed by Azure OpenAI Assistants API.
Useful as a standalone conversational CLI or as a reference for Azure OpenAI
Entra ID authentication patterns.

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
- Session metadata stored at `~/.security_assistant_session.json` with `0600` permissions

---

## Project structure

```text
chat-cli/
├── jsm_triage/             # Multi-provider JSM helpdesk triage CLI
│   ├── auth/               #   OAuth 2.0 3LO (Atlassian, Azure, GitHub)
│   ├── jsm/                #   Atlassian REST API client + data models
│   ├── providers/          #   AI provider backends
│   ├── cli.py              #   Entry point (rich TUI)
│   ├── triage_engine.py    #   Provider orchestration + prompt building
│   ├── requirements.txt
│   └── README.md
├── assistant.py            # Azure OpenAI chat assistant runtime
├── run_assistant.py        # Preflight checks + launcher
├── requirements.txt        # assistant.py dependencies
└── .env.example            # Environment template
```
