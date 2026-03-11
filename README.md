# Security Incident Triage Assistant CLI

A clean, persistent command-line chat assistant for Azure OpenAI, focused on security incident triage.

## Highlights

- **Structured**: launcher checks and chat runtime are separated.
- **Easy setup**: preflight checks for Python, dependencies, and `.env` values.
- **Secure defaults**: Entra ID auth + private local session file permissions.
- **Reliable UX**: graceful shutdown, session restore, and configurable run timeouts.

## Requirements

- Python **3.9+**
- Azure OpenAI resource + deployment name
- Entra ID authentication available locally (`az login`, service principal, or managed identity)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Copy and edit environment file:

```bash
cp .env.example .env
```

Required values:

```env
ENDPOINT_URL=https://your-resource.openai.azure.com/
DEPLOYMENT_NAME=your_model_deployment_name
```

Optional value:

```env
ASSISTANT_RUN_TIMEOUT_SECONDS=180
```

## Run

Recommended (includes preflight checks):

```bash
python run_assistant.py
```

Direct runtime:

```bash
python assistant.py
```

## Interactive commands

| Command | Description |
|---|---|
| `help` | Show command help and examples |
| `new` | Start a new conversation thread |
| `status` | Show current config/session metadata |
| `quit` / `exit` | Save session and close |

## Security notes

- Session metadata is written to `~/.security_assistant_session.json`.
- Session writes are **atomic** and permissions are restricted to user read/write (`0600`).
- Required env vars are validated before startup.
- Assistant run polling uses a timeout to avoid hanging forever.

## Project structure

```text
chat-cli/
├── assistant.py        # Main interactive runtime
├── run_assistant.py    # Preflight checks + launcher
├── requirements.txt    # Runtime dependencies
├── .env.example        # Environment template
└── README.md           # Documentation
```
