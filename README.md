# Security Incident Triage Assistant CLI

A persistent chat interface for Azure OpenAI Assistant with remote MCP (Model Context Protocol) integration for Azure security tools.

## 🏗️ Architecture

This solution consists of two separate components:

### 1. **CLI Assistant** (This Repository)
- Azure OpenAI-powered security assistant
- Persistent chat interface with session management  
- MCP client that connects to remote security tools
- Runs locally on analyst workstations

### 2. **MCP Server** (Separate Azure Infrastructure)
- HTTP-based Model Context Protocol server
- Provides Azure security tools (Sentinel, Entra ID, Graph)
- Deployed on Azure Container Apps or similar
- Secured with API key authentication

```
┌─────────────────┐    HTTPS/API Key    ┌─────────────────┐
│   CLI Assistant │ ◄─────────────────► │   MCP Server    │
│   (This Repo)   │                     │  (Azure Infra)  │
│                 │                     │                 │
│ • Chat Interface│                     │ • Security Tools│
│ • Session Mgmt  │                     │ • Azure Auth    │
│ • OpenAI Client │                     │ • Sentinel API  │
└─────────────────┘                     └─────────────────┘
```

## ✨ Features

✅ **Persistent Sessions**: Automatically saves and restores conversations  
✅ **Cross-Platform**: Works on Windows, Linux, and macOS  
✅ **Interactive CLI**: Full-featured command-line interface  
✅ **Remote MCP**: Connects to production MCP server infrastructure  
✅ **Security Focus**: Specialized for security incident analysis  
✅ **Robust Error Handling**: Graceful recovery and helpful messages

## Prerequisites

- Python 3.8 or higher
- Azure OpenAI account with deployed model
- Access to a deployed MCP server with Azure security tools
- MCP server API key for authentication

## Setup

### 1. Install Dependencies

```powershell
# Install CLI dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

Copy the example environment file and configure it:

```powershell
Copy-Item .env.example .env
```

Edit `.env` with your configuration:

```env
# Azure OpenAI Configuration
ENDPOINT_URL=https://your-azure-openai-instance.openai.azure.com/
AZURE_OPENAI_API_KEY=your-azure-openai-key
DEPLOYMENT_NAME=your-gpt-model-deployment-name

# Remote MCP Server Configuration
MCP_SERVER_URL=https://your-mcp-server.azurecontainerapps.io
MCP_API_KEY=your-secure-api-key-here
```

### 3. MCP Server Infrastructure

The MCP server must be deployed separately on Azure infrastructure with:
- Azure Sentinel workspace access
- Entra ID permissions
- Log Analytics workspace connectivity
- API key authentication enabled

### 4. Start the Assistant

```powershell
python assistant.py
```

Or use the launcher script:

```powershell
python run_assistant.py
```

## Usage

### Starting the Assistant

When you first run the application, it will:
- Connect to Azure OpenAI
- Attempt to connect to the remote MCP server
- Load available Azure security tools from the MCP server
- Create a new security assistant (or restore existing one)
- Start a new conversation thread (or continue previous one)
- Display a welcome message with available commands

The assistant will work without MCP server connection but with limited functionality.

### Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands and examples |
| `new` | Start a new conversation thread |
| `quit` or `exit` | Exit the application (saves session) |
| `Ctrl+C` | Quick exit with session save |

### Example Interactions

```
💬 You: Analyze incident INC-12345
🤖 Assistant: I'd be happy to help you analyze incident INC-12345...

💬 You: Show me KQL to find failed logins
🤖 Assistant: Here's a KQL query to find failed login attempts...

💬 You: What entities are involved in the current incident?
🤖 Assistant: Based on our previous discussion about INC-12345...
```

## Session Management

The assistant automatically manages sessions through a hidden file in your home directory (`.security_assistant_session.json`). This enables:

- **Assistant Persistence**: Reuses the same assistant configuration across sessions
- **Conversation Continuity**: Maintains conversation history and context
- **Automatic Recovery**: Handles cases where assistants or threads no longer exist

## File Structure

```
chat-development/
├── assistant.py           # Main CLI application (remote MCP client)
├── run_assistant.py      # Launcher script with dependency checks
├── requirements.txt      # Python dependencies for CLI
├── .env.example         # Environment template for remote configuration
├── README.md           # This file
└── mcp-server/         # MCP server reference implementation
    ├── main.py          # Original stdio MCP server
    ├── http_server.py   # Production HTTP MCP server
    ├── requirements.txt # MCP server dependencies
    └── Dockerfile       # Container configuration for deployment
```

## Dependencies

- `openai` - Azure OpenAI Python SDK
- `python-dotenv` - Environment variable management
- `aiohttp` - HTTP client for MCP server communication

## MCP Server Deployment

This repository includes a reference implementation of the MCP server in the `mcp-server/` directory. To deploy the MCP server to Azure:

### Option 1: Azure Container Apps

1. Build and push the container:
```powershell
# Build the container
docker build -t your-registry/azure-security-mcp:latest ./mcp-server

# Push to Azure Container Registry
docker push your-registry/azure-security-mcp:latest
```

2. Deploy to Container Apps with proper environment variables and Managed Identity

### Option 2: Azure Functions or App Service

Deploy the `http_server.py` as a web application with the appropriate Azure authentication configuration.

### MCP Server Environment Variables

The deployed MCP server requires:
- `AZURE_TENANT_ID` - Azure tenant ID
- `LOG_ANALYTICS_WORKSPACE_ID` - Log Analytics workspace ID
- `MCP_API_KEY` - API key for authentication
- `MCP_AUTH_REQUIRED=true` - Enable authentication
- Azure authentication via Managed Identity or Service Principal

## Cross-Platform Support

This CLI works on all major platforms:

- **Windows**: Run with `python assistant.py` or `py assistant.py`
- **Linux/macOS**: Run with `python3 assistant.py` or make executable with `chmod +x assistant.py && ./assistant.py`

## Security Features

The assistant is specifically designed for security incident analysis with:

- Built-in understanding of security incident workflows
- KQL query generation and optimization
- Azure Sentinel integration knowledge
- Entity analysis and correlation
- Investigation timeline creation
- Pattern recognition and threat hunting

## Troubleshooting

### Common Issues

1. **Missing .env file**:
   ```
   ❌ Error: Missing required environment variables.
   ```
   **Solution**: Create a `.env` file with your Azure OpenAI credentials.

2. **Invalid credentials**:
   ```
   ❌ Failed to initialize Azure OpenAI client
   ```
   **Solution**: Verify your `ENDPOINT_URL` and `AZURE_OPENAI_API_KEY` in the `.env` file.

3. **Assistant no longer exists**:
   ```
   ⚠️  Previous assistant no longer exists, creating new one...
   ```
   **Solution**: This is normal - the CLI will automatically create a new assistant.

### Getting Help

- Use the `help` command within the CLI for usage instructions
- Check that your Azure OpenAI deployment is active and accessible
- Ensure your API key has the necessary permissions

## License

This project is provided as-is for educational and development purposes.
