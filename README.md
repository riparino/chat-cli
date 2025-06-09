# Security Incident Triage Assistant CLI

A persistent chat interface for Azure OpenAI Assistant with session management, designed specifically for security incident analysis and triage.

## Features

✅ **Persistent Sessions**: Automatically saves and restores your assistant and conversation threads  
✅ **Cross-Platform**: Works on Windows, Linux, and macOS  
✅ **Interactive CLI**: Full-featured command-line interface with helpful commands  
✅ **Error Handling**: Robust error handling and graceful recovery  
✅ **Session Management**: Maintains context across multiple sessions  
✅ **Security Focus**: Specialized for security incident analysis and KQL queries  

## Prerequisites

- Python 3.7 or higher
- Azure OpenAI account with deployed model
- Azure OpenAI API key and endpoint

## Setup

1. **Clone or download this repository**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create a `.env` file** in the project directory with your Azure OpenAI credentials:
   ```env
   ENDPOINT_URL=https://your-resource.openai.azure.com/
   AZURE_OPENAI_API_KEY=your_api_key_here
   ```

4. **Run the assistant:**
   ```bash
   python assistant.py
   ```
   
   Or use the launcher script:
   ```bash
   python run_assistant.py
   ```

## Usage

### Starting the Assistant

When you first run the application, it will:
- Connect to Azure OpenAI
- Create a new security assistant (or restore existing one)
- Start a new conversation thread (or continue previous one)
- Display a welcome message with available commands

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
├── assistant.py           # Main CLI application
├── run_assistant.py      # Launcher script with checks
├── requirements.txt      # Python dependencies
├── .env                 # Azure OpenAI credentials (you create this)
└── README.md           # This file
```

## Dependencies

- `openai` - Azure OpenAI Python SDK
- `python-dotenv` - Environment variable management

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
