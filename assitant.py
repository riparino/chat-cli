#!/usr/bin/env python3
"""
Security Incident Triage Assistant CLI
A persistent chat interface for Azure OpenAI Assistant with session management and MCP integration.
"""

import os
import json
import time
import sys
import signal
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, List
from openai import AzureOpenAI
from dotenv import load_dotenv
import aiohttp

# Load environment variables
load_dotenv(".env")

class SecurityAssistantCLI:
    """CLI interface for the Security Incident Triage Assistant with MCP integration"""
    
    def __init__(self):
        """Initialize the CLI with Azure OpenAI client, session management, and MCP connection"""
        self.session_file = Path.home() / ".security_assistant_session.json"
        self.client = None
        self.assistant_id = None
        self.thread_id = None
        self.session_data = {}
        
        # MCP Configuration - Remote server only
        self.mcp_server_url = os.getenv("MCP_SERVER_URL")  # No default - must be configured
        self.mcp_api_key = os.getenv("MCP_API_KEY")
        self.mcp_enabled = False
        self.mcp_tools = []
        
        # Initialize Azure OpenAI client with error handling
        self._initialize_client()
        
        # Test MCP connection and load available tools if configured
        if self.mcp_server_url:
            asyncio.run(self._initialize_mcp_connection())
        else:
            print("ℹ️  No MCP server configured - running without security tools")
        
        # Set up graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _initialize_client(self) -> None:
        """Initialize Azure OpenAI client with proper error handling"""
        try:
            endpoint = os.getenv("ENDPOINT_URL")
            api_key = os.getenv("AZURE_OPENAI_API_KEY")
            
            if not endpoint or not api_key:
                print("❌ Error: Missing required environment variables.")
                print("Please ensure ENDPOINT_URL and AZURE_OPENAI_API_KEY are set in your .env file.")
                sys.exit(1)
            
            self.client = AzureOpenAI(
                azure_endpoint=endpoint,
                api_key=api_key,
                api_version="2024-05-01-preview"
            )
            print("✅ Connected to Azure OpenAI")
        except Exception as e:
            print(f"❌ Failed to initialize Azure OpenAI client: {e}")
            sys.exit(1)
    
    async def _initialize_mcp_connection(self) -> None:
        """Initialize connection to remote MCP server and load available tools"""
        try:
            print(f"🔄 Connecting to MCP server at {self.mcp_server_url}")
            
            # Test MCP server connection
            headers = {"Content-Type": "application/json"}
            if self.mcp_api_key:
                headers["Authorization"] = f"Bearer {self.mcp_api_key}"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                # Test health endpoint
                try:
                    async with session.get(f"{self.mcp_server_url}/health", headers=headers) as response:
                        if response.status == 200:
                            print("✅ MCP server connection established")
                            self.mcp_enabled = True
                        elif response.status == 401:
                            print("❌ MCP server authentication failed - check MCP_API_KEY")
                            return
                        else:
                            print(f"⚠️  MCP server responded with status {response.status}")
                            return
                except aiohttp.ClientError as e:
                    print(f"⚠️  MCP server not available: {e}")
                    print("Continuing without MCP security tools...")
                    return
                
                # Load available tools if connected
                if self.mcp_enabled:
                    await self._load_mcp_tools(session, headers)
                    
        except Exception as e:
            print(f"⚠️  Error connecting to MCP server: {e}")
            print("Continuing without MCP tools...")
    
    async def _load_mcp_tools(self, session: aiohttp.ClientSession, headers: Dict[str, str]) -> None:
        """Load available tools from MCP server"""
        try:
            async with session.get(f"{self.mcp_server_url}/tools", headers=headers) as response:
                if response.status == 200:
                    tools_data = await response.json()
                    self.mcp_tools = tools_data.get("tools", [])
                    print(f"✅ Loaded {len(self.mcp_tools)} MCP tools")
                    
                    # Log available tools for debugging
                    if self.mcp_tools:
                        tool_names = [tool.get("name", "unknown") for tool in self.mcp_tools]
                        print(f"🔧 Available tools: {', '.join(tool_names)}")
                else:
                    print(f"⚠️  Failed to load MCP tools: {response.status}")
        except Exception as e:
            print(f"⚠️  Error loading MCP tools: {e}")
    
    async def _call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a remote MCP tool and return the result"""
        if not self.mcp_enabled or not self.mcp_server_url:
            return None
            
        try:
            headers = {"Content-Type": "application/json"}
            if self.mcp_api_key:
                headers["Authorization"] = f"Bearer {self.mcp_api_key}"
            
            payload = {
                "name": tool_name,
                "arguments": arguments
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.post(f"{self.mcp_server_url}/call-tool", 
                                      json=payload, headers=headers) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result
                    elif response.status == 401:
                        print(f"⚠️  MCP authentication failed for tool '{tool_name}'")
                        return None
                    else:
                        error_text = await response.text()
                        print(f"⚠️  MCP tool call failed ({response.status}): {error_text}")
                        return None
                        
        except Exception as e:
            print(f"⚠️  Error calling MCP tool '{tool_name}': {e}")
            return None
    
    def _load_session(self) -> None:
        """Load existing session data or create new session"""
        try:
            if self.session_file.exists():
                with open(self.session_file, 'r') as f:
                    self.session_data = json.load(f)
                    self.assistant_id = self.session_data.get('assistant_id')
                    self.thread_id = self.session_data.get('thread_id')
                
                # Verify the assistant still exists
                if self.assistant_id:
                    try:
                        self.client.beta.assistants.retrieve(self.assistant_id)
                        print(f"📋 Restored session with assistant: {self.assistant_id}")
                    except Exception:
                        print("⚠️  Previous assistant no longer exists, creating new one...")
                        self.assistant_id = None
                        self.thread_id = None
                
                # Verify the thread still exists
                if self.thread_id:
                    try:
                        self.client.beta.threads.retrieve(self.thread_id)
                        print(f"💬 Continuing conversation in thread: {self.thread_id}")
                    except Exception:
                        print("⚠️  Previous conversation thread no longer exists, creating new one...")
                        self.thread_id = None
            
        except Exception as e:
            print(f"⚠️  Warning: Could not load session data: {e}")
            self.session_data = {}
    
    def _save_session(self) -> None:
        """Save current session data"""
        try:
            self.session_data.update({
                'assistant_id': self.assistant_id,
                'thread_id': self.thread_id
            })
            
            with open(self.session_file, 'w') as f:
                json.dump(self.session_data, f, indent=2)
                
        except Exception as e:
            print(f"⚠️  Warning: Could not save session data: {e}")
    
    def _create_assistant(self) -> str:
        """Create or retrieve the Security Incident Triage Assistant with MCP tools"""
        try:
            # Convert MCP tools to OpenAI function format
            openai_tools = self._convert_mcp_tools_to_openai_format()
            
            assistant = self.client.beta.assistants.create(
                model = os.getenv("DEPLOYMENT_NAME"),
                instructions="""You are a Security Incident Triage Assistant powered by Azure AI Studio and integrated with Azure Sentinel. 
Your primary role is to help security analysts investigate and triage security incidents efficiently.

You have access to the following capabilities through integrated Azure security tools:
1. Search and retrieve security incidents from Azure Sentinel
2. Analyze incident details and provide insights
3. Execute KQL queries against security logs
4. Search Entra ID for user information
5. Retrieve sign-in logs and risk detections
6. Find related incidents and patterns

Key guidelines:
- Always prioritize accuracy and security
- Provide clear, actionable recommendations
- Use specific incident IDs when referring to incidents
- Suggest relevant KQL queries for deeper investigation
- Be concise but thorough in your analysis
- If you're unsure about something, ask for clarification
- Remember context from previous messages in the conversation
- Use the available security tools to gather real data when answering questions

When users ask about "entities", "users involved", "affected accounts", "hosts", "IP addresses" or similar terms without specifying an incident ID, assume they are referring to the current incident being discussed in the conversation.

Always maintain a professional, helpful tone while being security-focused.""",
                tools=openai_tools,
                tool_resources={},
                temperature=1,
                top_p=0.7
            )
            
            self.assistant_id = assistant.id
            tool_count = len(openai_tools)
            print(f"🤖 Created new Security Assistant with {tool_count} tools: {self.assistant_id}")
            return assistant.id
            
        except Exception as e:
            print(f"❌ Failed to create assistant: {e}")
            sys.exit(1)
    
    def _convert_mcp_tools_to_openai_format(self) -> List[Dict[str, Any]]:
        """Convert MCP tools to OpenAI Assistant function format"""
        openai_tools = []
        
        for mcp_tool in self.mcp_tools:
            openai_tool = {
                "type": "function",
                "function": {
                    "name": mcp_tool.get("name", ""),
                    "description": mcp_tool.get("description", ""),
                    "parameters": mcp_tool.get("inputSchema", {})
                }
            }
            openai_tools.append(openai_tool)
        
        return openai_tools
    
    def _create_thread(self) -> str:
        """Create a new conversation thread"""
        try:
            thread = self.client.beta.threads.create()
            self.thread_id = thread.id
            print(f"💬 Started new conversation: {self.thread_id}")
            return thread.id
            
        except Exception as e:
            print(f"❌ Failed to create thread: {e}")
            sys.exit(1)
    
    async def _handle_function_calls(self, run) -> None:
        """Handle function calls from the assistant"""
        try:
            if hasattr(run, 'required_action') and run.required_action:
                tool_calls = run.required_action.submit_tool_outputs.tool_calls
                tool_outputs = []
                
                for tool_call in tool_calls:
                    function_name = tool_call.function.name
                    function_args = json.loads(tool_call.function.arguments)
                    
                    print(f"🔧 Calling tool: {function_name}")
                    
                    # Call the MCP tool
                    result = await self._call_mcp_tool(function_name, function_args)
                    
                    if result:
                        output = json.dumps(result)
                    else:
                        output = json.dumps({"error": "Tool call failed"})
                    
                    tool_outputs.append({
                        "tool_call_id": tool_call.id,
                        "output": output
                    })
                
                # Submit tool outputs
                if tool_outputs:
                    self.client.beta.threads.runs.submit_tool_outputs(
                        thread_id=self.thread_id,
                        run_id=run.id,
                        tool_outputs=tool_outputs
                    )
                    
        except Exception as e:
            print(f"⚠️  Error handling function calls: {e}")
    
    async def _send_message_async(self, content: str) -> None:
        """Send a message and get response from the assistant"""
        try:
            # Add user message to thread
            self.client.beta.threads.messages.create(
                thread_id=self.thread_id,
                role="user",
                content=content
            )
            
            # Create and monitor run
            run = self.client.beta.threads.runs.create(
                thread_id=self.thread_id,
                assistant_id=self.assistant_id
            )
            
            print("🤔 Assistant is thinking...", end="", flush=True)
            
            # Monitor run status with visual feedback
            dots = 0
            while run.status in ['queued', 'in_progress', 'cancelling']:
                time.sleep(1)
                print(".", end="", flush=True)
                dots += 1
                if dots > 30:  # Reset dots every 30 seconds
                    print("\n🤔 Still processing...", end="", flush=True)
                    dots = 0
                
                run = self.client.beta.threads.runs.retrieve(
                    thread_id=self.thread_id,
                    run_id=run.id
                )
            
            print()  # New line after dots
            
            # Handle run completion
            if run.status == 'completed':
                messages = self.client.beta.threads.messages.list(
                    thread_id=self.thread_id,
                    limit=1
                )
                
                if messages.data:
                    assistant_message = messages.data[0]
                    if assistant_message.content:
                        content = assistant_message.content[0]
                        if hasattr(content, 'text') and hasattr(content.text, 'value'):
                            print(f"\n🤖 Assistant:\n{content.text.value}\n")
                        else:
                            print(f"\n🤖 Assistant: {content}\n")
                    else:
                        print("\n🤖 Assistant: (No response content)\n")
                else:
                    print("\n⚠️  No response received from assistant\n")
                    
            elif run.status == 'requires_action':
                # Handle function calls
                await self._handle_function_calls(run)
                
                # Continue monitoring the run
                while run.status in ['queued', 'in_progress', 'requires_action']:
                    if run.status == 'requires_action':
                        await self._handle_function_calls(run)
                    time.sleep(1)
                    run = self.client.beta.threads.runs.retrieve(
                        thread_id=self.thread_id,
                        run_id=run.id
                    )
                
                # Get final response after function calls
                if run.status == 'completed':
                    messages = self.client.beta.threads.messages.list(
                        thread_id=self.thread_id,
                        limit=1
                    )
                    
                    if messages.data:
                        assistant_message = messages.data[0]
                        if assistant_message.content:
                            content = assistant_message.content[0]
                            if hasattr(content, 'text') and hasattr(content.text, 'value'):
                                print(f"\n🤖 Assistant:\n{content.text.value}\n")
                            else:
                                print(f"\n🤖 Assistant: {content}\n")
                        else:
                            print("\n🤖 Assistant: (No response content)\n")
                else:
                    print(f"\n⚠️  Function calling completed with status: {run.status}\n")
                
            elif run.status == 'failed':
                error_message = getattr(run, 'last_error', {}).get('message', 'Unknown error')
                print(f"\n❌ Run failed: {error_message}\n")
                
            else:
                print(f"\n⚠️  Unexpected run status: {run.status}\n")
                
        except Exception as e:
            print(f"\n❌ Error sending message: {e}\n")
    
    def _send_message(self, content: str) -> None:
        """Synchronous wrapper for sending messages"""
        asyncio.run(self._send_message_async(content))
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle graceful shutdown on interrupt signals"""
        print("\n\n👋 Goodbye! Session saved.")
        self._save_session()
        sys.exit(0)
    
    def _print_welcome(self) -> None:
        """Print welcome message and instructions"""
        print("=" * 60)
        print("🛡️  Security Incident Triage Assistant")
        print("=" * 60)
        print("Welcome to your personal security investigation assistant!")
        print("I can help you analyze incidents, suggest KQL queries, and more.")
        print("\nCommands:")
        print("  Type your questions or security analysis requests")
        print("  'help' - Show available commands")
        print("  'new' - Start a new conversation")
        print("  'quit' or 'exit' - Exit the application")
        print("  Ctrl+C - Quick exit")
        print("=" * 60)
        print()
    
    def _print_help(self) -> None:
        """Print help information"""
        print("\n📚 Help - Security Assistant Commands:")
        print("━" * 50)
        print("  General Commands:")
        print("    help - Show this help message")
        print("    new  - Start a new conversation thread")
        print("    quit, exit - Exit the application")
        print()
        print("  Security Analysis:")
        print("    • Ask about specific incident IDs")
        print("    • Request KQL query suggestions")
        print("    • Analyze security events and patterns")
        print("    • Get investigation recommendations")
        print()
        print("  Examples:")
        print("    'Analyze incident INC-12345'")
        print("    'Show me KQL to find failed logins'")
        print("    'What entities are involved in the current incident?'")
        print("━" * 50)
        print()
    
    def run(self) -> None:
        """Main CLI loop"""
        try:
            # Load existing session or create new one
            self._load_session()
            
            # Ensure we have an assistant
            if not self.assistant_id:
                self._create_assistant()
            
            # Ensure we have a thread
            if not self.thread_id:
                self._create_thread()
            
            # Save session after initialization
            self._save_session()
            
            # Print welcome message
            self._print_welcome()
            
            # Main chat loop
            while True:
                try:
                    user_input = input("💬 You: ").strip()
                    
                    if not user_input:
                        continue
                    
                    # Handle special commands
                    if user_input.lower() in ['quit', 'exit']:
                        print("👋 Goodbye! Session saved.")
                        self._save_session()
                        break
                    
                    elif user_input.lower() == 'help':
                        self._print_help()
                        continue
                    
                    elif user_input.lower() == 'new':
                        self._create_thread()
                        self._save_session()
                        print("🆕 Started a new conversation thread.\n")
                        continue
                    
                    # Send message to assistant
                    self._send_message(user_input)
                    
                except KeyboardInterrupt:
                    print("\n\n👋 Goodbye! Session saved.")
                    self._save_session()
                    break
                    
                except EOFError:
                    print("\n\n👋 Goodbye! Session saved.")
                    self._save_session()
                    break
                    
        except Exception as e:
            print(f"❌ Fatal error: {e}")
            sys.exit(1)

def main():
    """Entry point for the CLI application"""
    cli = SecurityAssistantCLI()
    cli.run()

if __name__ == "__main__":
    main()
