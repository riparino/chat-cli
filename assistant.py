#!/usr/bin/env python3
"""
Security Incident Triage Assistant CLI
A persistent chat interface for Azure OpenAI Assistant with session management.
"""

import os
import json
import time
import sys
import signal
from pathlib import Path
from typing import Optional, Dict, Any
from openai import AzureOpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv(".env")

class SecurityAssistantCLI:
    """CLI interface for the Security Incident Triage Assistant"""
    
    def __init__(self):
        """Initialize the CLI with Azure OpenAI client and session management"""
        self.session_file = Path.home() / ".security_assistant_session.json"
        self.client = None
        self.assistant_id = None
        self.thread_id = None
        self.session_data = {}
        
        # Initialize Azure OpenAI client with error handling
        self._initialize_client()
        
        # Set up graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _initialize_client(self) -> None:
        """Initialize Azure OpenAI client with proper error handling"""
        try:
            endpoint = os.getenv("ENDPOINT_URL")
            
            if not endpoint:
                print("❌ Error: Missing required environment variable ENDPOINT_URL.")
                print("Please ensure ENDPOINT_URL is set in your .env file.")
                sys.exit(1)
            
            # Import Azure Identity components
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
            
            # Initialize token provider for Entra ID authentication
            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(),
                "https://cognitiveservices.azure.com/.default"
            )
            
            self.client = AzureOpenAI(
                azure_ad_token_provider=token_provider,
                azure_endpoint=endpoint,
                api_version="2024-05-01-preview"
            )
            print("✅ Connected to Azure OpenAI with Entra ID authentication")
            
        except Exception as e:
            print(f"❌ Failed to initialize Azure OpenAI client: {e}")
            sys.exit(1)
    
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
        """Create or retrieve the Security Incident Triage Assistant"""
        try:
            assistant = self.client.beta.assistants.create(
                model = os.getenv("DEPLOYMENT_NAME"),
                instructions="""You are a Security Incident Triage Assistant powered by Azure AI Studio and integrated with Azure Sentinel. 
Your primary role is to help security analysts investigate and triage security incidents efficiently.

You have access to the following capabilities:
1. Search and retrieve security incidents from Azure Sentinel
2. Analyze incident details and provide insights
3. Execute KQL queries against security logs
4. Find related incidents and patterns
5. Suggest investigation steps and KQL queries
6. Create timelines of security events

Key guidelines:
- Always prioritize accuracy and security
- Provide clear, actionable recommendations
- Use specific incident IDs when referring to incidents
- Suggest relevant KQL queries for deeper investigation
- Be concise but thorough in your analysis
- If you're unsure about something, ask for clarification
- Remember context from previous messages in the conversation

When users ask about "entities", "users involved", "affected accounts", "hosts", "IP addresses" or similar terms without specifying an incident ID, assume they are referring to the current incident being discussed in the conversation.

Always maintain a professional, helpful tone while being security-focused.""",
                tools=[],
                tool_resources={},
                temperature=1,
                top_p=0.7
            )
            
            self.assistant_id = assistant.id
            print(f"🤖 Created new Security Assistant: {self.assistant_id}")
            return assistant.id
            
        except Exception as e:
            print(f"❌ Failed to create assistant: {e}")
            sys.exit(1)
    
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
    
    def _send_message(self, content: str) -> None:
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
                print("\n⚠️  Assistant requires action (function calling not implemented yet)\n")
                
            elif run.status == 'failed':
                error_message = getattr(run, 'last_error', {}).get('message', 'Unknown error')
                print(f"\n❌ Run failed: {error_message}\n")
                
            else:
                print(f"\n⚠️  Unexpected run status: {run.status}\n")
                
        except Exception as e:
            print(f"\n❌ Error sending message: {e}\n")
    
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