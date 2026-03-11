#!/usr/bin/env python3
"""Interactive CLI for a persistent Azure OpenAI security triage assistant."""

from __future__ import annotations

import json
import os
import signal
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

API_VERSION = "2024-05-01-preview"
DEFAULT_TIMEOUT_SECONDS = 180
RUN_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "expired", "requires_action"}


@dataclass(frozen=True)
class AssistantConfig:
    """Runtime configuration loaded from environment variables."""

    endpoint_url: str
    deployment_name: str
    run_timeout_seconds: int

    @classmethod
    def from_env(cls) -> "AssistantConfig":
        endpoint = (os.getenv("ENDPOINT_URL") or "").strip()
        deployment = (os.getenv("DEPLOYMENT_NAME") or "").strip()
        timeout_raw = (os.getenv("ASSISTANT_RUN_TIMEOUT_SECONDS") or "").strip()

        missing: list[str] = []
        if not endpoint:
            missing.append("ENDPOINT_URL")
        if not deployment:
            missing.append("DEPLOYMENT_NAME")

        if missing:
            print(f"❌ Missing required environment variables: {', '.join(missing)}")
            print("   Add them to your .env file (see .env.example).")
            raise SystemExit(1)

        if not endpoint.startswith("https://"):
            print("❌ ENDPOINT_URL must start with 'https://'.")
            raise SystemExit(1)

        run_timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        if timeout_raw:
            try:
                run_timeout_seconds = int(timeout_raw)
            except ValueError:
                print("❌ ASSISTANT_RUN_TIMEOUT_SECONDS must be an integer.")
                raise SystemExit(1)
            if run_timeout_seconds < 10:
                print("❌ ASSISTANT_RUN_TIMEOUT_SECONDS must be at least 10 seconds.")
                raise SystemExit(1)

        return cls(
            endpoint_url=endpoint.rstrip("/"),
            deployment_name=deployment,
            run_timeout_seconds=run_timeout_seconds,
        )


class SecurityAssistantCLI:
    """Persistent chat interface for security triage workflows."""

    def __init__(self) -> None:
        self.session_file = Path.home() / ".security_assistant_session.json"
        self.config = AssistantConfig.from_env()
        self.client = self._initialize_client()
        self.assistant_id: str | None = None
        self.thread_id: str | None = None

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _initialize_client(self) -> AzureOpenAI:
        """Initialize Azure OpenAI client with Entra ID authentication."""
        try:
            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(),
                "https://cognitiveservices.azure.com/.default",
            )
            return AzureOpenAI(
                azure_ad_token_provider=token_provider,
                azure_endpoint=self.config.endpoint_url,
                api_version=API_VERSION,
            )
        except Exception as exc:
            print(f"❌ Failed to initialize Azure OpenAI client: {exc}")
            print("   Ensure Azure auth is configured (e.g., run 'az login').")
            raise SystemExit(1)

    def _load_session(self) -> None:
        """Load and validate persisted assistant/thread IDs."""
        if not self.session_file.exists():
            return

        try:
            payload = json.loads(self.session_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"⚠️  Could not read session file. Starting fresh: {exc}")
            return

        assistant_id = payload.get("assistant_id")
        thread_id = payload.get("thread_id")

        if isinstance(assistant_id, str) and assistant_id and self._assistant_exists(assistant_id):
            self.assistant_id = assistant_id
        elif assistant_id:
            print("⚠️  Previous assistant no longer exists. Creating a new one.")

        if isinstance(thread_id, str) and thread_id and self._thread_exists(thread_id):
            self.thread_id = thread_id
        elif thread_id:
            print("⚠️  Previous thread no longer exists. Creating a new thread.")

        if not self.assistant_id:
            self.thread_id = None

    def _save_session(self) -> None:
        """Persist session metadata with user-only file permissions."""
        payload = {
            "assistant_id": self.assistant_id,
            "thread_id": self.thread_id,
        }

        tmp_file: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.session_file.parent,
                prefix=".security_assistant_session.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(json.dumps(payload, indent=2))
                handle.flush()
                os.fsync(handle.fileno())
                tmp_file = Path(handle.name)

            os.chmod(tmp_file, stat.S_IRUSR | stat.S_IWUSR)
            tmp_file.replace(self.session_file)
        except OSError as exc:
            print(f"⚠️  Could not save session file: {exc}")
            if tmp_file and tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass

    def _assistant_exists(self, assistant_id: str) -> bool:
        try:
            self.client.beta.assistants.retrieve(assistant_id)
            return True
        except Exception:
            return False

    def _thread_exists(self, thread_id: str) -> bool:
        try:
            self.client.beta.threads.retrieve(thread_id)
            return True
        except Exception:
            return False

    def _create_assistant(self) -> str:
        assistant = self.client.beta.assistants.create(
            model=self.config.deployment_name,
            instructions=(
                "You are a Security Incident Triage Assistant powered by Azure AI Studio and "
                "integrated with Azure Sentinel. Help analysts investigate incidents, generate "
                "KQL, and recommend clear next steps. Be accurate, concise, and ask for "
                "clarification when context is missing."
            ),
            tools=[],
            tool_resources={},
            temperature=0.7,
            top_p=0.9,
        )
        self.assistant_id = assistant.id
        print(f"🤖 Assistant ready: {assistant.id}")
        return assistant.id

    def _create_thread(self) -> str:
        thread = self.client.beta.threads.create()
        self.thread_id = thread.id
        print(f"💬 Using thread: {thread.id}")
        return thread.id

    def _wait_for_run(self, run_id: str) -> Any:
        """Poll run status with timeout to avoid hanging forever."""
        if not self.thread_id:
            raise RuntimeError("Thread must be initialized")

        started = time.monotonic()
        print("🤔 Assistant is thinking", end="", flush=True)

        while True:
            if time.monotonic() - started > self.config.run_timeout_seconds:
                raise TimeoutError(
                    f"Run timed out after {self.config.run_timeout_seconds} seconds before completion"
                )

            time.sleep(1)
            print(".", end="", flush=True)
            run = self.client.beta.threads.runs.retrieve(thread_id=self.thread_id, run_id=run_id)
            if run.status in RUN_TERMINAL_STATUSES:
                print()
                return run

    @staticmethod
    def _extract_text_from_message(message: Any) -> str:
        """Best-effort extraction of text from an Assistant API message."""
        content = getattr(message, "content", None) or []
        chunks: list[str] = []
        for item in content:
            text_obj = getattr(item, "text", None)
            value = getattr(text_obj, "value", None)
            if isinstance(value, str):
                chunks.append(value)
        return "\n".join(chunks).strip()

    def _latest_assistant_text(self) -> str | None:
        """Return the most recent assistant text response in the current thread."""
        if not self.thread_id:
            return None

        messages = self.client.beta.threads.messages.list(thread_id=self.thread_id, limit=10)
        for message in messages.data:
            if getattr(message, "role", "") != "assistant":
                continue
            text = self._extract_text_from_message(message)
            if text:
                return text
        return None

    def _send_message(self, user_text: str) -> None:
        if not self.thread_id or not self.assistant_id:
            raise RuntimeError("Assistant and thread must be initialized")

        try:
            self.client.beta.threads.messages.create(thread_id=self.thread_id, role="user", content=user_text)
            run = self.client.beta.threads.runs.create(thread_id=self.thread_id, assistant_id=self.assistant_id)
            run = self._wait_for_run(run.id)
        except TimeoutError as exc:
            print(f"\n❌ {exc}")
            return
        except Exception as exc:
            print(f"\n❌ Failed to send message: {exc}\n")
            return

        if run.status == "completed":
            response = self._latest_assistant_text()
            if response:
                print(f"\n🤖 Assistant:\n{response}\n")
            else:
                print("\n⚠️  No assistant response text returned.\n")
            return

        if run.status == "requires_action":
            print("\n⚠️  Assistant requested tool/function actions (not configured in this CLI).\n")
            return

        error = getattr(getattr(run, "last_error", None), "message", None) or "Unknown error"
        print(f"\n❌ Run ended with status '{run.status}': {error}\n")

    def _show_status(self) -> None:
        """Display current runtime/session state."""
        print("\n📌 Session status")
        print(f"  Endpoint:       {self.config.endpoint_url}")
        print(f"  Deployment:     {self.config.deployment_name}")
        print(f"  Run timeout:    {self.config.run_timeout_seconds}s")
        print(f"  Assistant ID:   {self.assistant_id or '(none)'}")
        print(f"  Thread ID:      {self.thread_id or '(none)'}")
        print(f"  Session file:   {self.session_file}\n")

    def _signal_handler(self, _signum: int, _frame: Any) -> None:
        print("\n\n👋 Goodbye! Session saved.")
        self._save_session()
        raise SystemExit(0)

    @staticmethod
    def _print_welcome() -> None:
        print("=" * 60)
        print("🛡️  Security Incident Triage Assistant")
        print("=" * 60)
        print("Commands: help | new | status | quit/exit")
        print("Type any security triage question to start.\n")

    @staticmethod
    def _print_help() -> None:
        print("\n📚 Commands")
        print("  help         Show this help")
        print("  new          Start a new conversation thread")
        print("  status       Show active configuration and session IDs")
        print("  quit / exit  Save and close")
        print("\nExamples")
        print("  Analyze incident INC-12345")
        print("  Show KQL for failed logins")
        print("  What entities are involved in this incident?\n")

    def run(self) -> None:
        self._load_session()
        if not self.assistant_id:
            self._create_assistant()
        if not self.thread_id:
            self._create_thread()
        self._save_session()
        self._print_welcome()

        while True:
            try:
                user_input = input("💬 You: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n\n👋 Goodbye! Session saved.")
                self._save_session()
                break

            if not user_input:
                continue

            lowered = user_input.lower()
            if lowered in {"quit", "exit"}:
                print("👋 Goodbye! Session saved.")
                self._save_session()
                break
            if lowered == "help":
                self._print_help()
                continue
            if lowered == "new":
                self._create_thread()
                self._save_session()
                print("🆕 Started a new conversation thread.\n")
                continue
            if lowered == "status":
                self._show_status()
                continue

            self._send_message(user_input)


def main() -> None:
    cli = SecurityAssistantCLI()
    cli.run()


if __name__ == "__main__":
    main()
