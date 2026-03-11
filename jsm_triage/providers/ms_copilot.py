"""Microsoft Copilot / Azure AI Inference provider.

Supports Azure AI Foundry models, Azure AI Studio deployments, and
Microsoft Copilot via the azure-ai-inference SDK.

Auth priority:
  1. MS_COPILOT_API_KEY  →  plain API key / subscription key
  2. DefaultAzureCredential (az login / Managed Identity)

Required env vars:
    MS_COPILOT_ENDPOINT    Azure AI inference endpoint
                           e.g. https://<resource>.services.ai.azure.com/models
                           or   https://<project>.inference.ai.azure.com
Optional:
    MS_COPILOT_API_KEY     API key (omit to use Entra ID)
    MS_COPILOT_MODEL       model name (e.g. gpt-4o, Phi-3-medium-128k-instruct)
"""

import os
from typing import Optional

from .base import AIProvider, TriageResult, ProviderError, parse_triage_json

DEFAULT_MODEL = "gpt-4o"


class MSCopilotProvider(AIProvider):
    """Microsoft Copilot / Azure AI Inference provider."""

    def __init__(self):
        self._client: Optional[object] = None
        self._model: str = DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "Microsoft Copilot"

    def _build_client(self):
        try:
            from azure.ai.inference import ChatCompletionsClient
            from azure.core.credentials import AzureKeyCredential

            endpoint = os.getenv("MS_COPILOT_ENDPOINT")
            if not endpoint:
                raise ProviderError(
                    "MS_COPILOT_ENDPOINT is required for Microsoft Copilot"
                )

            self._model = os.getenv("MS_COPILOT_MODEL", DEFAULT_MODEL)
            api_key = os.getenv("MS_COPILOT_API_KEY")

            if api_key:
                self._client = ChatCompletionsClient(
                    endpoint=endpoint,
                    credential=AzureKeyCredential(api_key),
                )
            else:
                from azure.identity import DefaultAzureCredential

                self._client = ChatCompletionsClient(
                    endpoint=endpoint,
                    credential=DefaultAzureCredential(),
                )
        except ImportError as exc:
            raise ProviderError(
                f"Missing dependency for Microsoft Copilot – install azure-ai-inference: {exc}"
            ) from exc

    def is_available(self) -> bool:
        return bool(os.getenv("MS_COPILOT_ENDPOINT"))

    def triage_ticket(self, system_prompt: str, user_prompt: str) -> TriageResult:
        if not self._client:
            self._build_client()

        try:
            from azure.ai.inference.models import SystemMessage, UserMessage

            response = self._client.complete(
                messages=[
                    SystemMessage(content=system_prompt),
                    UserMessage(content=user_prompt),
                ],
                model=self._model,
                temperature=0.2,
                max_tokens=1024,
                model_extras={"response_format": {"type": "json_object"}},
            )
            raw = response.choices[0].message.content
            return parse_triage_json(raw, self.name)
        except Exception as exc:
            raise ProviderError(f"Microsoft Copilot triage failed: {exc}") from exc

    def chat(self, messages: list[dict], **kwargs) -> str:
        if not self._client:
            self._build_client()
        try:
            from azure.ai.inference.models import SystemMessage, UserMessage, AssistantMessage

            ai_messages = []
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "system":
                    ai_messages.append(SystemMessage(content=content))
                elif role == "assistant":
                    ai_messages.append(AssistantMessage(content=content))
                else:
                    ai_messages.append(UserMessage(content=content))

            response = self._client.complete(
                messages=ai_messages,
                model=self._model,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 2048),
            )
            return response.choices[0].message.content
        except Exception as exc:
            raise ProviderError(f"Microsoft Copilot chat failed: {exc}") from exc
