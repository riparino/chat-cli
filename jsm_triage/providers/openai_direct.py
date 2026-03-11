"""Direct OpenAI (ChatGPT) provider.

Required env vars:
    OPENAI_API_KEY         OpenAI API key
Optional:
    OPENAI_MODEL           defaults to gpt-4o
    OPENAI_BASE_URL        override for OpenAI-compatible APIs (e.g. local Ollama)
    OPENAI_ORG_ID          organization ID (enterprise)
    OPENAI_PROJECT_ID      project ID (optional)
"""

import os
from typing import Optional

from .base import AIProvider, TriageResult, ProviderError
from .azure_openai import _parse_triage_json

DEFAULT_MODEL = "gpt-4o"


class OpenAIProvider(AIProvider):
    """Direct OpenAI API provider – supports ChatGPT and compatible endpoints."""

    def __init__(self):
        self._client: Optional[object] = None
        self._model: str = DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "OpenAI (ChatGPT)"

    def _build_client(self):
        try:
            from openai import OpenAI

            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ProviderError("OPENAI_API_KEY environment variable is required")

            self._model = os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
            base_url = os.getenv("OPENAI_BASE_URL")   # None means default
            org = os.getenv("OPENAI_ORG_ID")
            project = os.getenv("OPENAI_PROJECT_ID")

            kwargs = {"api_key": api_key}
            if base_url:
                kwargs["base_url"] = base_url
            if org:
                kwargs["organization"] = org
            if project:
                kwargs["project"] = project

            self._client = OpenAI(**kwargs)
        except ImportError as exc:
            raise ProviderError(f"Missing dependency for OpenAI: {exc}") from exc

    def is_available(self) -> bool:
        return bool(os.getenv("OPENAI_API_KEY"))

    def triage_ticket(self, ticket_data: dict, system_prompt: str, user_prompt: str) -> TriageResult:
        if not self._client:
            self._build_client()

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=1024,
            )
            raw = response.choices[0].message.content
            return _parse_triage_json(raw, self.name)
        except Exception as exc:
            raise ProviderError(f"OpenAI triage failed: {exc}") from exc

    def chat(self, messages: list[dict], **kwargs) -> str:
        if not self._client:
            self._build_client()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 2048),
            )
            return response.choices[0].message.content
        except Exception as exc:
            raise ProviderError(f"OpenAI chat failed: {exc}") from exc
