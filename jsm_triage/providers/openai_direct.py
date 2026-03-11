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

from .base import OpenAICompatibleProvider, ProviderError

DEFAULT_MODEL = "gpt-4o"


class OpenAIProvider(OpenAICompatibleProvider):
    """Direct OpenAI API provider – supports ChatGPT and compatible endpoints."""

    @property
    def name(self) -> str:
        return "OpenAI (ChatGPT)"

    def is_available(self) -> bool:
        return bool(os.getenv("OPENAI_API_KEY"))

    def _build_client(self) -> None:
        try:
            from openai import OpenAI

            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ProviderError("OPENAI_API_KEY environment variable is required")

            self._model = os.getenv("OPENAI_MODEL", DEFAULT_MODEL)

            kwargs = {"api_key": api_key}
            base_url = os.getenv("OPENAI_BASE_URL")
            org = os.getenv("OPENAI_ORG_ID")
            project = os.getenv("OPENAI_PROJECT_ID")
            if base_url:
                kwargs["base_url"] = base_url
            if org:
                kwargs["organization"] = org
            if project:
                kwargs["project"] = project

            self._client = OpenAI(**kwargs)
        except ImportError as exc:
            raise ProviderError(f"Missing dependency for OpenAI: {exc}") from exc
