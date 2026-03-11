"""GitHub Copilot / GitHub Models provider.

Uses the GitHub Models inference endpoint which is OpenAI-API-compatible.
Works with GitHub Copilot Individual, Business, and Enterprise plans.

Auth priority (first match wins):
  1. 3LO OAuth token stored by GitHubOAuth.login()
  2. GITHUB_TOKEN environment variable (PAT or Actions token)

Run 'jsm-triage auth github' for browser-based 3LO login.

Optional env vars:
    GITHUB_MODEL   defaults to gpt-4o  (any model listed on github.com/marketplace/models)
                   e.g. gpt-4o, gpt-4o-mini, Mistral-large, Meta-Llama-3.1-70B-Instruct
"""

import os
from typing import Optional

from .base import AIProvider, TriageResult, ProviderError
from .azure_openai import _parse_triage_json


GITHUB_MODELS_ENDPOINT = "https://models.inference.ai.azure.com"
DEFAULT_MODEL = "gpt-4o"


class GitHubCopilotProvider(AIProvider):
    """GitHub Models API – OpenAI-compatible endpoint authenticated with a GitHub token."""

    def __init__(self, github_oauth=None):
        self._client: Optional[object] = None
        self._model: str = DEFAULT_MODEL
        self._github_oauth = github_oauth  # GitHubOAuth instance (optional)

    @property
    def name(self) -> str:
        return "GitHub Copilot"

    def _resolve_token(self) -> str:
        """Return the best available GitHub token."""
        if self._github_oauth and self._github_oauth.is_configured():
            try:
                return self._github_oauth.get_access_token()
            except Exception:
                pass
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise ProviderError(
                "GitHub token not found – set GITHUB_TOKEN or run 'jsm-triage auth github'"
            )
        return token

    def _build_client(self):
        try:
            from openai import OpenAI

            token = self._resolve_token()
            self._model = os.getenv("GITHUB_MODEL", DEFAULT_MODEL)
            self._client = OpenAI(
                base_url=GITHUB_MODELS_ENDPOINT,
                api_key=token,
            )
        except ImportError as exc:
            raise ProviderError(f"Missing dependency for GitHub Copilot: {exc}") from exc

    def is_available(self) -> bool:
        if self._github_oauth and self._github_oauth.is_configured():
            try:
                self._github_oauth.get_access_token()
                return True
            except Exception:
                pass
        return bool(os.getenv("GITHUB_TOKEN"))

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
            raise ProviderError(f"GitHub Copilot triage failed: {exc}") from exc

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
            raise ProviderError(f"GitHub Copilot chat failed: {exc}") from exc
