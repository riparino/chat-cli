"""GitHub Copilot / GitHub Models provider.

Uses the GitHub Models inference endpoint (OpenAI-API-compatible).
Works with GitHub Copilot Individual, Business, and Enterprise plans.

Auth priority (first match wins):
  1. 3LO OAuth token stored by GitHubOAuth.login()
  2. GITHUB_TOKEN environment variable (PAT or Actions token)

Run 'jsm-triage auth github' for browser-based 3LO login.

Optional env vars:
    GITHUB_MODEL   defaults to gpt-4o  (any model on github.com/marketplace/models)
"""

import os

from .base import OpenAICompatibleProvider, ProviderError

GITHUB_MODELS_ENDPOINT = "https://models.inference.ai.azure.com"
DEFAULT_MODEL = "gpt-4o"


class GitHubCopilotProvider(OpenAICompatibleProvider):
    """GitHub Models API – OpenAI-compatible endpoint authenticated with a GitHub token."""

    def __init__(self, github_oauth=None):
        super().__init__()
        self._github_oauth = github_oauth

    @property
    def name(self) -> str:
        return "GitHub Copilot"

    def _resolve_token(self) -> str:
        if self._github_oauth and self._github_oauth.is_configured():
            token = self._github_oauth.get_valid_token()
            if token:
                return token
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise ProviderError(
                "GitHub token not found – set GITHUB_TOKEN or run 'jsm-triage auth github'"
            )
        return token

    def is_available(self) -> bool:
        if self._github_oauth and self._github_oauth.is_configured():
            if self._github_oauth.get_valid_token():
                return True
        return bool(os.getenv("GITHUB_TOKEN"))

    def _build_client(self) -> None:
        try:
            from openai import OpenAI

            self._model = os.getenv("GITHUB_MODEL", DEFAULT_MODEL)
            self._client = OpenAI(
                base_url=GITHUB_MODELS_ENDPOINT,
                api_key=self._resolve_token(),
            )
        except ImportError as exc:
            raise ProviderError(f"Missing dependency for GitHub Copilot: {exc}") from exc
