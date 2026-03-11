"""OAuth 2.0 3-legged auth helpers for Atlassian, Azure, and GitHub."""

from .token_store import TokenStore
from .atlassian_oauth import AtlassianOAuth
from .azure_oauth import AzureOAuth
from .github_oauth import GitHubOAuth

# Canonical provider keys used by TokenStore — import from here instead of
# from the individual modules to avoid repeated cross-module imports.
ATLASSIAN_KEY = "atlassian"
AZURE_KEY = "azure"
GITHUB_KEY = "github"

PROVIDER_LABELS: list[tuple[str, str]] = [
    (ATLASSIAN_KEY, "Atlassian"),
    (AZURE_KEY,     "Azure"),
    (GITHUB_KEY,    "GitHub"),
]

__all__ = [
    "TokenStore", "AtlassianOAuth", "AzureOAuth", "GitHubOAuth",
    "ATLASSIAN_KEY", "AZURE_KEY", "GITHUB_KEY", "PROVIDER_LABELS",
]
