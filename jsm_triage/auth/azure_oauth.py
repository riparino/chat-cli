"""Azure OAuth 2.0 – Device Authorization Grant via MSAL.

This covers interactive login for Azure OpenAI and Microsoft Copilot when
DefaultAzureCredential is not available (e.g. no az CLI, no Managed Identity).

Required env vars:
    AZURE_CLIENT_ID          App registration client ID
    AZURE_TENANT_ID          Tenant ID (or 'common' for multi-tenant)
Optional:
    AZURE_CLIENT_SECRET      For confidential client flows
    AZURE_SCOPES             Space-separated; defaults to OpenAI cognitive scope

The device flow is preferred for CLI tools:
  1. MSAL prints a URL + user code
  2. User opens URL in any browser and enters the code
  3. CLI polls until user completes authentication
  4. Tokens cached in MSAL's default token cache (~/.msal_token_cache.bin)
     and mirrored into our TokenStore for easy access.
"""

import os
import time
from pathlib import Path
from typing import Optional

from .token_store import TokenStore

PROVIDER_KEY = "azure"
DEFAULT_SCOPES = ["https://cognitiveservices.azure.com/.default"]


class AzureOAuth:
    """Azure OAuth 2.0 via MSAL device code flow."""

    def __init__(self, store: Optional[TokenStore] = None):
        self._store = store or TokenStore()
        self._client_id = os.getenv("AZURE_CLIENT_ID", "")
        self._tenant_id = os.getenv("AZURE_TENANT_ID", "common")
        self._client_secret = os.getenv("AZURE_CLIENT_SECRET")
        raw_scopes = os.getenv("AZURE_SCOPES", "")
        self._scopes = raw_scopes.split() if raw_scopes else DEFAULT_SCOPES
        self._msal_app = None

    def is_configured(self) -> bool:
        return bool(self._client_id and self._tenant_id)

    def _build_app(self):
        try:
            import msal
        except ImportError as exc:
            raise RuntimeError(
                "Install msal for Azure OAuth: pip install msal"
            ) from exc

        authority = f"https://login.microsoftonline.com/{self._tenant_id}"
        cache_path = Path.home() / ".jsm_triage" / "msal_cache.bin"
        cache = msal.SerializableTokenCache()
        if cache_path.exists():
            cache.deserialize(cache_path.read_text())

        if self._client_secret:
            self._msal_app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=authority,
                client_credential=self._client_secret,
                token_cache=cache,
            )
        else:
            self._msal_app = msal.PublicClientApplication(
                self._client_id,
                authority=authority,
                token_cache=cache,
            )

        self._cache = cache
        self._cache_path = cache_path

    def _persist_cache(self):
        if self._msal_app and self._cache and self._cache.has_state_changed:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(self._cache.serialize())

    def get_access_token(self) -> str:
        """Return a valid access token, refreshing silently if possible."""
        if not self._msal_app:
            self._build_app()

        # Try silent acquisition first
        accounts = self._msal_app.get_accounts()
        if accounts:
            result = self._msal_app.acquire_token_silent(self._scopes, account=accounts[0])
            if result and "access_token" in result:
                self._persist_cache()
                return result["access_token"]

        # Try stored refresh token
        if not self._store.is_expired(PROVIDER_KEY, buffer_seconds=120):
            token = self._store.access_token(PROVIDER_KEY)
            if token:
                return token

        raise RuntimeError(
            "Azure token expired or unavailable – run 'jsm-triage auth azure' to login"
        )

    def login(self) -> None:
        """Run interactive device code flow login."""
        if not self._msal_app:
            self._build_app()

        flow = self._msal_app.initiate_device_flow(scopes=self._scopes)
        if "user_code" not in flow:
            raise RuntimeError(f"Failed to start device flow: {flow.get('error_description', flow)}")

        print(f"\n  Azure authentication required.")
        print(f"  Visit: {flow['verification_uri']}")
        print(f"  Enter code: {flow['user_code']}")
        print(f"  Waiting for authentication (expires in {flow.get('expires_in', 900)}s)…\n")

        result = self._msal_app.acquire_token_by_device_flow(flow)

        if "access_token" not in result:
            raise RuntimeError(
                f"Azure authentication failed: {result.get('error_description', result)}"
            )

        self._persist_cache()

        # Mirror into TokenStore
        self._store.store_token_response(PROVIDER_KEY, {
            "access_token": result["access_token"],
            "refresh_token": result.get("refresh_token", ""),
            "expires_in": result.get("expires_in", 3600),
            "token_type": result.get("token_type", "Bearer"),
        })

        account = self._msal_app.get_accounts()[0] if self._msal_app.get_accounts() else {}
        username = account.get("username", "unknown")
        print(f"  ✅ Authenticated as {username}")
