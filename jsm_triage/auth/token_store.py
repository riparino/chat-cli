"""Secure local token storage (~/.jsm_triage/tokens.json).

Tokens are stored with 0600 permissions so only the current user can read them.
On platforms with a system keyring (macOS Keychain, GNOME Keyring, Windows Credential
Manager) the file is further protected by the OS login.
"""

import json
import os
import stat
import time
from pathlib import Path
from typing import Optional


class TokenStore:
    """Persist and retrieve OAuth tokens keyed by provider name."""

    def __init__(self, path: Optional[Path] = None):
        self._path = path or Path.home() / ".jsm_triage" / "tokens.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Restrict directory permissions
        try:
            os.chmod(self._path.parent, stat.S_IRWXU)
        except OSError:
            pass
        self._data: dict = self._load()

    # ------------------------------------------------------------------

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self) -> None:
        self._path.write_text(json.dumps(self._data, indent=2))
        try:
            os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    # ------------------------------------------------------------------

    def get(self, provider: str) -> Optional[dict]:
        """Return stored token data for *provider*, or None."""
        return self._data.get(provider)

    def save(self, provider: str, token_data: dict) -> None:
        """Store *token_data* for *provider*."""
        self._data[provider] = token_data
        self._save()

    def clear(self, provider: str) -> None:
        self._data.pop(provider, None)
        self._save()

    def clear_all(self) -> None:
        self._data = {}
        self._save()

    # ------------------------------------------------------------------
    # Convenience helpers

    def is_expired(self, provider: str, buffer_seconds: int = 60) -> bool:
        """Return True if the stored access token is expired (or missing)."""
        entry = self.get(provider)
        if not entry:
            return True
        expires_at = entry.get("expires_at", 0)
        return time.time() >= (expires_at - buffer_seconds)

    def access_token(self, provider: str) -> Optional[str]:
        entry = self.get(provider)
        return entry.get("access_token") if entry else None

    def refresh_token(self, provider: str) -> Optional[str]:
        entry = self.get(provider)
        return entry.get("refresh_token") if entry else None

    def store_token_response(self, provider: str, resp: dict) -> None:
        """
        Store a token response dict (as returned by OAuth token endpoints).
        Computes and stores expires_at from expires_in.
        """
        expires_in = int(resp.get("expires_in", 3600))
        resp["expires_at"] = time.time() + expires_in
        self.save(provider, resp)
