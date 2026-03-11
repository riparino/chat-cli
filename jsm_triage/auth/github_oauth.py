"""GitHub OAuth – Device Authorization Grant (3LO for CLI/desktop apps).

This authenticates to GitHub and obtains a token that can be used with the
GitHub Models API (and GitHub Copilot where available).

Required env vars:
    GITHUB_CLIENT_ID     GitHub OAuth App or GitHub App client ID

Optional:
    GITHUB_SCOPES        comma-separated; defaults to read:user (minimal)
                         GitHub Models only needs a valid GitHub token –
                         no special Copilot scopes required.

Setting up:
  1. Go to https://github.com/settings/developers → OAuth Apps → New
  2. Set "Application name", "Homepage URL" (any), leave callback blank
  3. Enable "Device flow" checkbox
  4. Copy Client ID → GITHUB_CLIENT_ID in .env
  5. Run 'jsm-triage auth github'

Note: GitHub Copilot access via GitHub Models is scoped to the account's
      Copilot subscription – no additional OAuth scopes needed beyond a
      valid GitHub token.
"""

import json
import os
import time
import webbrowser
from typing import Optional

import requests

from .token_store import TokenStore

PROVIDER_KEY = "github"
DEVICE_CODE_URL = "https://github.com/login/device/code"
TOKEN_URL       = "https://github.com/login/oauth/access_token"

DEFAULT_SCOPES = "read:user"


class GitHubOAuth:
    """GitHub device authorization grant (3LO for CLI tools)."""

    def __init__(self, store: Optional[TokenStore] = None):
        self._store = store or TokenStore()
        self._client_id = os.getenv("GITHUB_CLIENT_ID", "")
        self._scopes = os.getenv("GITHUB_SCOPES", DEFAULT_SCOPES)

    def is_configured(self) -> bool:
        return bool(self._client_id)

    def get_access_token(self) -> str:
        """Return stored GitHub access token (GitHub tokens don't expire by default)."""
        token = self._store.access_token(PROVIDER_KEY)
        if token:
            return token
        # Fall back to GITHUB_TOKEN env var (set in CI / Actions automatically)
        env_token = os.getenv("GITHUB_TOKEN")
        if env_token:
            return env_token
        raise RuntimeError(
            "No GitHub token – run 'jsm-triage auth github' or set GITHUB_TOKEN"
        )

    def login(self) -> None:
        """Run the GitHub device flow login."""
        if not self._client_id:
            raise RuntimeError("GITHUB_CLIENT_ID is required for GitHub OAuth login")

        # Step 1: request device + user code
        resp = requests.post(
            DEVICE_CODE_URL,
            data={"client_id": self._client_id, "scope": self._scopes},
            headers={"Accept": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        device_code = data["device_code"]
        user_code   = data["user_code"]
        verify_url  = data["verification_uri"]
        expires_in  = int(data.get("expires_in", 900))
        interval    = int(data.get("interval", 5))

        print(f"\n  GitHub authentication:")
        print(f"  Visit: {verify_url}")
        print(f"  Enter code: {user_code}")
        print(f"  Waiting… (expires in {expires_in}s)\n")

        try:
            webbrowser.open(verify_url)
        except Exception:
            print(f"  (Could not open browser automatically – please visit the URL above)")

        # Step 2: poll for token
        deadline = time.time() + expires_in
        while time.time() < deadline:
            time.sleep(interval)
            poll = requests.post(
                TOKEN_URL,
                data={
                    "client_id": self._client_id,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
                headers={"Accept": "application/json"},
                timeout=15,
            )
            poll.raise_for_status()
            result = poll.json()

            error = result.get("error")
            if error == "authorization_pending":
                continue
            elif error == "slow_down":
                interval += 5
                continue
            elif error == "expired_token":
                raise RuntimeError("Device code expired – please try again")
            elif error == "access_denied":
                raise RuntimeError("GitHub authentication was denied by the user")
            elif error:
                raise RuntimeError(f"GitHub OAuth error: {error}")

            access_token = result.get("access_token")
            if access_token:
                # GitHub access tokens don't expire (unless fine-grained PAT)
                self._store.save(PROVIDER_KEY, {
                    "access_token": access_token,
                    "token_type": result.get("token_type", "bearer"),
                    "scope": result.get("scope", self._scopes),
                    "expires_at": time.time() + (365 * 24 * 3600),  # 1 year sentinel
                })
                print(f"  ✅ GitHub authentication successful")
                return

        raise RuntimeError("Timed out waiting for GitHub authentication")
