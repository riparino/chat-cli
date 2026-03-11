"""Atlassian OAuth 2.0 – Authorization Code with PKCE (3LO).

Flow:
  1. generate_auth_url()  →  user opens URL in browser
  2. exchange_code()      ←  Atlassian redirects to localhost callback with ?code=…
  3. Access + refresh tokens stored in TokenStore.
  4. get_access_token()   →  returns valid token (auto-refreshes if needed)

Required env vars:
    ATLASSIAN_CLIENT_ID      from developer.atlassian.com → OAuth 2.0 App
    ATLASSIAN_CLIENT_SECRET  from developer.atlassian.com → OAuth 2.0 App
Optional:
    ATLASSIAN_REDIRECT_URI   defaults to http://localhost:8765/callback
    ATLASSIAN_SCOPES         space-separated, defaults to standard JSM scopes

Setting up the Atlassian OAuth App:
  1. Go to https://developer.atlassian.com/console/myapps/
  2. Create a new app → OAuth 2.0 (3LO)
  3. Add callback URL: http://localhost:8765/callback
  4. Add scopes (see DEFAULT_SCOPES below)
  5. Copy Client ID and Secret into .env
"""

import base64
import hashlib
import http.server
import json
import os
import secrets
import threading
import time
import urllib.parse
import webbrowser
from typing import Optional

import requests

from .token_store import TokenStore

PROVIDER_KEY = "atlassian"

AUTH_URL     = "https://auth.atlassian.com/authorize"
TOKEN_URL    = "https://auth.atlassian.com/oauth/token"
RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

DEFAULT_SCOPES = (
    "read:jira-work "
    "write:jira-work "
    "read:jira-user "
    "manage:jira-project "
    "read:servicedesk-request "
    "write:servicedesk-request "
    "manage:servicedesk-customer "
    "offline_access"          # enables refresh tokens
)


class AtlassianOAuth:
    """Manages the Atlassian 3LO OAuth 2.0 flow for CLI tools."""

    def __init__(self, store: Optional[TokenStore] = None):
        self._store = store or TokenStore()
        self._client_id = os.getenv("ATLASSIAN_CLIENT_ID", "")
        self._client_secret = os.getenv("ATLASSIAN_CLIENT_SECRET", "")
        self._redirect_uri = os.getenv("ATLASSIAN_REDIRECT_URI", "http://localhost:8765/callback")
        self._scopes = os.getenv("ATLASSIAN_SCOPES", DEFAULT_SCOPES)
        self._cloud_id: Optional[str] = None

    def is_configured(self) -> bool:
        return bool(self._client_id and self._client_secret)

    # ------------------------------------------------------------------
    # PKCE helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pkce_pair() -> tuple[str, str]:
        """Return (code_verifier, code_challenge) for PKCE."""
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return verifier, challenge

    # ------------------------------------------------------------------
    # Authorization URL
    # ------------------------------------------------------------------

    def generate_auth_url(self, state: str, code_challenge: str) -> str:
        params = {
            "audience": "api.atlassian.com",
            "client_id": self._client_id,
            "scope": self._scopes,
            "redirect_uri": self._redirect_uri,
            "state": state,
            "response_type": "code",
            "prompt": "consent",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"

    # ------------------------------------------------------------------
    # Token exchange
    # ------------------------------------------------------------------

    def exchange_code(self, code: str, code_verifier: str) -> dict:
        resp = requests.post(
            TOKEN_URL,
            json={
                "grant_type": "authorization_code",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "code": code,
                "redirect_uri": self._redirect_uri,
                "code_verifier": code_verifier,
            },
            timeout=30,
        )
        resp.raise_for_status()
        token_data = resp.json()
        self._store.store_token_response(PROVIDER_KEY, token_data)
        return token_data

    def refresh(self) -> dict:
        refresh_token = self._store.refresh_token(PROVIDER_KEY)
        if not refresh_token:
            raise RuntimeError("No refresh token – please run 'jsm-triage auth atlassian' to login")

        resp = requests.post(
            TOKEN_URL,
            json={
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": refresh_token,
            },
            timeout=30,
        )
        resp.raise_for_status()
        token_data = resp.json()
        self._store.store_token_response(PROVIDER_KEY, token_data)
        return token_data

    # ------------------------------------------------------------------
    # Token access (auto-refresh)
    # ------------------------------------------------------------------

    def get_access_token(self) -> str:
        if self._store.is_expired(PROVIDER_KEY):
            self.refresh()
        token = self._store.access_token(PROVIDER_KEY)
        if not token:
            raise RuntimeError("Not authenticated – run 'jsm-triage auth atlassian'")
        return token

    # ------------------------------------------------------------------
    # Cloud ID (required for REST API base URL)
    # ------------------------------------------------------------------

    def get_cloud_id(self) -> str:
        if self._cloud_id:
            return self._cloud_id

        cached = self._store.get(PROVIDER_KEY) or {}
        if "cloud_id" in cached:
            self._cloud_id = cached["cloud_id"]
            return self._cloud_id

        token = self.get_access_token()
        resp = requests.get(
            RESOURCES_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        resources = resp.json()
        if not resources:
            raise RuntimeError("No Atlassian Cloud resources accessible with these credentials")

        # Prefer the site matching ATLASSIAN_DOMAIN if set
        domain = os.getenv("ATLASSIAN_DOMAIN", "").lower()
        chosen = resources[0]
        if domain:
            for r in resources:
                if domain in r.get("url", "").lower():
                    chosen = r
                    break

        self._cloud_id = chosen["id"]
        existing = self._store.get(PROVIDER_KEY) or {}
        existing["cloud_id"] = self._cloud_id
        existing["cloud_url"] = chosen.get("url", "")
        self._store.save(PROVIDER_KEY, existing)
        return self._cloud_id

    def get_api_base(self) -> str:
        """Return the per-cloud REST API base URL."""
        cloud_id = self.get_cloud_id()
        return f"https://api.atlassian.com/ex/jira/{cloud_id}"

    # ------------------------------------------------------------------
    # Interactive login (opens browser + local callback server)
    # ------------------------------------------------------------------

    def login(self) -> None:
        """Run the full browser-based OAuth 3LO login flow."""
        verifier, challenge = self._pkce_pair()
        state = secrets.token_urlsafe(16)
        auth_url = self.generate_auth_url(state, challenge)

        result: dict = {}
        server_error: list[str] = []
        redirect_port = int(urllib.parse.urlparse(self._redirect_uri).port or 8765)

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # suppress server logs
                pass

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)

                if "error" in params:
                    server_error.append(params["error"][0])
                elif "code" in params:
                    result["code"] = params["code"][0]
                    result["state"] = params.get("state", [""])[0]

                body = b"<html><body><h2>Authentication complete – you may close this tab.</h2></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = http.server.HTTPServer(("localhost", redirect_port), _Handler)
        server.timeout = 120  # wait up to 2 minutes

        print(f"\n  Opening browser for Atlassian authentication…")
        print(f"  If the browser does not open, visit:\n  {auth_url}\n")
        webbrowser.open(auth_url)

        # Handle one request (the callback)
        server.handle_request()
        server.server_close()

        if server_error:
            raise RuntimeError(f"OAuth error: {server_error[0]}")
        if not result.get("code"):
            raise RuntimeError("No authorization code received – did you cancel?")
        if result.get("state") != state:
            raise RuntimeError("OAuth state mismatch – possible CSRF attack")

        print("  Exchanging authorization code for tokens…")
        self.exchange_code(result["code"], verifier)
        cloud_id = self.get_cloud_id()
        print(f"  ✅ Authenticated!  Cloud ID: {cloud_id}")
