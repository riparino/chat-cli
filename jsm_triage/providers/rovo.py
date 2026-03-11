"""Atlassian Rovo AI provider.

Uses the Atlassian Rovo REST API to invoke Rovo agents for ticket analysis.
Rovo is Atlassian's enterprise AI layer built into Jira, Confluence, etc.

Required env vars:
    ATLASSIAN_DOMAIN       your-org.atlassian.net
    ATLASSIAN_EMAIL        user@example.com (service account)
    ATLASSIAN_API_TOKEN    Atlassian API token
Optional:
    ROVO_AGENT_ID          specific Rovo agent ID (uses default if unset)

Note: Rovo API access requires Atlassian Guard / Rovo licence on the site.
      The Rovo Chat API is used here; field extraction falls back to regex parsing
      since Rovo returns natural language rather than structured JSON.
"""

import json
import os
import re
from typing import Optional

import requests

from .base import AIProvider, TriageResult, ProviderError

ROVO_CHAT_API = "https://api.atlassian.com/rovo/v1/chats"


class RovoProvider(AIProvider):
    """Atlassian Rovo AI provider – uses Rovo Chat API."""

    def __init__(self):
        self._session: Optional[requests.Session] = None
        self._domain: Optional[str] = None

    @property
    def name(self) -> str:
        return "Atlassian Rovo"

    def _build_session(self):
        email = os.getenv("ATLASSIAN_EMAIL")
        token = os.getenv("ATLASSIAN_API_TOKEN")
        domain = os.getenv("ATLASSIAN_DOMAIN")

        if not all([email, token, domain]):
            raise ProviderError(
                "Rovo requires ATLASSIAN_DOMAIN, ATLASSIAN_EMAIL, and ATLASSIAN_API_TOKEN"
            )

        self._domain = domain
        self._session = requests.Session()
        self._session.auth = (email, token)
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def is_available(self) -> bool:
        return all([
            os.getenv("ATLASSIAN_DOMAIN"),
            os.getenv("ATLASSIAN_EMAIL"),
            os.getenv("ATLASSIAN_API_TOKEN"),
        ])

    def triage_ticket(self, ticket_data: dict, system_prompt: str, user_prompt: str) -> TriageResult:
        if not self._session:
            self._build_session()

        # Combine system + user prompts – Rovo chat is single-turn
        combined_message = (
            f"{system_prompt}\n\n---\n\n{user_prompt}\n\n"
            "IMPORTANT: Respond ONLY with a valid JSON object – no markdown fences."
        )

        try:
            # Create a new Rovo chat and send the message
            agent_id = os.getenv("ROVO_AGENT_ID")
            payload: dict = {"message": combined_message}
            if agent_id:
                payload["agentId"] = agent_id

            resp = self._session.post(ROVO_CHAT_API, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()

            # Extract the assistant reply from Rovo's response envelope
            raw = self._extract_rovo_reply(data)
            return _parse_rovo_response(raw, self.name)

        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            raise ProviderError(f"Rovo API error {status}: {exc}") from exc
        except Exception as exc:
            raise ProviderError(f"Rovo triage failed: {exc}") from exc

    def chat(self, messages: list[dict], **kwargs) -> str:
        """Send a multi-turn conversation to Rovo (flattens to single message)."""
        if not self._session:
            self._build_session()

        # Flatten history into a single prompt for Rovo's single-turn API
        history_text = "\n\n".join(
            f"[{m['role'].upper()}]: {m['content']}" for m in messages
        )

        try:
            resp = self._session.post(
                ROVO_CHAT_API,
                json={"message": history_text},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return self._extract_rovo_reply(data)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            raise ProviderError(f"Rovo chat error {status}: {exc}") from exc

    @staticmethod
    def _extract_rovo_reply(data: dict) -> str:
        """Pull the assistant text from Rovo API response."""
        # Rovo API envelope varies; try known paths
        for path in [
            ["message", "content"],
            ["response", "message"],
            ["data", "message"],
            ["content"],
            ["message"],
        ]:
            val = data
            try:
                for key in path:
                    val = val[key]
                if isinstance(val, str) and val.strip():
                    return val.strip()
            except (KeyError, TypeError):
                continue

        # Last resort: stringify the whole response
        return json.dumps(data)


def _parse_rovo_response(raw: str, provider_name: str) -> TriageResult:
    """Parse Rovo's reply – tries JSON first, falls back to heuristic extraction."""
    # Strip markdown fences if present
    clean = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()

    try:
        data = json.loads(clean)
        from .azure_openai import _parse_triage_json
        return _parse_triage_json(json.dumps(data), provider_name)
    except (json.JSONDecodeError, ValueError):
        pass

    # Heuristic fallback – extract key fields from free-form text
    priority = _extract_field(raw, r"\bpriority[:\s]+([A-Za-z]+)")
    category = _extract_field(raw, r"\bcategory[:\s]+([^\n,\.]+)")
    summary = _extract_field(raw, r"\bsummary[:\s]+([^\n]+)")

    return TriageResult(
        priority=priority or "Medium",
        category=category or "General",
        subcategory="",
        suggested_team=_extract_field(raw, r"\bteam[:\s]+([^\n,\.]+)"),
        suggested_assignee=None,
        summary=summary or raw[:300],
        suggested_actions=_extract_list(raw),
        escalate="escalat" in raw.lower(),
        confidence=0.4,  # lower confidence for heuristic parse
        provider_used=provider_name,
        raw_response=raw,
    )


def _extract_field(text: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else None


def _extract_list(text: str) -> list[str]:
    """Extract numbered or bulleted list items from free-form text."""
    items = re.findall(r"(?:^\s*[\d\-\*•]+[\.\)]\s*)(.+)", text, re.MULTILINE)
    return [i.strip() for i in items if i.strip()][:8]
