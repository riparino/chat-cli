"""Atlassian Rovo AI provider.

Uses the Atlassian Rovo REST API to invoke Rovo agents for ticket analysis.
Rovo is Atlassian's enterprise AI layer built into Jira, Confluence, etc.

Truly supported:
  - Single-turn triage via Rovo Chat API (POST /rovo/v1/chats)
  - Optional ROVO_AGENT_ID for custom agent routing
  - Retry on transient errors (5xx, 429)
  - JSON parsing with fallback heuristic extraction

Stubs / limitations:
  - The Rovo Chat API does not reliably return structured JSON; heuristic
    fallback parsing is used when the model returns prose.
  - Rovo is single-turn only; conversation history is flattened.
  - Rovo API response envelope varies; multiple extraction paths are tried.
  - Rovo may have lower instruction-following fidelity than OpenAI/Azure.

Required env vars:
    ATLASSIAN_DOMAIN       your-org.atlassian.net
    ATLASSIAN_EMAIL        user@example.com (service account)
    ATLASSIAN_API_TOKEN    Atlassian API token
Optional:
    ROVO_AGENT_ID          specific Rovo agent ID (uses default if unset)

Note: Rovo API access requires Atlassian Guard / Rovo licence on the site.
"""

import json
import logging
import os
import re
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .base import AIProvider, IAMTriageResult, ProviderError, parse_triage_json

logger = logging.getLogger(__name__)

ROVO_CHAT_API = "https://api.atlassian.com/rovo/v1/chats"
REQUEST_TIMEOUT = 60


def _build_retry_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


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
        self._session = _build_retry_session()
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

    def triage_ticket(self, system_prompt: str, user_prompt: str) -> IAMTriageResult:
        if not self._session:
            self._build_session()

        # Combine system + user prompts – Rovo chat is single-turn
        combined_message = (
            f"{system_prompt}\n\n---\n\n{user_prompt}\n\n"
            "CRITICAL: Respond ONLY with a single valid JSON object. "
            "No markdown fences. No text before or after the JSON."
        )

        try:
            agent_id = os.getenv("ROVO_AGENT_ID")
            payload: dict = {"message": combined_message}
            if agent_id:
                payload["agentId"] = agent_id

            resp = self._session.post(ROVO_CHAT_API, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            raw = self._extract_rovo_reply(data)
            result = _parse_rovo_response(raw, self.name)
            logger.debug(
                "Rovo triage: category=%s priority=%s confidence=%.2f",
                result.category,
                result.priority,
                result.confidence,
            )
            return result

        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            raise ProviderError(f"Rovo API error {status}: {exc}") from exc
        except ProviderError:
            raise
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
                timeout=REQUEST_TIMEOUT,
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
        return json.dumps(data)


def _parse_rovo_response(raw: str, provider_name: str) -> IAMTriageResult:
    """Parse Rovo's reply – tries JSON first, falls back to heuristic extraction."""
    # Strip markdown fences if present
    clean = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()

    try:
        return parse_triage_json(clean, provider_name)
    except (ProviderError, ValueError):
        pass

    # Try to extract embedded JSON object
    match = re.search(r"\{[\s\S]+\}", clean)
    if match:
        try:
            return parse_triage_json(match.group(0), provider_name)
        except (ProviderError, ValueError):
            pass

    # Heuristic fallback – extract key fields from free-form text
    # This is a last resort; confidence is set low to signal unreliable extraction
    logger.warning(
        "Rovo returned non-JSON response; falling back to heuristic extraction"
    )

    priority = _extract_field(raw, r"\bpriority[:\s]+([A-Za-z]+)")
    category = _extract_field(raw, r"\bcategory[:\s]+([^\n,\.]+)")
    rationale = _extract_field(raw, r"\b(?:rationale|summary)[:\s]+([^\n]+)")

    # Normalise category
    from .base import VALID_CATEGORIES, VALID_PRIORITIES
    if category and category not in VALID_CATEGORIES:
        category = "Insufficient Information"
    if priority and priority not in VALID_PRIORITIES:
        priority = "Medium"

    return IAMTriageResult(
        category=category or "Insufficient Information",
        subcategory="",
        priority=priority or "Medium",
        urgency="Standard",
        business_impact="Medium",
        rationale=rationale or raw[:300],
        suggested_actions=_extract_list(raw),
        escalation_required="escalat" in raw.lower(),
        confidence=0.3,   # low confidence for heuristic parse
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
