"""
Confluence knowledge retriever for grounding triage decisions.

This module provides two retrieval modes:

Mode A – Direct Confluence REST API search (preferred):
  - Uses the Confluence REST API v1 (/wiki/rest/api/search) with CQL queries.
  - Requires only a standard Atlassian API token (same as JSM).
  - Returns page title, excerpt, and URL for citation.
  - Works as long as the service account has Confluence read access.
  - Does NOT require Rovo or Atlassian Guard licensing.

Mode B – Rovo-assisted retrieval (optional, requires Rovo license):
  - Sends a targeted retrieval question to the Rovo chat API.
  - Asks Rovo to find and summarise relevant guidance.
  - Falls back gracefully if Rovo is unavailable.

Configuration:
  The grounding_sources.yaml file defines which Confluence spaces, labels,
  ancestor pages, or CQL queries to search for relevant guidance.

Explicit limitations (do NOT overclaim):
  - This retrieves specific, targeted pages, not all of Confluence.
  - Retrieval is performed at triage time using a query derived from the ticket.
  - The system does not continuously crawl or index Confluence.
  - Search relevance depends on Confluence's CQL matching, not semantic similarity.
  - Rovo retrieval is single-turn and prompt-based, not a vector search.
"""

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..prompts.builder import KnowledgeSnippet

logger = logging.getLogger(__name__)

# Confluence REST API endpoints
CONFLUENCE_SEARCH_API = "/wiki/rest/api/search"
CONFLUENCE_CONTENT_API = "/wiki/rest/api/content"

# Request limits
DEFAULT_RESULT_LIMIT = 5
MAX_EXCERPT_CHARS = 800
REQUEST_TIMEOUT = 15


@dataclass
class GroundingSourceConfig:
    """Configuration for a set of Confluence sources to search."""
    # CQL queries to run (most flexible)
    cql_queries: list[str] = field(default_factory=list)
    # Specific page IDs to always include
    page_ids: list[str] = field(default_factory=list)
    # Space keys to restrict search to (used with ticket-derived query)
    spaces: list[str] = field(default_factory=list)
    # Confluence labels that tag policy/guidance pages
    labels: list[str] = field(default_factory=list)
    # Maximum results per query
    result_limit: int = DEFAULT_RESULT_LIMIT


def _build_retry_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    """Create a requests.Session with automatic retries on transient errors."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class ConfluenceRetriever:
    """
    Retrieves relevant Confluence pages for grounding triage decisions.

    Authentication uses the same Atlassian API token as the JSM client.
    No additional licensing (beyond Confluence read access) is required.

    Truly supported:
      - CQL-based search via Confluence REST API v1
      - Direct page retrieval by page ID
      - Space-scoped search with ticket-derived query
      - Label-based policy page discovery

    Stubs / limitations:
      - No semantic/vector search (uses Confluence CQL relevance ranking only)
      - No continuous indexing – retrieval is on-demand per triage request
      - Page content is the full-text excerpt from Confluence search API (may be truncated)
      - ADF body content requires separate page fetch (done only for pinned pages)
    """

    def __init__(
        self,
        domain: Optional[str] = None,
        email: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        self._domain = domain or os.getenv("ATLASSIAN_DOMAIN", "")
        self._email = email or os.getenv("ATLASSIAN_EMAIL", "")
        self._api_token = api_token or os.getenv("ATLASSIAN_API_TOKEN", "")
        self._session: Optional[requests.Session] = None
        self._base_url = f"https://{self._domain}" if self._domain else ""

    def is_available(self) -> bool:
        """Return True if Confluence credentials are configured."""
        return bool(self._domain and self._email and self._api_token)

    def _get_session(self) -> requests.Session:
        if self._session is None:
            if not self.is_available():
                raise RuntimeError(
                    "Confluence retriever requires ATLASSIAN_DOMAIN, "
                    "ATLASSIAN_EMAIL, and ATLASSIAN_API_TOKEN"
                )
            self._session = _build_retry_session()
            self._session.auth = (self._email, self._api_token)
            self._session.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
        return self._session

    def retrieve_for_query(
        self,
        query: str,
        config: Optional[GroundingSourceConfig] = None,
        pinned_page_ids: Optional[list[str]] = None,
    ) -> list[KnowledgeSnippet]:
        """
        Retrieve relevant Confluence snippets for the given query.

        Combines:
          1. Pinned page IDs (always fetched when configured)
          2. CQL queries from config (admin-defined policy pages)
          3. Full-text search across configured spaces with ticket query

        Args:
            query:           Ticket-derived search query string.
            config:          Grounding source configuration.
            pinned_page_ids: Page IDs to always include.

        Returns:
            List of KnowledgeSnippet objects (may be empty on failure).
        """
        if not self.is_available():
            logger.debug("Confluence retriever not available (credentials missing)")
            return []

        snippets: list[KnowledgeSnippet] = []
        seen_ids: set[str] = set()

        # 1. Fetch pinned pages (always include these)
        all_pinned = list(pinned_page_ids or [])
        if config and config.page_ids:
            all_pinned.extend(config.page_ids)

        for page_id in all_pinned:
            if page_id in seen_ids:
                continue
            snippet = self._fetch_page_by_id(page_id)
            if snippet:
                snippets.append(snippet)
                seen_ids.add(page_id)

        # 2. Run admin-configured CQL queries
        if config and config.cql_queries:
            for cql in config.cql_queries:
                results = self._run_cql_search(
                    cql, limit=config.result_limit
                )
                for s in results:
                    page_id = s.source_url or s.title
                    if page_id not in seen_ids:
                        snippets.append(s)
                        seen_ids.add(page_id)

        # 3. Full-text search scoped to configured spaces + labels
        if config and (config.spaces or config.labels):
            cql_parts = [f'text ~ "{_escape_cql(query)}"', 'type = "page"']
            if config.spaces:
                space_list = ",".join(f'"{s}"' for s in config.spaces)
                cql_parts.append(f"space.key in ({space_list})")
            if config.labels:
                label_list = ",".join(f'"{lb}"' for lb in config.labels)
                cql_parts.append(f"label in ({label_list})")
            full_text_cql = " AND ".join(cql_parts)
            results = self._run_cql_search(full_text_cql, limit=config.result_limit)
            for s in results:
                page_id = s.source_url or s.title
                if page_id not in seen_ids:
                    snippets.append(s)
                    seen_ids.add(page_id)

        elif query and not (config and config.cql_queries):
            # Fallback: general text search with no space restriction
            cql = f'text ~ "{_escape_cql(query)}" AND type = "page"'
            results = self._run_cql_search(cql, limit=3)
            for s in results:
                page_id = s.source_url or s.title
                if page_id not in seen_ids:
                    snippets.append(s)
                    seen_ids.add(page_id)

        logger.info(
            "Confluence retrieval: query=%r, snippets_found=%d",
            query[:60],
            len(snippets),
        )
        return snippets

    def _run_cql_search(self, cql: str, limit: int = 5) -> list[KnowledgeSnippet]:
        """Run a CQL search and return knowledge snippets from results."""
        session = self._get_session()
        url = self._base_url + CONFLUENCE_SEARCH_API

        params = {
            "cql": cql,
            "limit": limit,
            "expand": "content.excerpt,content.space,content._links",
        }

        try:
            resp = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response else "?"
            logger.warning("Confluence search HTTP %s for CQL %r: %s", status, cql[:80], exc)
            return []
        except Exception as exc:
            logger.warning("Confluence search failed for CQL %r: %s", cql[:80], exc)
            return []

        snippets = []
        for result in data.get("results", []):
            content = result.get("content", {})
            title = content.get("title", result.get("title", "Untitled"))
            excerpt = result.get("excerpt", "") or ""
            excerpt = _clean_html(excerpt)[:MAX_EXCERPT_CHARS]

            # Build page URL
            links = content.get("_links", {})
            page_path = links.get("webui", "")
            page_url = f"https://{self._domain}/wiki{page_path}" if page_path else None

            if title and excerpt:
                snippets.append(KnowledgeSnippet(
                    title=title,
                    content=excerpt,
                    source_url=page_url,
                    source_type="confluence",
                ))

        return snippets

    def _fetch_page_by_id(self, page_id: str) -> Optional[KnowledgeSnippet]:
        """Fetch a specific Confluence page by ID and return as a knowledge snippet."""
        session = self._get_session()
        url = self._base_url + CONFLUENCE_CONTENT_API + f"/{page_id}"

        try:
            resp = session.get(
                url,
                params={"expand": "body.storage,space,_links"},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning("Could not fetch Confluence page %s: %s", page_id, exc)
            return None

        title = data.get("title", f"Page {page_id}")
        body = data.get("body", {}).get("storage", {}).get("value", "")
        content = _clean_html(body)[:MAX_EXCERPT_CHARS]

        links = data.get("_links", {})
        page_path = links.get("webui", "")
        page_url = f"https://{self._domain}/wiki{page_path}" if page_path else None

        return KnowledgeSnippet(
            title=title,
            content=content,
            source_url=page_url,
            source_type="confluence",
        )


class RovoKnowledgeRetriever:
    """
    Rovo-based knowledge retrieval.

    Uses the Rovo Chat API to ask a targeted retrieval question and extract
    relevant guidance. This requires an Atlassian Rovo/Guard licence.

    Truly supported:
      - Sending a targeted retrieval query to Rovo Chat API
      - Extracting text response as a knowledge snippet

    Limitations:
      - Rovo responds with generated text, not structured page references
      - No guaranteed citation of specific Confluence page URLs
      - Single-turn only (Rovo Chat API)
      - Rovo may hallucinate or produce stale guidance
      - Requires ATLASSIAN_DOMAIN, ATLASSIAN_EMAIL, ATLASSIAN_API_TOKEN + Rovo licence

    When to use:
      - Use as a secondary retrieval source after ConfluenceRetriever
      - Or as the primary retrieval source when direct Confluence access is restricted
    """

    ROVO_CHAT_API = "https://api.atlassian.com/rovo/v1/chats"

    def __init__(
        self,
        domain: Optional[str] = None,
        email: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        self._domain = domain or os.getenv("ATLASSIAN_DOMAIN", "")
        self._email = email or os.getenv("ATLASSIAN_EMAIL", "")
        self._api_token = api_token or os.getenv("ATLASSIAN_API_TOKEN", "")
        self._agent_id = os.getenv("ROVO_AGENT_ID")
        self._session: Optional[requests.Session] = None

    def is_available(self) -> bool:
        return bool(self._domain and self._email and self._api_token)

    def _get_session(self) -> requests.Session:
        if self._session is None:
            self._session = _build_retry_session()
            self._session.auth = (self._email, self._api_token)
            self._session.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
        return self._session

    def retrieve_for_query(self, query: str) -> list[KnowledgeSnippet]:
        """
        Ask Rovo to find relevant guidance for the given query.

        Constructs a retrieval-focused prompt instructing Rovo to return
        policy guidance found in Confluence, then extracts the response
        as a knowledge snippet.

        Returns an empty list on failure (never raises).
        """
        if not self.is_available():
            return []

        retrieval_prompt = (
            f"Search Confluence for policies, procedures, or guidance relevant to: "
            f'"{query}"\n\n'
            "Return a concise summary of any relevant policy or procedure you find. "
            "Include the page title and space if available. "
            "If you cannot find relevant guidance, say 'No relevant guidance found'."
        )

        try:
            session = self._get_session()
            payload: dict = {"message": retrieval_prompt}
            if self._agent_id:
                payload["agentId"] = self._agent_id

            resp = session.post(
                self.ROVO_CHAT_API,
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            # Extract reply from Rovo's response envelope
            reply = self._extract_reply(data)
            if not reply or "no relevant guidance" in reply.lower():
                logger.debug("Rovo found no relevant guidance for: %s", query[:60])
                return []

            return [KnowledgeSnippet(
                title=f"Rovo: guidance for '{query[:50]}'",
                content=reply[:MAX_EXCERPT_CHARS],
                source_url=None,
                source_type="rovo",
            )]

        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response else "?"
            logger.warning("Rovo retrieval HTTP %s for query %r: %s", status, query[:60], exc)
            return []
        except Exception as exc:
            logger.warning("Rovo retrieval failed for query %r: %s", query[:60], exc)
            return []

    @staticmethod
    def _extract_reply(data: dict) -> str:
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
        import json as _json
        return _json.dumps(data)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape_cql(text: str) -> str:
    """Escape a string for safe use in a CQL text search query."""
    # Escape double quotes and backslashes
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _clean_html(html: str) -> str:
    """Strip HTML tags and normalise whitespace from Confluence content."""
    import re
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", html)
    # Decode common HTML entities
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace(
        "&gt;", ">").replace("&quot;", '"').replace("&#39;", "'").replace(
        "&nbsp;", " ")
    # Normalise whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text
