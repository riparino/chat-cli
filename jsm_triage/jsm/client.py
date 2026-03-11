"""Atlassian JSM REST API client.

Auth priority (first match wins):
  1. OAuth 2.0 3LO  – tokens stored by AtlassianOAuth.login()
  2. ATLASSIAN_OAUTH_TOKEN env var  – a raw Bearer token you supply
  3. Basic auth  – ATLASSIAN_EMAIL + ATLASSIAN_API_TOKEN (API key)

For OAuth 2.0 3LO (recommended for enterprise):
    ATLASSIAN_CLIENT_ID
    ATLASSIAN_CLIENT_SECRET
    (run 'jsm-triage auth atlassian' to complete browser login)

For Basic auth (simpler, still widely used):
    ATLASSIAN_DOMAIN       your-org.atlassian.net
    ATLASSIAN_EMAIL        service-account@example.com
    ATLASSIAN_API_TOKEN    from id.atlassian.com → Security → API tokens
"""

import os
from typing import Optional

import requests

from .models import Ticket, ServiceDesk, Queue


class JSMClient:
    """Thin wrapper around the Atlassian REST APIs needed for ticket triage."""

    def __init__(self, oauth=None):
        """
        Args:
            oauth: An AtlassianOAuth instance.  When provided and authenticated,
                   OAuth 2.0 Bearer tokens are used and the per-cloud API base is
                   resolved automatically.  Pass None to fall back to env-var auth.
        """
        self._oauth = oauth
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self._base_url: Optional[str] = None
        self._init_auth()

    # ------------------------------------------------------------------
    # Auth initialisation
    # ------------------------------------------------------------------

    def _init_auth(self) -> None:
        """Configure the session with the best available auth method."""

        # 1. OAuth 2.0 3LO (preferred)
        if self._oauth and self._oauth.is_configured():
            try:
                token = self._oauth.get_access_token()
                self._session.headers["Authorization"] = f"Bearer {token}"
                self._base_url = self._oauth.get_api_base()
                return
            except Exception as exc:
                print(f"  Warning: OAuth 2.0 login failed ({exc}); falling back to API token auth")

        # 2. Raw bearer token env var
        raw_bearer = os.getenv("ATLASSIAN_OAUTH_TOKEN")
        if raw_bearer:
            self._session.headers["Authorization"] = f"Bearer {raw_bearer}"
            domain = os.getenv("ATLASSIAN_DOMAIN", "").strip().rstrip("/")
            if domain:
                self._base_url = f"https://{domain}"
                return
            raise RuntimeError("ATLASSIAN_DOMAIN required when using ATLASSIAN_OAUTH_TOKEN")

        # 3. Basic auth (API token)
        email = os.getenv("ATLASSIAN_EMAIL")
        api_token = os.getenv("ATLASSIAN_API_TOKEN")
        domain = os.getenv("ATLASSIAN_DOMAIN", "").strip().rstrip("/")

        if not domain:
            raise RuntimeError(
                "ATLASSIAN_DOMAIN is required.  "
                "Set it in .env or run 'jsm-triage auth atlassian' for OAuth login."
            )
        if not email or not api_token:
            raise RuntimeError(
                "Provide ATLASSIAN_EMAIL + ATLASSIAN_API_TOKEN for basic auth, "
                "or run 'jsm-triage auth atlassian' for OAuth 2.0 login."
            )

        self._session.auth = (email, api_token)
        self._base_url = f"https://{domain}"

    def _refresh_oauth_header(self) -> None:
        """Re-fetch an OAuth token if it has expired (called before each request)."""
        if self._oauth and self._oauth.is_configured():
            try:
                token = self._oauth.get_access_token()
                self._session.headers["Authorization"] = f"Bearer {token}"
            except Exception:
                pass

    def _base(self) -> str:
        self._refresh_oauth_header()
        return self._base_url or ""

    def _get(self, path: str, **params) -> dict:
        url = f"{self._base()}{path}"
        resp = self._session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self._base()}{path}"
        resp = self._session.post(url, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _put(self, path: str, body: dict) -> None:
        url = f"{self._base()}{path}"
        resp = self._session.put(url, json=body, timeout=30)
        resp.raise_for_status()

    # ------------------------------------------------------------------
    # Service desk discovery
    # ------------------------------------------------------------------

    def list_service_desks(self) -> list[ServiceDesk]:
        data = self._get("/rest/servicedeskapi/servicedesk")
        desks = []
        for item in data.get("values", []):
            desks.append(ServiceDesk(
                id=str(item["id"]),
                project_key=item.get("projectKey", ""),
                name=item.get("projectName", ""),
            ))
        return desks

    def list_queues(self, service_desk_id: str) -> list[Queue]:
        data = self._get(f"/rest/servicedeskapi/servicedesk/{service_desk_id}/queue")
        queues = []
        for item in data.get("values", []):
            queues.append(Queue(
                id=str(item["id"]),
                name=item.get("name", ""),
                issue_count=item.get("issueCount", 0),
            ))
        return queues

    # ------------------------------------------------------------------
    # Ticket retrieval
    # ------------------------------------------------------------------

    def get_ticket(self, issue_key: str) -> Ticket:
        """Fetch a single ticket with comments."""
        data = self._get(
            f"/rest/api/3/issue/{issue_key}",
            fields="summary,description,status,priority,issuetype,reporter,assignee,"
                   "labels,components,comment,customfield_10010,created,updated",
            expand="renderedFields",
        )
        return Ticket.from_jira_api(data)

    def get_queue_tickets(
        self,
        service_desk_id: str,
        queue_id: str,
        limit: int = 50,
        start: int = 0,
    ) -> list[Ticket]:
        """Retrieve tickets from a JSM queue.

        The queue endpoint already returns full issue fields, so we parse them
        directly instead of issuing a separate GET per ticket (avoids N+1).
        """
        data = self._get(
            f"/rest/servicedeskapi/servicedesk/{service_desk_id}/queue/{queue_id}/issue",
            start=start,
            limit=limit,
        )
        tickets = []
        for issue in data.get("values", []):
            try:
                tickets.append(Ticket.from_jira_api(issue))
            except Exception as exc:
                print(f"  Warning: could not parse {issue.get('key', '?')}: {exc}")
        return tickets

    def search_tickets(self, jql: str, limit: int = 50, start: int = 0) -> list[Ticket]:
        """Run a JQL query and return matching tickets."""
        data = self._post(
            "/rest/api/3/search",
            body={
                "jql": jql,
                "startAt": start,
                "maxResults": limit,
                "fields": [
                    "summary", "description", "status", "priority",
                    "issuetype", "reporter", "assignee",
                    "labels", "components", "comment", "customfield_10010",
                ],
            },
        )
        tickets = []
        for issue in data.get("issues", []):
            try:
                tickets.append(Ticket.from_jira_api(issue))
            except Exception as exc:
                print(f"  Warning: could not parse {issue.get('key', '?')}: {exc}")
        return tickets

    # ------------------------------------------------------------------
    # Ticket updates
    # ------------------------------------------------------------------

    def add_comment(self, issue_key: str, body: str) -> dict:
        """Add a plain-text comment to a ticket."""
        return self._post(
            f"/rest/api/3/issue/{issue_key}/comment",
            body={
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": body}],
                        }
                    ],
                }
            },
        )

    def add_multiline_comment(self, issue_key: str, wiki_text: str) -> dict:
        """Add a plain-text multi-line comment, converting each line to an ADF paragraph."""
        # Split by newlines and create ADF paragraph nodes
        paragraphs = []
        for line in wiki_text.split("\n"):
            if line.strip():
                paragraphs.append({
                    "type": "paragraph",
                    "content": [{"type": "text", "text": line}],
                })
        if not paragraphs:
            paragraphs = [{"type": "paragraph", "content": [{"type": "text", "text": wiki_text}]}]

        return self._post(
            f"/rest/api/3/issue/{issue_key}/comment",
            body={
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": paragraphs,
                }
            },
        )

    def update_priority(self, issue_key: str, priority_name: str) -> None:
        """Update the priority field of a ticket."""
        self._put(
            f"/rest/api/3/issue/{issue_key}",
            body={"fields": {"priority": {"name": priority_name}}},
        )

    def update_labels(self, issue_key: str, labels: list[str]) -> None:
        """Replace all labels on a ticket."""
        self._put(
            f"/rest/api/3/issue/{issue_key}",
            body={"fields": {"labels": labels}},
        )

    def assign_ticket(self, issue_key: str, account_id: str) -> None:
        """Assign a ticket to a user by their Atlassian account ID."""
        self._put(
            f"/rest/api/3/issue/{issue_key}/assignee",
            body={"accountId": account_id},
        )

    def get_transitions(self, issue_key: str) -> list[dict]:
        """Return available workflow transitions for a ticket."""
        data = self._get(f"/rest/api/3/issue/{issue_key}/transitions")
        return data.get("transitions", [])

    def transition_ticket(self, issue_key: str, transition_id: str) -> None:
        """Execute a workflow transition."""
        self._post(
            f"/rest/api/3/issue/{issue_key}/transitions",
            body={"transition": {"id": transition_id}},
        )

    def get_users_by_email(self, email: str) -> list[dict]:
        """Find users by email address (for assignee lookup)."""
        data = self._get("/rest/api/3/user/search", query=email)
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def test_connection(self) -> str:
        """Verify credentials and return the cloud site name."""
        data = self._get("/rest/api/3/serverInfo")
        return data.get("baseUrl", self._base_url or "")
