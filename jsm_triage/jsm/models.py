"""Data models for Atlassian JSM entities."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class TicketComment:
    id: str
    author: str
    body: str
    created: Optional[datetime] = None


@dataclass
class Ticket:
    """Represents a JSM / Jira issue."""

    key: str                        # e.g. IT-42
    summary: str
    description: str
    status: str                     # e.g. "Open", "In Progress"
    priority: str                   # e.g. "Medium"
    issue_type: str                 # e.g. "Service Request"
    reporter: str
    assignee: Optional[str]
    labels: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    comments: list[TicketComment] = field(default_factory=list)
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    service_desk_id: Optional[str] = None
    request_type: Optional[str] = None
    custom_fields: dict = field(default_factory=dict)

    def to_triage_dict(self) -> dict:
        """Flatten ticket into a dict suitable for the triage prompt."""
        return {
            "key": self.key,
            "summary": self.summary,
            "description": self.description[:2000] if self.description else "",
            "status": self.status,
            "current_priority": self.priority,
            "issue_type": self.issue_type,
            "reporter": self.reporter,
            "assignee": self.assignee,
            "labels": self.labels,
            "components": self.components,
            "request_type": self.request_type,
            "recent_comments": [
                {"author": c.author, "body": c.body[:500]}
                for c in self.comments[-3:]       # last 3 comments
            ],
        }

    @classmethod
    def from_jira_api(cls, data: dict) -> "Ticket":
        """Construct from a Jira REST API issue response."""
        fields = data.get("fields", {})

        def safe_str(obj, *keys, default="") -> str:
            for k in keys:
                if obj is None:
                    return default
                obj = obj.get(k) if isinstance(obj, dict) else None
            return obj or default

        comments_raw = fields.get("comment", {}).get("comments", [])
        comments = [
            TicketComment(
                id=c.get("id", ""),
                author=safe_str(c, "author", "displayName"),
                body=safe_str(c, "body") if isinstance(c.get("body"), str)
                     else _extract_adf_text(c.get("body")),
            )
            for c in comments_raw
        ]

        description = fields.get("description", "") or ""
        if isinstance(description, dict):
            description = _extract_adf_text(description)

        return cls(
            key=data.get("key", ""),
            summary=fields.get("summary", ""),
            description=description,
            status=safe_str(fields, "status", "name"),
            priority=safe_str(fields, "priority", "name", default="Medium"),
            issue_type=safe_str(fields, "issuetype", "name"),
            reporter=safe_str(fields, "reporter", "displayName"),
            assignee=safe_str(fields, "assignee", "displayName") or None,
            labels=fields.get("labels", []),
            components=[c.get("name", "") for c in fields.get("components", [])],
            comments=comments,
            request_type=safe_str(fields, "customfield_10010", "requestType", "name"),
        )


def _extract_adf_text(adf: object, depth: int = 0) -> str:
    """Recursively extract plain text from Atlassian Document Format (ADF) nodes."""
    if depth > 20:
        return ""
    if isinstance(adf, str):
        return adf
    if not isinstance(adf, dict):
        return ""

    node_type = adf.get("type", "")
    text = adf.get("text", "")
    children = adf.get("content", [])

    parts = []
    if text:
        parts.append(text)
    for child in (children or []):
        parts.append(_extract_adf_text(child, depth + 1))

    joiner = "\n" if node_type in ("paragraph", "heading", "bulletList", "orderedList") else " "
    return joiner.join(p for p in parts if p)


@dataclass
class Queue:
    id: str
    name: str
    issue_count: int = 0


@dataclass
class ServiceDesk:
    id: str
    project_key: str
    name: str
    queues: list[Queue] = field(default_factory=list)
