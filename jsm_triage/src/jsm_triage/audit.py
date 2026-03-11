"""
Structured audit logging for triage operations.

Every triage operation is logged to ~/.jsm_triage/audit.jsonl with:
  - Ticket key and summary (PII-aware truncation)
  - Provider used
  - Sources used (knowledge snippets cited)
  - Triage result summary (category, priority, recommended_next_step)
  - Actions taken (comment posted, priority updated, label added)
  - Dry-run status
  - Timestamp

The audit log is append-only and human-readable (JSONL format).
It provides the auditability required for enterprise deployment:
every AI-assisted triage decision is traceable.

Additionally configures Python structured logging for the jsm_triage package
so that log output can be directed to a file or log aggregation system.
"""

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_LOG_DIR = Path.home() / ".jsm_triage"
_AUDIT_FILE = _LOG_DIR / "audit.jsonl"
_LOG_FILE = _LOG_DIR / "jsm_triage.log"

logger = logging.getLogger(__name__)


def configure_logging(
    verbose: bool = False,
    log_to_file: bool = True,
    log_dir: Optional[Path] = None,
) -> None:
    """
    Configure structured logging for the jsm_triage package.

    - Console: INFO level (DEBUG if verbose)
    - File: DEBUG level (if log_to_file, rotating, 5MB × 3 backups)

    Call this once at CLI startup.
    """
    log_dir = log_dir or _LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger("jsm_triage")
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_handler.setFormatter(
        logging.Formatter("%(levelname)s [%(name)s] %(message)s")
    )
    root_logger.addHandler(console_handler)

    # File handler (rotating)
    if log_to_file:
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_dir / "jsm_triage.log",
                maxBytes=5 * 1024 * 1024,  # 5 MB
                backupCount=3,
                encoding="utf-8",
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%SZ",
                )
            )
            root_logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("Could not create log file: %s", exc)


class AuditLog:
    """
    Append-only audit log for triage operations.

    Records every triage event with enough context to reproduce and
    review the decision later. This is the primary auditability mechanism.

    Thread-safety: Not thread-safe; designed for single-user CLI.
    """

    def __init__(self, audit_path: Optional[Path] = None):
        self._path = audit_path or _AUDIT_FILE
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        ticket_key: str,
        ticket_summary: str,
        provider_used: str,
        result_dict: Optional[dict] = None,
        knowledge_sources: Optional[list[str]] = None,
        actions_taken: Optional[dict] = None,
        dry_run: bool = False,
        error: Optional[str] = None,
    ) -> None:
        """
        Write a triage audit record.

        Args:
            ticket_key:        Jira ticket key (e.g. IT-42)
            ticket_summary:    Truncated ticket summary (no PII beyond key)
            provider_used:     AI provider name
            result_dict:       Serialised IAMTriageResult (or None on failure)
            knowledge_sources: List of knowledge source titles/IDs used
            actions_taken:     Dict of JSM actions (comment_posted, priority_updated, etc.)
            dry_run:           Whether this was a dry-run (no JSM writes)
            error:             Error message if triage failed
        """
        record = {
            "timestamp": _now_iso(),
            "ticket_key": ticket_key,
            "ticket_summary": (ticket_summary or "")[:120],  # truncate for audit log
            "provider_used": provider_used,
            "dry_run": dry_run,
            "knowledge_sources_used": knowledge_sources or [],
            "actions_taken": actions_taken or {},
        }

        if result_dict:
            record["result"] = {
                "category": result_dict.get("category"),
                "subcategory": result_dict.get("subcategory"),
                "priority": result_dict.get("priority"),
                "recommended_next_step": result_dict.get("recommended_next_step"),
                "confidence": result_dict.get("confidence"),
                "escalation_required": result_dict.get("escalation_required"),
                "requires_approval": result_dict.get("requires_approval"),
            }

        if error:
            record["error"] = error

        try:
            line = json.dumps(record, ensure_ascii=False)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as exc:
            logger.error("Failed to write audit record for %s: %s", ticket_key, exc)

    def get_records(
        self,
        ticket_key: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Read audit records, optionally filtered by ticket key."""
        if not self._path.exists():
            return []

        records = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if ticket_key is None or record.get("ticket_key") == ticket_key:
                    records.append(record)
            except json.JSONDecodeError:
                continue

        # Return most recent first, up to limit
        return list(reversed(records))[:limit]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
