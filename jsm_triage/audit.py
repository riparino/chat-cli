"""Audit trail writer for triage decisions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, log_file: str | Path = "data/triage_audit.jsonl"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: dict) -> None:
        row = dict(event)
        row.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with self.log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
