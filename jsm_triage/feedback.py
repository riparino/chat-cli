"""Explicit feedback loop storage and exports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FeedbackStore:
    def __init__(self, base_dir: str | Path = "data"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.feedback_file = self.base_dir / "triage_feedback.jsonl"

    def record(self, record: dict[str, Any]) -> None:
        record = dict(record)
        record.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with self.feedback_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def load(self) -> list[dict[str, Any]]:
        if not self.feedback_file.exists():
            return []
        rows = []
        for line in self.feedback_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def export_examples(self, output_file: str | Path) -> int:
        rows = [r for r in self.load() if r.get("outcome") in {"accepted", "corrected"}]
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return len(rows)

    def candidate_rule_updates(self) -> list[dict[str, Any]]:
        proposals = []
        for row in self.load():
            if row.get("outcome") == "corrected" and row.get("final_assignment_group"):
                proposals.append(
                    {
                        "category": row.get("final_category") or row.get("predicted_category"),
                        "assignment_group": row.get("final_assignment_group"),
                        "source_ticket": row.get("ticket"),
                        "note": "Candidate only; admin review required",
                    }
                )
        return proposals
