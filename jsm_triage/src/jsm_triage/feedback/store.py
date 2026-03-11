"""
Feedback store for tracking triage decisions and human-reviewed outcomes.

Design principles:
  - No hidden model fine-tuning or autonomous policy mutation.
  - All feedback is stored explicitly in a human-readable JSONL file.
  - Proposed improvements are staged for admin review; never applied automatically.
  - The feedback store is the source of truth for building example corpora.
  - Feedback is append-only; records are never silently overwritten.

Storage location:
  ~/.jsm_triage/feedback.jsonl       – main feedback store
  ~/.jsm_triage/staged_rules.jsonl   – candidate routing rules for admin review

Record schema:
  {
    "ticket_key": "IT-42",
    "timestamp": "2024-01-15T10:30:00Z",
    "triage_result": { ... IAMTriageResult fields ... },
    "outcome": "accepted" | "corrected" | "rejected",
    "correction": { ... corrected fields, if outcome is "corrected" ... },
    "reviewer_notes": "...",
    "approved_as_example": false,
    "example_tags": []
  }
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Outcome values
OUTCOME_ACCEPTED = "accepted"
OUTCOME_CORRECTED = "corrected"
OUTCOME_REJECTED = "rejected"
VALID_OUTCOMES = {OUTCOME_ACCEPTED, OUTCOME_CORRECTED, OUTCOME_REJECTED}

_DEFAULT_STORE_DIR = Path.home() / ".jsm_triage"


class FeedbackStore:
    """
    Persistent store for triage decisions and human outcomes.

    Thread-safety: Not thread-safe. Designed for single-user CLI usage.
    File format: JSONL (one JSON record per line, append-only).
    """

    def __init__(self, store_dir: Optional[Path] = None):
        self._dir = store_dir or _DEFAULT_STORE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._feedback_path = self._dir / "feedback.jsonl"
        self._staged_rules_path = self._dir / "staged_rules.jsonl"

    # ------------------------------------------------------------------
    # Writing feedback
    # ------------------------------------------------------------------

    def record_triage(
        self,
        ticket_key: str,
        triage_result_dict: dict,
        provider_used: str,
        knowledge_sources: Optional[list[str]] = None,
    ) -> None:
        """
        Record a triage decision without outcome (pending human review).

        Call this immediately after triage to create a record.
        The outcome can be updated later via record_outcome().
        """
        record = {
            "ticket_key": ticket_key,
            "timestamp": _now_iso(),
            "triage_result": triage_result_dict,
            "provider_used": provider_used,
            "knowledge_sources": knowledge_sources or [],
            "outcome": None,
            "correction": None,
            "reviewer_notes": None,
            "approved_as_example": False,
            "example_tags": [],
        }
        self._append(self._feedback_path, record)
        logger.debug("Recorded triage for %s", ticket_key)

    def record_outcome(
        self,
        ticket_key: str,
        outcome: str,
        correction: Optional[dict] = None,
        reviewer_notes: Optional[str] = None,
        approved_as_example: bool = False,
        example_tags: Optional[list[str]] = None,
    ) -> bool:
        """
        Record the human outcome for a previously triaged ticket.

        This creates a NEW record with the outcome, preserving the
        immutable original triage record. Returns True if the original
        record was found.

        Args:
            ticket_key:           The ticket key (e.g. IT-42).
            outcome:              "accepted" | "corrected" | "rejected"
            correction:           Dict of corrected fields (if outcome=="corrected").
            reviewer_notes:       Free-text notes from the reviewer.
            approved_as_example:  If True, this ticket is approved for use as
                                  a grounding example in future triage.
            example_tags:         Tags to categorise this example.
        """
        if outcome not in VALID_OUTCOMES:
            raise ValueError(
                f"Invalid outcome '{outcome}'. Must be one of: {VALID_OUTCOMES}"
            )

        record = {
            "ticket_key": ticket_key,
            "timestamp": _now_iso(),
            "record_type": "outcome",
            "outcome": outcome,
            "correction": correction,
            "reviewer_notes": reviewer_notes,
            "approved_as_example": approved_as_example,
            "example_tags": example_tags or [],
        }
        self._append(self._feedback_path, record)
        logger.info("Recorded outcome '%s' for %s", outcome, ticket_key)
        return True

    def stage_rule_candidate(
        self,
        rule_type: str,
        suggested_rule: dict,
        supporting_tickets: list[str],
        notes: str = "",
    ) -> None:
        """
        Stage a candidate routing or approval rule for admin review.

        Staged rules are NEVER applied automatically. An admin must review
        them via `jsm-triage review-rules` and manually add approved rules
        to the config files.

        Args:
            rule_type:           "routing" | "approval"
            suggested_rule:      The proposed rule dict.
            supporting_tickets:  Ticket keys that support this suggestion.
            notes:               Explanation of why this rule is suggested.
        """
        record = {
            "timestamp": _now_iso(),
            "rule_type": rule_type,
            "suggested_rule": suggested_rule,
            "supporting_tickets": supporting_tickets,
            "notes": notes,
            "status": "pending_review",  # never changes automatically
        }
        self._append(self._staged_rules_path, record)
        logger.info("Staged %s rule candidate for admin review", rule_type)

    # ------------------------------------------------------------------
    # Reading feedback
    # ------------------------------------------------------------------

    def get_all_records(self) -> list[dict]:
        """Return all feedback records in chronological order."""
        return self._read_all(self._feedback_path)

    def get_records_for_ticket(self, ticket_key: str) -> list[dict]:
        """Return all feedback records for a specific ticket."""
        return [
            r for r in self._read_all(self._feedback_path)
            if r.get("ticket_key") == ticket_key
        ]

    def get_approved_examples(self) -> list[dict]:
        """
        Return all records approved as grounding examples.

        These are outcome records with approved_as_example=True.
        Suitable for export into triage_examples.jsonl.
        """
        examples = []
        for record in self._read_all(self._feedback_path):
            if record.get("approved_as_example") and record.get("record_type") == "outcome":
                examples.append(record)
        return examples

    def get_staged_rules(self) -> list[dict]:
        """Return all staged candidate rules pending admin review."""
        return self._read_all(self._staged_rules_path)

    def get_statistics(self) -> dict:
        """Return aggregate statistics about the feedback corpus."""
        records = self._read_all(self._feedback_path)
        triages = [r for r in records if r.get("record_type") != "outcome"]
        outcomes = [r for r in records if r.get("record_type") == "outcome"]

        by_outcome = {OUTCOME_ACCEPTED: 0, OUTCOME_CORRECTED: 0, OUTCOME_REJECTED: 0}
        for r in outcomes:
            outcome = r.get("outcome")
            if outcome in by_outcome:
                by_outcome[outcome] += 1

        return {
            "total_triaged": len(triages),
            "total_outcomes_recorded": len(outcomes),
            "outcomes_by_type": by_outcome,
            "approved_examples": sum(
                1 for r in outcomes if r.get("approved_as_example")
            ),
            "staged_rules": len(self.get_staged_rules()),
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_examples_jsonl(
        self, output_path: Optional[Path] = None
    ) -> tuple[int, Path]:
        """
        Export approved examples to a triage_examples.jsonl file.

        The exported file can be placed in the config/ directory to be
        used as grounding context in future triage operations.

        Returns:
            (count, output_path) – number of examples exported and the path.
        """
        examples = self.get_approved_examples()

        if output_path is None:
            output_path = self._dir / "exported_examples.jsonl"

        lines = []
        for record in examples:
            # Build an example record from the outcome + correction
            triage = record.get("correction") or {}
            example = {
                "ticket_key": record.get("ticket_key", ""),
                "summary": triage.get("request_type", ""),
                "category": triage.get("category", ""),
                "subcategory": triage.get("subcategory", ""),
                "recommended_next_step": triage.get("recommended_next_step", ""),
                "rationale": triage.get("rationale", ""),
                "missing_fields": triage.get("missing_fields", []),
                "tags": record.get("example_tags", []),
                "_source_outcome_timestamp": record.get("timestamp", ""),
                "_reviewer_notes": record.get("reviewer_notes", ""),
            }
            lines.append(json.dumps(example, ensure_ascii=False))

        output_path.write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")
        logger.info("Exported %d examples to %s", len(examples), output_path)
        return len(examples), output_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _append(path: Path, record: dict) -> None:
        """Append a record to a JSONL file."""
        line = json.dumps(record, ensure_ascii=False)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    @staticmethod
    def _read_all(path: Path) -> list[dict]:
        """Read all records from a JSONL file."""
        if not path.exists():
            return []
        records = []
        for line_num, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed JSON at %s line %d: %s", path, line_num, exc)
        return records


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
