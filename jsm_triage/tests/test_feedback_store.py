"""Tests for FeedbackStore."""

import json
from pathlib import Path

import pytest

from jsm_triage.feedback.store import (
    FeedbackStore,
    OUTCOME_ACCEPTED,
    OUTCOME_CORRECTED,
    OUTCOME_REJECTED,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_triage_dict() -> dict:
    return {
        "category": "Developer Tooling Access",
        "subcategory": "GitHub org access",
        "priority": "Medium",
        "recommended_next_step": "Fulfill",
        "confidence": 0.85,
        "rationale": "Standard request.",
    }


# ---------------------------------------------------------------------------
# FeedbackStore – basic operations
# ---------------------------------------------------------------------------

class TestFeedbackStore:

    def test_record_triage_creates_file(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        store.record_triage(
            ticket_key="IT-42",
            triage_result_dict=_sample_triage_dict(),
            provider_used="Azure OpenAI",
        )
        assert (tmp_path / "feedback.jsonl").exists()

    def test_record_outcome_creates_record(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        store.record_outcome(
            ticket_key="IT-42",
            outcome=OUTCOME_ACCEPTED,
        )
        records = store.get_all_records()
        outcome_records = [r for r in records if r.get("outcome") == OUTCOME_ACCEPTED]
        assert len(outcome_records) == 1

    def test_invalid_outcome_raises(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        with pytest.raises(ValueError, match="Invalid outcome"):
            store.record_outcome("IT-42", "invalid_outcome")

    def test_get_records_for_ticket(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        store.record_triage("IT-1", _sample_triage_dict(), "Azure OpenAI")
        store.record_triage("IT-2", _sample_triage_dict(), "OpenAI")
        store.record_outcome("IT-1", OUTCOME_ACCEPTED)

        records = store.get_records_for_ticket("IT-1")
        assert len(records) == 2
        assert all(r.get("ticket_key") == "IT-1" for r in records)

        records_it2 = store.get_records_for_ticket("IT-2")
        assert len(records_it2) == 1

    def test_approved_examples(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        store.record_outcome(
            "IT-42",
            OUTCOME_ACCEPTED,
            approved_as_example=True,
            example_tags=["github", "onboarding"],
        )
        store.record_outcome("IT-43", OUTCOME_REJECTED, approved_as_example=False)

        examples = store.get_approved_examples()
        assert len(examples) == 1
        assert examples[0]["ticket_key"] == "IT-42"

    def test_statistics(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        store.record_triage("IT-1", _sample_triage_dict(), "P1")
        store.record_triage("IT-2", _sample_triage_dict(), "P1")
        store.record_outcome("IT-1", OUTCOME_ACCEPTED)
        store.record_outcome("IT-2", OUTCOME_CORRECTED, approved_as_example=True)

        stats = store.get_statistics()
        assert stats["total_triaged"] == 2
        assert stats["total_outcomes_recorded"] == 2
        assert stats["outcomes_by_type"][OUTCOME_ACCEPTED] == 1
        assert stats["outcomes_by_type"][OUTCOME_CORRECTED] == 1
        assert stats["approved_examples"] == 1

    def test_export_examples_jsonl(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        correction = {
            "category": "Developer Tooling Access",
            "subcategory": "GitHub org access",
            "recommended_next_step": "Fulfill",
            "rationale": "Standard request.",
        }
        store.record_outcome(
            "IT-42",
            OUTCOME_CORRECTED,
            correction=correction,
            approved_as_example=True,
            example_tags=["github"],
            reviewer_notes="Good example of GitHub access",
        )

        output = tmp_path / "out.jsonl"
        count, path = store.export_examples_jsonl(output_path=output)
        assert count == 1
        assert path == output

        lines = output.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        exported = json.loads(lines[0])
        assert exported["category"] == "Developer Tooling Access"
        assert exported["tags"] == ["github"]

    def test_export_empty_store(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        count, path = store.export_examples_jsonl(tmp_path / "out.jsonl")
        assert count == 0

    def test_stage_rule_candidate(self, tmp_path):
        store = FeedbackStore(store_dir=tmp_path)
        store.stage_rule_candidate(
            rule_type="routing",
            suggested_rule={"category": "New Access Request", "team": "IAM Team"},
            supporting_tickets=["IT-1", "IT-2"],
            notes="Repeatedly routed here",
        )

        staged = store.get_staged_rules()
        assert len(staged) == 1
        assert staged[0]["rule_type"] == "routing"
        assert staged[0]["status"] == "pending_review"  # never auto-applied
        assert "IT-1" in staged[0]["supporting_tickets"]

    def test_feedback_is_append_only(self, tmp_path):
        """Records must not be overwritten."""
        store = FeedbackStore(store_dir=tmp_path)
        store.record_triage("IT-42", _sample_triage_dict(), "P1")
        store.record_triage("IT-42", _sample_triage_dict(), "P1")  # second record

        records = store.get_records_for_ticket("IT-42")
        assert len(records) == 2  # both records preserved

    def test_handles_missing_store_dir(self, tmp_path):
        """Should create the store directory if it doesn't exist."""
        new_dir = tmp_path / "new" / "nested" / "dir"
        store = FeedbackStore(store_dir=new_dir)
        store.record_triage("IT-1", _sample_triage_dict(), "P1")
        assert (new_dir / "feedback.jsonl").exists()
