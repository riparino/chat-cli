"""Tests for the PromptBuilder and related prompt construction logic."""

import pytest

from jsm_triage.jsm.models import Ticket
from jsm_triage.prompts.builder import (
    KnowledgeSnippet,
    PromptBuilder,
    PromptContext,
    _redact_ticket,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ticket(**kwargs) -> Ticket:
    defaults = dict(
        key="IT-42",
        summary="New GitHub org access for contractor John Smith",
        description="John Smith (contractor from Acme Corp) needs GitHub access to repo X.",
        status="Open",
        priority="Medium",
        issue_type="Service Request",
        reporter="jane.doe@example.com",
        assignee=None,
        labels=["new-access"],
        components=[],
        request_type="Developer Tooling Access",
    )
    defaults.update(kwargs)
    return Ticket(**defaults)


def _make_snippet(title: str, content: str = "Policy content.") -> KnowledgeSnippet:
    return KnowledgeSnippet(
        title=title,
        content=content,
        source_url=f"https://wiki.example.com/{title}",
        source_type="confluence",
    )


# ---------------------------------------------------------------------------
# PromptBuilder.build – basic structure
# ---------------------------------------------------------------------------

class TestPromptBuilderBuild:

    def test_contains_ticket_data(self):
        builder = PromptBuilder()
        ticket = _make_ticket()
        prompt = builder.build(ticket)
        assert "IT-42" in prompt
        assert "GitHub org access" in prompt

    def test_contains_triage_instruction(self):
        builder = PromptBuilder()
        prompt = builder.build(_make_ticket())
        assert "Triage" in prompt
        assert "JSON" in prompt

    def test_no_grounding_adds_note(self):
        builder = PromptBuilder()
        prompt = builder.build(_make_ticket(), context=PromptContext())
        assert "No internal policy context" in prompt

    def test_grounding_suppresses_fallback_note(self):
        # routing_rules_text counts as grounding; the fallback note should not appear
        builder = PromptBuilder()
        ctx = PromptContext(routing_rules_text="Route GitHub access to DevPlatform Team.")
        prompt = builder.build(_make_ticket(), context=ctx)
        assert "No internal policy context" not in prompt

    def test_org_context_injected(self):
        builder = PromptBuilder()
        ctx = PromptContext(org_context="ACME Corporation IAM policy context.")
        prompt = builder.build(_make_ticket(), context=ctx)
        assert "ACME Corporation" in prompt
        assert "ORGANISATION CONTEXT" in prompt

    def test_routing_rules_injected(self):
        builder = PromptBuilder()
        ctx = PromptContext(routing_rules_text="Route GitHub access to DevPlatform Team.")
        prompt = builder.build(_make_ticket(), context=ctx)
        assert "DevPlatform Team" in prompt
        assert "ROUTING RULES" in prompt

    def test_approval_rules_injected(self):
        builder = PromptBuilder()
        ctx = PromptContext(approval_rules_text="Privileged access needs Security approval.")
        prompt = builder.build(_make_ticket(), context=ctx)
        assert "Security approval" in prompt
        assert "APPROVAL RULES" in prompt

    def test_knowledge_snippets_injected(self):
        builder = PromptBuilder()
        snippet = _make_snippet("IT Access Policy", "All access needs manager approval.")
        ctx = PromptContext(knowledge_snippets=[snippet])
        prompt = builder.build(_make_ticket(), context=ctx)
        assert "IT Access Policy" in prompt
        assert "manager approval" in prompt
        assert "KNOWLEDGE" in prompt

    def test_example_snippets_injected(self):
        builder = PromptBuilder()
        ctx = PromptContext(example_snippets=["Example: IT-001 – GitHub access\n  Category: Dev Tooling"])
        prompt = builder.build(_make_ticket(), context=ctx)
        assert "IT-001" in prompt
        assert "REVIEWED EXAMPLES" in prompt

    def test_long_description_does_not_exceed_limit(self):
        # Ticket.to_triage_dict() truncates description to 2000 chars.
        # PromptBuilder should still produce a valid prompt.
        long_desc = "x" * 5000
        ticket = _make_ticket(description=long_desc)
        builder = PromptBuilder()
        prompt = builder.build(ticket)
        # Prompt should be built successfully (no error)
        assert "IT-42" in prompt
        # The full 5000-char description should not appear verbatim
        assert "x" * 5000 not in prompt


# ---------------------------------------------------------------------------
# PromptBuilder.build – redaction
# ---------------------------------------------------------------------------

class TestPromptBuilderRedaction:

    def test_redact_reporter(self):
        builder = PromptBuilder(redact_sensitive=True)
        ticket = _make_ticket(reporter="sensitive.person@company.com")
        prompt = builder.build(ticket)
        assert "sensitive.person@company.com" not in prompt
        assert "[REDACTED]" in prompt

    def test_redact_description(self):
        builder = PromptBuilder(redact_sensitive=True)
        ticket = _make_ticket(description="PII data: John Smith SSN 123-45-6789")
        prompt = builder.build(ticket)
        assert "123-45-6789" not in prompt
        assert "[REDACTED]" in prompt

    def test_no_redaction_by_default(self):
        builder = PromptBuilder(redact_sensitive=False)
        ticket = _make_ticket(reporter="jane.doe@example.com")
        prompt = builder.build(ticket)
        assert "jane.doe@example.com" in prompt


# ---------------------------------------------------------------------------
# _redact_ticket helper
# ---------------------------------------------------------------------------

class TestRedactTicket:

    def test_redacts_reporter(self):
        d = {"reporter": "Jane Doe", "summary": "Test ticket", "key": "IT-1"}
        result = _redact_ticket(d)
        assert result["reporter"] == "[REDACTED]"
        assert result["summary"] == "Test ticket"
        assert result["key"] == "IT-1"

    def test_redacts_assignee(self):
        d = {"assignee": "John Smith", "key": "IT-1"}
        result = _redact_ticket(d)
        assert result["assignee"] == "[REDACTED]"

    def test_redacts_description(self):
        d = {"description": "Sensitive info here", "key": "IT-1"}
        result = _redact_ticket(d)
        assert result["description"] == "[REDACTED]"

    def test_redacts_comments(self):
        d = {
            "key": "IT-1",
            "recent_comments": [
                {"author": "Jane", "body": "Please help"},
                {"author": "Admin", "body": "Working on it"},
            ],
        }
        result = _redact_ticket(d)
        for comment in result["recent_comments"]:
            assert comment["body"] == "[REDACTED]"
            assert comment["author"] == "[REDACTED]"

    def test_does_not_redact_empty_fields(self):
        d = {"reporter": "", "key": "IT-1"}
        result = _redact_ticket(d)
        assert result["reporter"] == ""  # empty string left alone

    def test_original_not_mutated(self):
        d = {"reporter": "Jane Doe", "key": "IT-1"}
        _redact_ticket(d)
        assert d["reporter"] == "Jane Doe"  # original unchanged


# ---------------------------------------------------------------------------
# PromptContext.has_grounding
# ---------------------------------------------------------------------------

class TestPromptContextHasGrounding:

    def test_empty_context_has_no_grounding(self):
        ctx = PromptContext()
        assert ctx.has_grounding() is False

    def test_org_context_alone_not_grounding(self):
        ctx = PromptContext(org_context="Some context")
        assert ctx.has_grounding() is False

    def test_routing_rules_is_grounding(self):
        ctx = PromptContext(routing_rules_text="Some rules")
        assert ctx.has_grounding() is True

    def test_knowledge_snippet_is_grounding(self):
        ctx = PromptContext(knowledge_snippets=[_make_snippet("Test")])
        assert ctx.has_grounding() is True

    def test_examples_is_grounding(self):
        ctx = PromptContext(example_snippets=["Example text"])
        assert ctx.has_grounding() is True


# ---------------------------------------------------------------------------
# KnowledgeSnippet.to_prompt_block
# ---------------------------------------------------------------------------

class TestKnowledgeSnippet:

    def test_prompt_block_contains_title(self):
        snippet = _make_snippet("My Policy Page", "This is the content.")
        block = snippet.to_prompt_block()
        assert "My Policy Page" in block
        assert "This is the content." in block

    def test_prompt_block_contains_url(self):
        snippet = KnowledgeSnippet(
            title="Policy",
            content="Content",
            source_url="https://wiki.example.com/policy",
        )
        block = snippet.to_prompt_block()
        assert "wiki.example.com" in block

    def test_prompt_block_truncates_long_content(self):
        long_content = "A" * 2000
        snippet = KnowledgeSnippet(title="T", content=long_content)
        block = snippet.to_prompt_block()
        assert "truncated" in block


# ---------------------------------------------------------------------------
# build_knowledge_query
# ---------------------------------------------------------------------------

class TestBuildKnowledgeQuery:

    def test_uses_summary(self):
        builder = PromptBuilder()
        ticket = _make_ticket(summary="Urgent GitHub access needed")
        query = builder.build_knowledge_query(ticket)
        assert "GitHub" in query

    def test_includes_request_type(self):
        builder = PromptBuilder()
        ticket = _make_ticket(request_type="Developer Tooling Access")
        query = builder.build_knowledge_query(ticket)
        assert "Developer Tooling" in query

    def test_query_not_too_long(self):
        builder = PromptBuilder()
        ticket = _make_ticket(summary="x" * 500)
        query = builder.build_knowledge_query(ticket)
        assert len(query) <= 300
