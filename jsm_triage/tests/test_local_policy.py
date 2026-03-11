"""Tests for LocalPolicyLoader and policy file parsing."""

import json
import textwrap
from pathlib import Path

import pytest

from jsm_triage.grounding.local_policy import (
    LocalPolicyLoader,
    RoutingRule,
    ApprovalRule,
    TriageExample,
    PolicyConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_routing_yaml(path: Path) -> None:
    path.write_text(textwrap.dedent("""\
        rules:
          - category: "Developer Tooling Access"
            subcategory_pattern: "github"
            keywords: ["github", "git"]
            team: "Developer Platform Team"
            assignment_group: "Dev Platform - GitHub"
            notes: "GitHub access"
          - category: "Cloud / Infrastructure Access"
            keywords: ["azure", "subscription"]
            team: "Cloud Platform Team"
            assignment_group: "Cloud - Azure"
    """), encoding="utf-8")


def _write_approval_yaml(path: Path) -> None:
    path.write_text(textwrap.dedent("""\
        rules:
          - category: "Privileged Access"
            requires_approval: true
            approval_type: "Security Team Approval"
            notes: "PAM approval"
          - category: "Password / Account Recovery"
            requires_approval: false
            notes: "Self-service"
    """), encoding="utf-8")


def _write_examples_jsonl(path: Path) -> None:
    examples = [
        {
            "ticket_key": "IT-001",
            "summary": "GitHub access for new engineer",
            "category": "Developer Tooling Access",
            "subcategory": "GitHub org access",
            "recommended_next_step": "Fulfill",
            "rationale": "Standard request.",
            "missing_fields": [],
            "tags": ["github", "onboarding"],
        },
        {
            "ticket_key": "IT-002",
            "summary": "Azure Owner role on production subscription",
            "category": "Privileged Access",
            "subcategory": "Azure RBAC role",
            "recommended_next_step": "Pending Approval",
            "rationale": "Requires security approval.",
            "missing_fields": ["security_team_approval"],
            "tags": ["azure", "privileged"],
        },
    ]
    path.write_text(
        "\n".join(json.dumps(e) for e in examples) + "\n",
        encoding="utf-8",
    )


def _write_policy_yaml(path: Path) -> None:
    path.write_text(textwrap.dedent("""\
        org_context: "We are Example Corp."
        policy_summary: "All access needs manager approval."
        vip_indicators:
          - "CTO"
          - "CEO"
        urgent_termination_indicators:
          - "urgent termination"
          - "suspended employee"
    """), encoding="utf-8")


# ---------------------------------------------------------------------------
# LocalPolicyLoader – basic loading
# ---------------------------------------------------------------------------

class TestLocalPolicyLoader:

    def test_empty_dir_returns_empty_config(self, tmp_path):
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        config = loader.load()
        assert config.is_empty()

    def test_loads_routing_rules(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        _write_routing_yaml(tmp_path / "routing_rules.yaml")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        config = loader.load()
        assert len(config.routing_rules) == 2
        assert config.routing_rules[0].category == "Developer Tooling Access"
        assert config.routing_rules[0].team == "Developer Platform Team"

    def test_loads_approval_rules(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        _write_approval_yaml(tmp_path / "approval_rules.yaml")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        config = loader.load()
        assert len(config.approval_rules) == 2
        priv_rule = config.approval_rules[0]
        assert priv_rule.requires_approval is True
        assert priv_rule.approval_type == "Security Team Approval"

    def test_loads_examples(self, tmp_path):
        _write_examples_jsonl(tmp_path / "triage_examples.jsonl")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        config = loader.load()
        assert len(config.examples) == 2
        assert config.examples[0].ticket_key == "IT-001"
        assert config.examples[0].tags == ["github", "onboarding"]

    def test_loads_policy_yaml(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        _write_policy_yaml(tmp_path / "triage_policy.yaml")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        config = loader.load()
        assert config.org_context == "We are Example Corp."
        assert config.policy_text == "All access needs manager approval."
        assert "CTO" in config.vip_indicators
        assert "urgent termination" in config.urgent_termination_indicators
        assert config.is_empty() is False

    def test_config_is_cached(self, tmp_path):
        _write_examples_jsonl(tmp_path / "triage_examples.jsonl")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        config1 = loader.load()
        config2 = loader.load()
        assert config1 is config2  # same object = cached

    def test_ignores_comments_in_jsonl(self, tmp_path):
        content = (
            "# This is a comment\n"
            '{"ticket_key": "IT-001", "summary": "Test", "category": "Onboarding", '
            '"subcategory": "", "recommended_next_step": "Fulfill", "rationale": "r"}\n'
            "\n"  # blank line
        )
        (tmp_path / "triage_examples.jsonl").write_text(content, encoding="utf-8")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        config = loader.load()
        assert len(config.examples) == 1


# ---------------------------------------------------------------------------
# Rendering rules as text
# ---------------------------------------------------------------------------

class TestRenderRulesText:

    def test_render_routing_rules(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        _write_routing_yaml(tmp_path / "routing_rules.yaml")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        text = loader.render_routing_rules_text()
        assert text is not None
        assert "Developer Platform Team" in text
        assert "Developer Tooling Access" in text

    def test_render_routing_rules_none_when_empty(self, tmp_path):
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        assert loader.render_routing_rules_text() is None

    def test_render_approval_rules(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        _write_approval_yaml(tmp_path / "approval_rules.yaml")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        text = loader.render_approval_rules_text()
        assert text is not None
        assert "Security Team Approval" in text
        assert "Privileged Access" in text


# ---------------------------------------------------------------------------
# find_matching_examples
# ---------------------------------------------------------------------------

class TestFindMatchingExamples:

    def test_finds_relevant_example(self, tmp_path):
        _write_examples_jsonl(tmp_path / "triage_examples.jsonl")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        matches = loader.find_matching_examples("GitHub access for engineer")
        assert len(matches) >= 1
        assert any("github" in ex.tags for ex in matches)

    def test_no_match_returns_empty(self, tmp_path):
        _write_examples_jsonl(tmp_path / "triage_examples.jsonl")
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        # A query that shouldn't match any examples
        matches = loader.find_matching_examples("zzzznotaword")
        assert matches == []

    def test_respects_limit(self, tmp_path):
        # Write 3 very similar examples
        examples = [
            {
                "ticket_key": f"IT-{i:03d}",
                "summary": f"GitHub access request {i}",
                "category": "Developer Tooling Access",
                "subcategory": "GitHub org access",
                "recommended_next_step": "Fulfill",
                "rationale": "Test",
                "tags": ["github"],
            }
            for i in range(5)
        ]
        (tmp_path / "triage_examples.jsonl").write_text(
            "\n".join(json.dumps(e) for e in examples), encoding="utf-8"
        )
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        matches = loader.find_matching_examples("GitHub access", limit=2)
        assert len(matches) <= 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:

    def test_validation_missing_dir(self):
        loader = LocalPolicyLoader(config_dir="/nonexistent/path/xyz")
        issues = loader.validate()
        assert any("not found" in issue.lower() for issue in issues)

    def test_validation_valid_config(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        _write_routing_yaml(tmp_path / "routing_rules.yaml")
        _write_approval_yaml(tmp_path / "approval_rules.yaml")
        _write_examples_jsonl(tmp_path / "triage_examples.jsonl")

        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        issues = loader.validate()
        # With valid files, no error-level issues
        error_issues = [i for i in issues if "error" in i.lower()]
        assert error_issues == []

    def test_validation_bad_jsonl(self, tmp_path):
        (tmp_path / "triage_examples.jsonl").write_text(
            "not valid json\n", encoding="utf-8"
        )
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        issues = loader.validate()
        assert any("JSON" in issue for issue in issues)

    def test_validation_routing_rule_missing_team(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        (tmp_path / "routing_rules.yaml").write_text(
            "rules:\n  - category: 'New Access Request'\n",
            encoding="utf-8",
        )
        loader = LocalPolicyLoader(config_dir=str(tmp_path))
        issues = loader.validate()
        assert any("team" in i.lower() or "group" in i.lower() for i in issues)
