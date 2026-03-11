"""Configuration loading and validation for production triage."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class FeatureFlags:
    dry_run_default: bool = True
    allow_comment_posting: bool = False
    allow_priority_updates: bool = False
    allow_label_updates: bool = False
    allow_assignment_suggestions: bool = True


@dataclass
class GroundingConfig:
    confluence_queries: list[str] = field(default_factory=list)
    confluence_pages: list[str] = field(default_factory=list)
    confluence_spaces: list[str] = field(default_factory=list)
    confluence_labels: list[str] = field(default_factory=list)
    max_snippets: int = 5


@dataclass
class TriageConfig:
    categories: list[str] = field(default_factory=list)
    required_fields_by_category: dict[str, list[str]] = field(default_factory=dict)
    vip_keywords: list[str] = field(default_factory=list)
    urgent_termination_keywords: list[str] = field(default_factory=list)


@dataclass
class RoutingConfig:
    rules: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ApprovalConfig:
    rules: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AppConfig:
    triage_policy: TriageConfig = field(default_factory=TriageConfig)
    routing_rules: RoutingConfig = field(default_factory=RoutingConfig)
    approval_rules: ApprovalConfig = field(default_factory=ApprovalConfig)
    grounding: GroundingConfig = field(default_factory=GroundingConfig)
    feature_flags: FeatureFlags = field(default_factory=FeatureFlags)
    examples: list[dict[str, Any]] = field(default_factory=list)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    content = path.read_text()
    if yaml is not None:
        raw = yaml.safe_load(content)
        return raw or {}
    return json.loads(content) if content.strip() else {}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def load_app_config(config_dir: str | Path = "config") -> AppConfig:
    cdir = Path(config_dir)
    triage_policy = _load_yaml(cdir / "triage_policy.yaml")
    routing_rules = _load_yaml(cdir / "routing_rules.yaml")
    approval_rules = _load_yaml(cdir / "approval_rules.yaml")
    grounding = _load_yaml(cdir / "grounding.yaml")
    feature_flags = _load_yaml(cdir / "feature_flags.yaml")
    examples = _load_jsonl(cdir / "triage_examples.jsonl")

    return AppConfig(
        triage_policy=TriageConfig(**{k: v for k, v in triage_policy.items() if k in TriageConfig.__annotations__}),
        routing_rules=RoutingConfig(rules=routing_rules.get("rules", [])),
        approval_rules=ApprovalConfig(rules=approval_rules.get("rules", [])),
        grounding=GroundingConfig(**{k: v for k, v in grounding.items() if k in GroundingConfig.__annotations__}),
        feature_flags=FeatureFlags(**{k: v for k, v in feature_flags.items() if k in FeatureFlags.__annotations__}),
        examples=examples,
    )


def validate_config(config: AppConfig) -> list[str]:
    issues: list[str] = []
    if not config.triage_policy.categories:
        issues.append("triage_policy.categories is empty")
    if config.grounding.max_snippets <= 0:
        issues.append("grounding.max_snippets must be > 0")
    for i, rule in enumerate(config.routing_rules.rules):
        if "category" not in rule or "assignment_group" not in rule:
            issues.append(f"routing_rules.rules[{i}] missing category/assignment_group")
    return issues
