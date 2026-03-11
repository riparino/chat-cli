"""
Local policy and rules loader for offline/fallback grounding.

Loads admin-curated configuration files:
  - config/triage_policy.yaml    – general policy rules and category guidance
  - config/routing_rules.yaml    – category → team routing mappings
  - config/approval_rules.yaml   – when approval is required and what type
  - config/triage_examples.jsonl – reviewed example tickets for grounding
  - config/grounding_sources.yaml – Confluence spaces/pages to search

These files are first-class grounding sources. The system works entirely
from local config when Confluence/Rovo is unavailable.

Config discovery order (highest to lowest priority):
  1. Path passed explicitly
  2. TRIAGE_CONFIG_DIR environment variable
  3. ~/.jsm_triage/config/
  4. <package_root>/config/  (bundled examples)

Explicit limitations:
  - These files are static; they do not auto-update.
  - Admins must manually update them to reflect policy changes.
  - Example tickets are injected verbatim; quality depends on curation.
  - No semantic matching; routing rules are keyword/pattern based.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import yaml; fall back gracefully if not installed
try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False
    logger.warning(
        "PyYAML not installed – local YAML policy files will not be loaded. "
        "Run: pip install pyyaml"
    )

# Package config directory (bundled examples)
_PACKAGE_CONFIG_DIR = Path(__file__).parent.parent.parent.parent.parent / "config"
# User config directory
_USER_CONFIG_DIR = Path.home() / ".jsm_triage" / "config"


@dataclass
class RoutingRule:
    """Maps a category/subcategory pattern to a team and assignment group."""
    category: str
    subcategory_pattern: Optional[str] = None   # substring match, case-insensitive
    keywords: list[str] = field(default_factory=list)  # ticket summary/description keywords
    team: Optional[str] = None
    assignment_group: Optional[str] = None
    priority_hint: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class ApprovalRule:
    """Defines when approval is required and what type."""
    category: str
    subcategory_pattern: Optional[str] = None
    keywords: list[str] = field(default_factory=list)
    requires_approval: bool = True
    approval_type: str = "Manager Approval"
    notes: Optional[str] = None


@dataclass
class TriageExample:
    """A reviewed historical ticket used as a grounding example."""
    ticket_key: str
    summary: str
    category: str
    subcategory: str
    recommended_next_step: str
    rationale: str
    missing_fields: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class PolicyConfig:
    """Aggregated local policy configuration."""
    routing_rules: list[RoutingRule] = field(default_factory=list)
    approval_rules: list[ApprovalRule] = field(default_factory=list)
    examples: list[TriageExample] = field(default_factory=list)
    org_context: Optional[str] = None
    vip_indicators: list[str] = field(default_factory=list)   # email domains, job titles
    urgent_termination_indicators: list[str] = field(default_factory=list)
    policy_text: Optional[str] = None   # raw triage_policy.yaml summary text

    def is_empty(self) -> bool:
        return not (self.routing_rules or self.approval_rules or self.examples)


@dataclass
class GroundingSourcesConfig:
    """Configuration for Confluence grounding sources."""
    cql_queries: list[str] = field(default_factory=list)
    page_ids: list[str] = field(default_factory=list)
    spaces: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    result_limit: int = 5


class LocalPolicyLoader:
    """
    Loads and validates admin-curated local policy configuration files.

    Config file discovery:
      1. config_dir argument (explicit)
      2. TRIAGE_CONFIG_DIR env var
      3. ~/.jsm_triage/config/
      4. <package>/config/ (bundled examples)

    Files loaded:
      - triage_policy.yaml     → org_context, vip_indicators, policy_text
      - routing_rules.yaml     → routing_rules list
      - approval_rules.yaml    → approval_rules list
      - triage_examples.jsonl  → examples list
      - grounding_sources.yaml → Confluence sources config
    """

    def __init__(self, config_dir: Optional[str] = None):
        self._config_dir = self._resolve_config_dir(config_dir)
        self._loaded_config: Optional[PolicyConfig] = None
        self._loaded_grounding: Optional[GroundingSourcesConfig] = None

    def _resolve_config_dir(self, explicit: Optional[str]) -> Path:
        if explicit:
            p = Path(explicit)
            if p.is_dir():
                return p
            logger.warning("Specified config dir %s not found", explicit)

        env_dir = os.getenv("TRIAGE_CONFIG_DIR")
        if env_dir:
            p = Path(env_dir)
            if p.is_dir():
                return p

        if _USER_CONFIG_DIR.is_dir():
            return _USER_CONFIG_DIR

        if _PACKAGE_CONFIG_DIR.is_dir():
            return _PACKAGE_CONFIG_DIR

        logger.debug("No config directory found; using empty policy config")
        return _PACKAGE_CONFIG_DIR  # may not exist, handled gracefully

    def config_dir(self) -> Path:
        return self._config_dir

    def load(self) -> PolicyConfig:
        """Load all policy config files. Returns empty PolicyConfig on any failure."""
        if self._loaded_config is not None:
            return self._loaded_config

        config = PolicyConfig()

        # triage_policy.yaml
        policy_path = self._config_dir / "triage_policy.yaml"
        if policy_path.exists() and _YAML_AVAILABLE:
            try:
                data = _load_yaml(policy_path)
                config.org_context = data.get("org_context")
                config.vip_indicators = data.get("vip_indicators", [])
                config.urgent_termination_indicators = data.get(
                    "urgent_termination_indicators", []
                )
                config.policy_text = data.get("policy_summary")
                logger.info("Loaded triage_policy.yaml from %s", policy_path)
            except Exception as exc:
                logger.warning("Could not load triage_policy.yaml: %s", exc)

        # routing_rules.yaml
        routing_path = self._config_dir / "routing_rules.yaml"
        if routing_path.exists() and _YAML_AVAILABLE:
            try:
                data = _load_yaml(routing_path)
                rules_raw = data.get("rules", [])
                for r in rules_raw:
                    config.routing_rules.append(RoutingRule(
                        category=r.get("category", ""),
                        subcategory_pattern=r.get("subcategory_pattern"),
                        keywords=r.get("keywords", []),
                        team=r.get("team"),
                        assignment_group=r.get("assignment_group"),
                        priority_hint=r.get("priority_hint"),
                        notes=r.get("notes"),
                    ))
                logger.info(
                    "Loaded %d routing rules from %s",
                    len(config.routing_rules),
                    routing_path,
                )
            except Exception as exc:
                logger.warning("Could not load routing_rules.yaml: %s", exc)

        # approval_rules.yaml
        approval_path = self._config_dir / "approval_rules.yaml"
        if approval_path.exists() and _YAML_AVAILABLE:
            try:
                data = _load_yaml(approval_path)
                rules_raw = data.get("rules", [])
                for r in rules_raw:
                    config.approval_rules.append(ApprovalRule(
                        category=r.get("category", ""),
                        subcategory_pattern=r.get("subcategory_pattern"),
                        keywords=r.get("keywords", []),
                        requires_approval=r.get("requires_approval", True),
                        approval_type=r.get("approval_type", "Manager Approval"),
                        notes=r.get("notes"),
                    ))
                logger.info(
                    "Loaded %d approval rules from %s",
                    len(config.approval_rules),
                    approval_path,
                )
            except Exception as exc:
                logger.warning("Could not load approval_rules.yaml: %s", exc)

        # triage_examples.jsonl
        examples_path = self._config_dir / "triage_examples.jsonl"
        if examples_path.exists():
            try:
                for line in examples_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ex_data = json.loads(line)
                    config.examples.append(TriageExample(
                        ticket_key=ex_data.get("ticket_key", ""),
                        summary=ex_data.get("summary", ""),
                        category=ex_data.get("category", ""),
                        subcategory=ex_data.get("subcategory", ""),
                        recommended_next_step=ex_data.get("recommended_next_step", ""),
                        rationale=ex_data.get("rationale", ""),
                        missing_fields=ex_data.get("missing_fields", []),
                        tags=ex_data.get("tags", []),
                    ))
                logger.info(
                    "Loaded %d triage examples from %s",
                    len(config.examples),
                    examples_path,
                )
            except Exception as exc:
                logger.warning("Could not load triage_examples.jsonl: %s", exc)

        self._loaded_config = config
        return config

    def load_grounding_sources(self) -> GroundingSourcesConfig:
        """Load Confluence grounding sources configuration."""
        if self._loaded_grounding is not None:
            return self._loaded_grounding

        gs = GroundingSourcesConfig()
        sources_path = self._config_dir / "grounding_sources.yaml"

        if sources_path.exists() and _YAML_AVAILABLE:
            try:
                data = _load_yaml(sources_path)
                gs.cql_queries = data.get("cql_queries", [])
                gs.page_ids = data.get("page_ids", [])
                gs.spaces = data.get("spaces", [])
                gs.labels = data.get("labels", [])
                gs.result_limit = data.get("result_limit", 5)
                logger.info("Loaded grounding_sources.yaml from %s", sources_path)
            except Exception as exc:
                logger.warning("Could not load grounding_sources.yaml: %s", exc)

        self._loaded_grounding = gs
        return gs

    def render_routing_rules_text(self) -> Optional[str]:
        """
        Render routing rules as a compact text block for prompt injection.

        Returns None if no rules are loaded.
        """
        config = self.load()
        if not config.routing_rules:
            return None

        lines = ["Category routing rules (admin-curated):"]
        for rule in config.routing_rules:
            parts = [f"  Category: {rule.category}"]
            if rule.subcategory_pattern:
                parts.append(f"Subcategory contains: {rule.subcategory_pattern}")
            if rule.keywords:
                parts.append(f"Keywords: {', '.join(rule.keywords)}")
            if rule.team:
                parts.append(f"→ Team: {rule.team}")
            if rule.assignment_group:
                parts.append(f"→ Group: {rule.assignment_group}")
            if rule.priority_hint:
                parts.append(f"Priority hint: {rule.priority_hint}")
            lines.append("  | ".join(parts))
        return "\n".join(lines)

    def render_approval_rules_text(self) -> Optional[str]:
        """
        Render approval rules as a compact text block for prompt injection.

        Returns None if no rules are loaded.
        """
        config = self.load()
        if not config.approval_rules:
            return None

        lines = ["Approval rules (admin-curated):"]
        for rule in config.approval_rules:
            parts = [f"  Category: {rule.category}"]
            if rule.subcategory_pattern:
                parts.append(f"Subcategory contains: {rule.subcategory_pattern}")
            if rule.keywords:
                parts.append(f"Keywords: {', '.join(rule.keywords)}")
            parts.append(
                f"→ requires_approval={rule.requires_approval}, "
                f"approval_type={rule.approval_type}"
            )
            lines.append("  | ".join(parts))
        return "\n".join(lines)

    def find_matching_examples(
        self, query: str, limit: int = 3
    ) -> list[TriageExample]:
        """
        Find reviewed examples relevant to the query using simple keyword matching.

        This is intentionally a simple keyword match, not a semantic search.
        The intent is to retrieve exact or near-exact pattern matches, not
        fuzzy AI-style matches. Better than random; deterministic.
        """
        config = self.load()
        if not config.examples:
            return []

        query_lower = query.lower()
        scored: list[tuple[int, TriageExample]] = []

        for ex in config.examples:
            score = 0
            # Check summary
            if ex.summary:
                for word in query_lower.split():
                    if len(word) > 3 and word in ex.summary.lower():
                        score += 2
            # Check category
            if ex.category and ex.category.lower() in query_lower:
                score += 3
            # Check subcategory
            if ex.subcategory and ex.subcategory.lower() in query_lower:
                score += 3
            # Check tags
            for tag in ex.tags:
                if tag.lower() in query_lower:
                    score += 2
            if score > 0:
                scored.append((score, ex))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [ex for _, ex in scored[:limit]]

    def render_example_snippets(
        self, examples: list[TriageExample]
    ) -> list[str]:
        """Convert TriageExample objects to compact text snippets for prompt injection."""
        snippets = []
        for ex in examples:
            lines = [
                f"Example: {ex.ticket_key} – {ex.summary}",
                f"  Category: {ex.category} / {ex.subcategory}",
                f"  Next Step: {ex.recommended_next_step}",
                f"  Rationale: {ex.rationale[:200]}",
            ]
            if ex.missing_fields:
                lines.append(f"  Missing: {', '.join(ex.missing_fields)}")
            snippets.append("\n".join(lines))
        return snippets

    def validate(self) -> list[str]:
        """
        Validate all config files and return a list of issues found.

        Returns an empty list if everything is valid.
        """
        issues: list[str] = []

        if not self._config_dir.exists():
            issues.append(
                f"Config directory not found: {self._config_dir}. "
                "Create it and add policy files, or set TRIAGE_CONFIG_DIR."
            )
            return issues

        if not _YAML_AVAILABLE:
            issues.append(
                "PyYAML not installed. YAML policy files cannot be loaded. "
                "Run: pip install pyyaml"
            )

        for fname in [
            "triage_policy.yaml",
            "routing_rules.yaml",
            "approval_rules.yaml",
            "grounding_sources.yaml",
        ]:
            fpath = self._config_dir / fname
            if not fpath.exists():
                issues.append(f"Missing config file (not required but recommended): {fpath}")
            elif _YAML_AVAILABLE:
                try:
                    _load_yaml(fpath)
                except Exception as exc:
                    issues.append(f"YAML parse error in {fname}: {exc}")

        examples_path = self._config_dir / "triage_examples.jsonl"
        if not examples_path.exists():
            issues.append(
                f"Missing examples file (not required but recommended): {examples_path}"
            )
        else:
            try:
                for i, line in enumerate(
                    examples_path.read_text(encoding="utf-8").splitlines(), 1
                ):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        json.loads(line)
            except json.JSONDecodeError as exc:
                issues.append(f"JSON parse error in triage_examples.jsonl line {i}: {exc}")
            except Exception as exc:
                issues.append(f"Error reading triage_examples.jsonl: {exc}")

        # Validate routing rules structure
        routing_path = self._config_dir / "routing_rules.yaml"
        if routing_path.exists() and _YAML_AVAILABLE:
            try:
                data = _load_yaml(routing_path)
                rules = data.get("rules", [])
                for i, rule in enumerate(rules):
                    if not rule.get("category"):
                        issues.append(
                            f"routing_rules.yaml rule[{i}] missing required field 'category'"
                        )
                    if not rule.get("team") and not rule.get("assignment_group"):
                        issues.append(
                            f"routing_rules.yaml rule[{i}] for '{rule.get('category')}' "
                            "has no team or assignment_group"
                        )
            except Exception:
                pass  # already caught above

        return issues


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> dict:
    """Load and parse a YAML file."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}
