"""Base classes, shared data models, and shared utilities for AI providers."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from ..models import KnowledgeSnippet, TriageResult


class ProviderError(Exception):
    pass


def parse_triage_json(raw: str, provider_name: str) -> TriageResult:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Model returned invalid JSON: {exc}") from exc

    result = TriageResult(
        request_type=data.get("request_type", "unknown"),
        category=data.get("category", "Insufficient Information"),
        subcategory=data.get("subcategory", ""),
        business_impact=data.get("business_impact", "Medium"),
        urgency=data.get("urgency", "Medium"),
        priority=data.get("priority", "Medium"),
        requires_approval=bool(data.get("requires_approval", False)),
        approval_type=data.get("approval_type"),
        required_information_missing=bool(data.get("required_information_missing", False)),
        missing_fields=data.get("missing_fields", []),
        likely_fulfilling_team=data.get("likely_fulfilling_team"),
        likely_assignment_group=data.get("likely_assignment_group"),
        suggested_actions=data.get("suggested_actions", []),
        recommended_next_step=data.get("recommended_next_step", "request_more_info"),
        escalation_required=bool(data.get("escalation_required", False)),
        escalation_reason=data.get("escalation_reason"),
        confidence=float(data.get("confidence", 0.5)),
        rationale=data.get("rationale", ""),
        policy_references=data.get("policy_references", []),
        knowledge_sources_used=data.get("knowledge_sources_used", []),
        facts=data.get("facts", []),
        inferences=data.get("inferences", []),
        provider_used=provider_name,
        raw_response=raw,
    )
    result.validate()
    return result


class AIProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def triage_ticket(self, system_prompt: str, user_prompt: str) -> TriageResult:
        ...

    def chat(self, messages: list[dict], **kwargs) -> str:
        raise NotImplementedError

    def retrieve_knowledge(
        self, query: str, curated_queries: list[str] | None = None, max_snippets: int = 5
    ) -> list[KnowledgeSnippet]:
        return []


class OpenAICompatibleProvider(AIProvider):
    def __init__(self):
        self._client = None
        self._model: str = ""

    @abstractmethod
    def _build_client(self) -> None:
        ...

    def triage_ticket(self, system_prompt: str, user_prompt: str) -> TriageResult:
        if not self._client:
            self._build_client()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1400,
            )
            return parse_triage_json(response.choices[0].message.content, self.name)
        except Exception as exc:
            raise ProviderError(f"{self.name} triage failed: {exc}") from exc

    def chat(self, messages: list[dict], **kwargs) -> str:
        if not self._client:
            self._build_client()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 2048),
            )
            return response.choices[0].message.content
        except Exception as exc:
            raise ProviderError(f"{self.name} chat failed: {exc}") from exc
