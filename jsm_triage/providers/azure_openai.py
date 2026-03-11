"""Azure OpenAI provider – supports both API key and Entra ID (DefaultAzureCredential)."""

import json
import os
from typing import Optional

from .base import AIProvider, TriageResult, ProviderError


class AzureOpenAIProvider(AIProvider):
    """
    Wraps Azure OpenAI using the openai SDK.

    Auth priority:
      1. AZURE_OPENAI_API_KEY  →  plain API key
      2. DefaultAzureCredential (az login / Managed Identity / Service Principal)

    Required env vars:
        AZURE_OPENAI_ENDPOINT      https://<resource>.openai.azure.com/
        AZURE_OPENAI_DEPLOYMENT    your model deployment name (e.g. gpt-4o)
    Optional:
        AZURE_OPENAI_API_KEY       leave unset to use Entra ID
        AZURE_OPENAI_API_VERSION   defaults to 2024-05-01-preview
    """

    def __init__(self):
        self._client: Optional[object] = None
        self._deployment: Optional[str] = None

    @property
    def name(self) -> str:
        return "Azure OpenAI"

    def _build_client(self, azure_oauth=None):
        try:
            from openai import AzureOpenAI

            endpoint = os.getenv("AZURE_OPENAI_ENDPOINT") or os.getenv("ENDPOINT_URL")
            deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT") or os.getenv("DEPLOYMENT_NAME")
            api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-05-01-preview")
            api_key = os.getenv("AZURE_OPENAI_API_KEY")

            if not endpoint or not deployment:
                raise ProviderError(
                    "Azure OpenAI requires AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT"
                )

            self._deployment = deployment

            if api_key:
                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    api_key=api_key,
                    api_version=api_version,
                )
            elif azure_oauth and azure_oauth.is_configured():
                # Use 3LO OAuth token via MSAL
                def _token_provider():
                    return azure_oauth.get_access_token()

                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    azure_ad_token_provider=_token_provider,
                    api_version=api_version,
                )
            else:
                from azure.identity import DefaultAzureCredential, get_bearer_token_provider

                token_provider = get_bearer_token_provider(
                    DefaultAzureCredential(),
                    "https://cognitiveservices.azure.com/.default",
                )
                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    azure_ad_token_provider=token_provider,
                    api_version=api_version,
                )
        except ImportError as exc:
            raise ProviderError(f"Missing dependency for Azure OpenAI: {exc}") from exc

    def is_available(self) -> bool:
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT") or os.getenv("ENDPOINT_URL")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT") or os.getenv("DEPLOYMENT_NAME")
        return bool(endpoint and deployment)

    def triage_ticket(self, ticket_data: dict, system_prompt: str, user_prompt: str) -> TriageResult:
        if not self._client:
            self._build_client()

        try:
            response = self._client.chat.completions.create(
                model=self._deployment,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=1024,
            )
            raw = response.choices[0].message.content
            return _parse_triage_json(raw, self.name)
        except Exception as exc:
            raise ProviderError(f"Azure OpenAI triage failed: {exc}") from exc

    def chat(self, messages: list[dict], **kwargs) -> str:
        if not self._client:
            self._build_client()
        try:
            response = self._client.chat.completions.create(
                model=self._deployment,
                messages=messages,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 2048),
            )
            return response.choices[0].message.content
        except Exception as exc:
            raise ProviderError(f"Azure OpenAI chat failed: {exc}") from exc


def _parse_triage_json(raw: str, provider_name: str) -> TriageResult:
    """Parse the JSON response from the model into a TriageResult."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Model returned invalid JSON: {exc}\nRaw: {raw[:500]}") from exc

    return TriageResult(
        priority=data.get("priority", "Medium"),
        category=data.get("category", "General"),
        subcategory=data.get("subcategory", ""),
        suggested_team=data.get("suggested_team"),
        suggested_assignee=data.get("suggested_assignee"),
        summary=data.get("summary", ""),
        suggested_actions=data.get("suggested_actions", []),
        escalate=data.get("escalate", False),
        escalation_reason=data.get("escalation_reason"),
        estimated_resolution=data.get("estimated_resolution"),
        confidence=float(data.get("confidence", 0.5)),
        provider_used=provider_name,
        raw_response=raw,
    )
