"""Azure OpenAI provider – supports API key, Entra ID, and MSAL device-flow OAuth."""

import os

from .base import OpenAICompatibleProvider, ProviderError


class AzureOpenAIProvider(OpenAICompatibleProvider):
    """
    Wraps Azure OpenAI using the openai SDK.

    Auth priority:
      1. AZURE_OPENAI_API_KEY  →  plain API key
      2. azure_oauth (MSAL device flow) when passed in
      3. DefaultAzureCredential (az login / Managed Identity / Service Principal)

    Required env vars:
        AZURE_OPENAI_ENDPOINT      https://<resource>.openai.azure.com/
        AZURE_OPENAI_DEPLOYMENT    model deployment name (e.g. gpt-4o)
    Optional:
        AZURE_OPENAI_API_KEY       leave unset to use Entra ID
        AZURE_OPENAI_API_VERSION   defaults to 2024-05-01-preview
    """

    def __init__(self, azure_oauth=None):
        super().__init__()
        self._azure_oauth = azure_oauth

    @property
    def name(self) -> str:
        return "Azure OpenAI"

    def is_available(self) -> bool:
        return bool(
            os.getenv("AZURE_OPENAI_ENDPOINT") and os.getenv("AZURE_OPENAI_DEPLOYMENT")
        )

    def _build_client(self) -> None:
        try:
            from openai import AzureOpenAI

            endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
            deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
            api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-05-01-preview")
            api_key = os.getenv("AZURE_OPENAI_API_KEY")

            if not endpoint or not deployment:
                raise ProviderError(
                    "Azure OpenAI requires AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT"
                )

            self._model = deployment

            if api_key:
                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    api_key=api_key,
                    api_version=api_version,
                )
            elif self._azure_oauth and self._azure_oauth.is_configured():
                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    azure_ad_token_provider=self._azure_oauth.get_access_token,
                    api_version=api_version,
                )
            else:
                from azure.identity import DefaultAzureCredential, get_bearer_token_provider

                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    azure_ad_token_provider=get_bearer_token_provider(
                        DefaultAzureCredential(),
                        "https://cognitiveservices.azure.com/.default",
                    ),
                    api_version=api_version,
                )
        except ImportError as exc:
            raise ProviderError(f"Missing dependency for Azure OpenAI: {exc}") from exc
