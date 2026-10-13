from app.core.config import settings
from app.services.ai.base import BaseAIProvider
from app.services.ai.heuristic_mock import HeuristicMockAIProvider
from app.services.ai.openai_client import OpenAICompatibleProvider
from app.services.ai.gemini_client import GeminiAIProvider
from app.core.logging import logger


def get_ai_provider(provider_override: str = None) -> BaseAIProvider:
    """
    Factory function returning the configured AI provider.
    Falls back gracefully to HeuristicMockAIProvider if API keys are missing or provider is 'mock'.
    """
    provider_name = (provider_override or settings.AI_PROVIDER).lower()

    if provider_name == "openai" and settings.OPENAI_API_KEY:
        return OpenAICompatibleProvider(
            api_key=settings.OPENAI_API_KEY,
            model=settings.AI_MODEL if settings.AI_MODEL.startswith("gpt") else "gpt-4o"
        )
    elif provider_name == "gemini" and settings.GEMINI_API_KEY:
        return GeminiAIProvider(
            api_key=settings.GEMINI_API_KEY,
            model=settings.AI_MODEL if settings.AI_MODEL.startswith("gemini") else "gemini-1.5-flash"
        )
    elif provider_name == "groq" and settings.GROQ_API_KEY:
        return OpenAICompatibleProvider(
            api_key=settings.GROQ_API_KEY,
            model="llama-3.3-70b-versatile",
            base_url="https://api.groq.com/openai/v1"
        )
    elif provider_name == "ollama":
        return OpenAICompatibleProvider(
            api_key="ollama",
            model="codellama",
            base_url=f"{settings.OLLAMA_BASE_URL}/v1"
        )

    # Default fallback: Heuristic mock engine
    return HeuristicMockAIProvider()
