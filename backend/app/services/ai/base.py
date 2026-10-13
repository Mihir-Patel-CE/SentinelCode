from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple
from app.schemas.review import FindingCreate


class BaseAIProvider(ABC):
    """Abstract interface for AI analysis providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    async def analyze(
        self,
        code: str,
        language: str,
        static_findings: List[FindingCreate]
    ) -> Tuple[List[FindingCreate], str]:
        """
        Analyzes code with an LLM and returns:
        1. A list of AI-generated findings.
        2. A high-level executive summary / review narrative.
        """
        pass
