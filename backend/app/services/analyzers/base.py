from abc import ABC, abstractmethod
from typing import List, Optional
from pydantic import BaseModel
from app.schemas.review import FindingCreate


class AnalysisResult(BaseModel):
    status: str = "completed"  # "completed", "completed_with_limitations", "failed", "unsupported_language"
    language: str
    findings: List[FindingCreate] = []
    coverage_summary: str = ""
    limitations: str = ""
    error_message: Optional[str] = None


class BaseAnalyzer(ABC):
    """Abstract base class for all language-specific static analyzers."""
    
    @property
    @abstractmethod
    def language(self) -> str:
        """Returns the supported language identifier."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable display name of the analyzer."""
        pass

    @property
    def features(self) -> List[str]:
        """List of static analysis layers and capabilities provided."""
        return []

    @property
    def limitations(self) -> str:
        """Clear notice of known analyzer limitations."""
        return "Single-file static heuristics. Cross-file references and external runtime behavior require broader context."

    @abstractmethod
    def analyze(self, code: str) -> AnalysisResult:
        """Performs deterministic static analysis on code without executing it."""
        pass
