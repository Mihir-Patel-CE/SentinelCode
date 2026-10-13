from pydantic import BaseModel, ConfigDict
from typing import Optional, Literal


class UserSettingsUpdate(BaseModel):
    enable_security_checks: Optional[bool] = None
    enable_quality_checks: Optional[bool] = None
    enable_performance_checks: Optional[bool] = None
    enable_ai_analysis: Optional[bool] = None
    preferred_ai_provider: Optional[Literal["mock", "openai", "gemini", "anthropic", "groq", "ollama"]] = None
    preferred_ai_model: Optional[str] = None
    severity_threshold: Optional[Literal["critical", "high", "medium", "low", "info"]] = None


class UserSettingsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    enable_security_checks: bool
    enable_quality_checks: bool
    enable_performance_checks: bool
    enable_ai_analysis: bool
    preferred_ai_provider: str
    preferred_ai_model: str
    severity_threshold: str
