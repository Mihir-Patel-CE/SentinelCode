from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = BACKEND_DIR / "sentinelcode.db"


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    PROJECT_NAME: str = "SentinelCode AI Code Review"
    API_V1_STR: str = "/api/v1"

    # Security
    SECRET_KEY: str = "sentinelcode-dev-secret-key-32-chars-long-min-for-security-check"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    ALGORITHM: str = "HS256"

    # Database
    DATABASE_URL: str = f"sqlite:///{DEFAULT_DB_PATH}"

    # CORS
    ALLOWED_ORIGINS: str = (
        "https://sentinel-code.vercel.app,"
        "https://sentinelcode.onrender.com,"
        "https://sentinelcode-1.onrender.com,"
        "http://localhost:5173,"
        "http://localhost:3000,"
        "http://127.0.0.1:5173,"
        "http://127.0.0.1:3000"
    )

    # AI Configuration
    AI_PROVIDER: str = "mock"  # mock, openai, gemini, anthropic, groq, ollama
    AI_MODEL: str = "sentinel-heuristic-v1"
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # Analysis Guardrails & Limits
    MAX_CODE_LENGTH_BYTES: int = 100_000  # 100 KB limit for code analysis requests
    ANALYSIS_TIMEOUT_SECONDS: int = 30
    RATE_LIMIT_PER_MINUTE: int = 60

    @property
    def cors_origins(self) -> List[str]:
        default_origins = [
            "https://sentinel-code.vercel.app",
            "https://sentinelcode.onrender.com",
            "https://sentinelcode-1.onrender.com",
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
        ]
        if not self.ALLOWED_ORIGINS:
            return default_origins
        configured = [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]
        return list(dict.fromkeys(configured + default_origins))

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
