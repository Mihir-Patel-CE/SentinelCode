from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Literal
from datetime import datetime


SeverityType = Literal["critical", "high", "medium", "low", "info"]
CategoryType = Literal["security", "bug", "quality", "performance", "style", "syntax"]
SourceType = Literal["static", "ai"]
ReviewStatusType = Literal["completed", "completed_with_limitations", "invalid_input", "unsupported_language", "failed"]


class FindingBase(BaseModel):
    rule_id: Optional[str] = None
    title: str = Field(..., max_length=255)
    description: str
    severity: SeverityType
    category: CategoryType
    source: SourceType
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    evidence: Optional[str] = None  # Verifiable code snippet from submitted user code
    confidence: Literal["high", "medium", "low"] = "high"
    suggested_fix: Optional[str] = None
    fix_diff: Optional[str] = None


class FindingCreate(FindingBase):
    pass


class FindingResponse(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    review_id: int


class ReviewCreateRequest(BaseModel):
    title: Optional[str] = Field("Untitled Review", max_length=200)
    language: str = Field("auto", description="Programming language identifier or 'auto' for detection")
    code: str = Field(..., min_length=1, max_length=100_000, description="Source code to analyze")
    enable_ai: bool = Field(True, description="Whether to include advisory AI analysis alongside deterministic static analysis")

    @field_validator("code")
    @classmethod
    def validate_code_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Code snippet cannot be empty or solely whitespace.")
        return v


class ReviewSummary(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    static_count: int
    ai_count: int


class ReviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    title: str
    language: str
    code: str
    quality_score: Optional[int] = None
    security_score: Optional[int] = None
    maintainability_index: Optional[int] = None
    summary: Optional[str] = None
    status: str
    coverage_summary: Optional[str] = None
    created_at: datetime
    findings: List[FindingResponse] = []


class ReviewListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    language: str
    status: str
    quality_score: Optional[int] = None
    security_score: Optional[int] = None
    total_findings: int
    created_at: datetime


class ReviewListResponse(BaseModel):
    items: List[ReviewListItem]
    total: int
    page: int
    size: int
    pages: int


class LanguageCapability(BaseModel):
    id: str
    name: str
    status: Literal["supported", "experimental", "planned"]
    features: List[str]
    limitations: str
