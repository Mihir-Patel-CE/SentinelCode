from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum
from app.core.database import Base


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, enum.Enum):
    SECURITY = "security"
    BUG = "bug"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    STYLE = "style"
    SYNTAX = "syntax"


class FindingSource(str, enum.Enum):
    STATIC = "static"
    AI = "ai"


class ReviewStatus(str, enum.Enum):
    COMPLETED = "completed"
    COMPLETED_WITH_LIMITATIONS = "completed_with_limitations"
    INVALID_INPUT = "invalid_input"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    FAILED = "failed"


class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    title = Column(String(200), default="Untitled Review")
    language = Column(String(50), nullable=False, default="python")
    code = Column(Text, nullable=False)
    
    # Calculated scores (nullable if analysis failed, unsupported, or invalid)
    quality_score = Column(Integer, nullable=True)
    security_score = Column(Integer, nullable=True)
    maintainability_index = Column(Integer, nullable=True)
    summary = Column(Text, nullable=True)
    status = Column(String(50), default="completed")
    coverage_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    user = relationship("User", back_populates="reviews")
    findings = relationship("Finding", back_populates="review", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    review_id = Column(Integer, ForeignKey("reviews.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(100), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="medium")
    category = Column(String(50), nullable=False, default="bug")
    source = Column(String(20), nullable=False, default="static")  # "static" or "ai"
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    column_start = Column(Integer, nullable=True)
    column_end = Column(Integer, nullable=True)
    evidence = Column(Text, nullable=True)  # Verifiable snippet from user's code
    confidence = Column(String(20), default="high")  # "high", "medium", "low"
    suggested_fix = Column(Text, nullable=True)
    fix_diff = Column(Text, nullable=True)

    # Relationships
    review = relationship("Review", back_populates="findings")
