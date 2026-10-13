from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class UserSettings(Base):
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    
    # Analysis preferences
    enable_security_checks = Column(Boolean, default=True)
    enable_quality_checks = Column(Boolean, default=True)
    enable_performance_checks = Column(Boolean, default=True)
    enable_ai_analysis = Column(Boolean, default=True)
    
    # Custom AI overrides (encrypted/masked or provider string)
    preferred_ai_provider = Column(String(50), default="mock")
    preferred_ai_model = Column(String(100), default="sentinel-heuristic-v1")
    
    # Thresholds
    severity_threshold = Column(String(20), default="info")

    user = relationship("User", back_populates="settings")
