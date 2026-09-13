"""SQLAlchemy 2.0 and Pydantic v2 data models for Indicators of Compromise (IoCs)."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


class ConfidenceTier(str, Enum):
    LOW = "LOW"          # 0 - 39
    MEDIUM = "MEDIUM"    # 40 - 69
    HIGH = "HIGH"        # 70 - 84
    CRITICAL = "CRITICAL"  # 85 - 100


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Pydantic Schemas (v2)
# ---------------------------------------------------------------------------

class ScoreBreakdown(BaseModel):
    source_weight: float = Field(default=0.0, description="Reliability weight of reporting sources")
    cross_source_factor: float = Field(default=1.0, description="Cross-feed confirmation multiplier")
    decay_factor: float = Field(default=1.0, description="Calculated exponential time decay factor")
    days_old: float = Field(default=0.0, description="Days elapsed since indicator last seen")
    enrichment_boost: float = Field(default=0.0, description="Additive confidence boost from enrichment APIs")
    raw_calculated_score: float = Field(default=0.0, description="Score before whitelist override and clamping")
    final_score: float = Field(default=0.0, description="Composite confidence score [0, 100]")
    tier: ConfidenceTier = Field(default=ConfidenceTier.LOW, description="Confidence categorization tier")
    is_whitelisted: bool = Field(default=False, description="True if indicator matched benign whitelist")
    whitelist_reason: Optional[str] = Field(default=None, description="Reason indicator was whitelisted")


class SourceMetadata(BaseModel):
    source_name: str
    confidence: Optional[float] = None
    reported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reference_url: Optional[str] = None
    raw_tags: List[str] = Field(default_factory=list)


class IndicatorBase(BaseModel):
    value: str
    normalized_value: str
    type: IndicatorType
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM)
    tags: List[str] = Field(default_factory=list)
    is_whitelisted: bool = False
    whitelist_reason: Optional[str] = None


class IndicatorCreate(BaseModel):
    value: str
    type: Optional[IndicatorType] = None
    source_name: str = "manual_entry"
    severity: SeverityLevel = SeverityLevel.MEDIUM
    tags: List[str] = Field(default_factory=list)
    reference_url: Optional[str] = None
    reported_at: Optional[datetime] = None


class IndicatorRead(IndicatorBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    confidence_tier: ConfidenceTier = ConfidenceTier.LOW
    sources: List[SourceMetadata] = Field(default_factory=list)
    enrichment: Dict[str, Any] = Field(default_factory=dict)
    score_breakdown: Optional[ScoreBreakdown] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IndicatorFilter(BaseModel):
    type: Optional[IndicatorType] = None
    min_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    max_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    tag: Optional[str] = None
    search: Optional[str] = None
    is_whitelisted: Optional[bool] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# SQLAlchemy 2.0 ORM Models
# ---------------------------------------------------------------------------

class IndicatorModel(Base):
    __tablename__ = "indicators"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    value = Column(String(1024), nullable=False, index=True)
    normalized_value = Column(String(1024), nullable=False, index=True)
    type = Column(String(32), nullable=False, index=True)
    confidence_score = Column(Float, default=0.0, nullable=False, index=True)
    severity = Column(String(32), default=SeverityLevel.MEDIUM.value, nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    is_whitelisted = Column(Boolean, default=False, nullable=False, index=True)
    whitelist_reason = Column(String(255), nullable=True)

    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    enrichment_data = Column(JSON, default=dict, nullable=False)
    score_breakdown = Column(JSON, default=dict, nullable=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    sources = relationship("IndicatorSourceModel", back_populates="indicator", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_indicators_type_normval", "type", "normalized_value", unique=True),
        Index("ix_indicators_score_whitelisted", "confidence_score", "is_whitelisted"),
    )


class IndicatorSourceModel(Base):
    __tablename__ = "indicator_sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    source_name = Column(String(128), nullable=False, index=True)
    confidence = Column(Float, nullable=True)
    reported_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    reference_url = Column(String(1024), nullable=True)
    raw_tags = Column(JSON, default=list, nullable=False)

    indicator = relationship("IndicatorModel", back_populates="sources")
