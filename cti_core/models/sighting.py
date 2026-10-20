"""Sighting record schema and ORM models for granular observation telemetry."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, Column, DateTime, Integer, String

from cti_core.models.indicator import Base


class SightingType(str, Enum):
    FIREWALL_DROP = "firewall_drop"
    DNS_QUERY = "dns_query"
    EDR_ALERT = "edr_alert"
    HONEYPOT_HIT = "honeypot_hit"
    EXTERNAL_FEED = "external_feed"


class SightingModel(Base):
    """SQLAlchemy model for recording individual IoC sightings across sensors."""

    __tablename__ = "ioc_sightings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    indicator_value = Column(String(512), nullable=False, index=True)
    sighting_type = Column(String(32), nullable=False, default=SightingType.EXTERNAL_FEED.value)
    sensor_id = Column(String(128), nullable=False, default="sentinel-hub")
    observed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    count = Column(Integer, default=1, nullable=False)
    context_data = Column(JSON, default=dict)


class SightingCreate(BaseModel):
    indicator_value: str = Field(..., description="The IoC value observed")
    sighting_type: SightingType = Field(default=SightingType.EXTERNAL_FEED)
    sensor_id: str = Field(default="sentinel-hub")
    count: int = Field(default=1, ge=1)
    context_data: Optional[Dict[str, Any]] = Field(default_factory=dict)


class SightingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator_value: str
    sighting_type: SightingType
    sensor_id: str
    observed_at: datetime
    count: int
    context_data: Dict[str, Any]
