"""Audit logging schema and model for SOC governance and compliance."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, Column, DateTime, String

from cti_core.models.indicator import Base


class AuditLogModel(Base):
    """SQLAlchemy model for recording compliance and change events."""

    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    action = Column(String(64), nullable=False, index=True)
    actor = Column(String(128), nullable=False, default="system")
    target_resource = Column(String(256), nullable=True)
    details = Column(JSON, default=dict)


class AuditLogRecord(BaseModel):
    """Pydantic model for audit log records."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: str = Field(..., description="Action name (e.g. export_firewall, add_whitelist)")
    actor: str = Field(default="system", description="User, service account, or token actor")
    target_resource: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
