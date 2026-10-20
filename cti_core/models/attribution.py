"""Threat Actor and Campaign attribution tracking schemas."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class MotivationType(str, Enum):
    FINANCIAL = "financial"
    ESPIONAGE = "espionage"
    SABOTAGE = "sabotage"
    HACKTIVISM = "hacktivism"
    UNKNOWN = "unknown"


class ThreatActor(BaseModel):
    """Schema representing an Advanced Persistent Threat (APT) group or criminal syndicate."""

    model_config = ConfigDict(from_attributes=True)

    name: str = Field(..., description="Canonical threat actor name (e.g., APT29, Lazarus Group)")
    aliases: List[str] = Field(default_factory=list, description="Known operational aliases (e.g., Cozy Bear, NOBELIUM)")
    origin_country: Optional[str] = Field(None, description="Suspected country of origin (ISO-3166 alpha-2 or name)")
    motivation: MotivationType = Field(default=MotivationType.UNKNOWN)
    sophistication: str = Field(default="advanced", description="Capabilities tier: novice, intermediate, advanced, nation-state")
    first_observed: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: Optional[str] = None


class Campaign(BaseModel):
    """Schema representing an orchestrated cyber campaign spanning multiple IoCs."""

    model_config = ConfigDict(from_attributes=True)

    name: str = Field(..., description="Operational campaign identifier (e.g., SolarWinds Sunburst, DarkGate 2024)")
    threat_actor_name: Optional[str] = Field(None, description="Attributed threat actor")
    objective: Optional[str] = Field(None, description="Tactical objective")
    target_sectors: List[str] = Field(default_factory=list, description="Targeted industries (e.g. defense, finance)")
    target_geographies: List[str] = Field(default_factory=list, description="Targeted countries")
    associated_indicators: List[str] = Field(default_factory=list, description="List of IoC values involved in campaign")
    active: bool = True
