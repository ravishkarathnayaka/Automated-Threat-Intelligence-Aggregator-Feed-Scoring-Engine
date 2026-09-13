"""STIX 2.1 serialization and validation models compliant with OASIS STIX 2.1 specification."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from cti_core.models.indicator import IndicatorType


def format_stix_datetime(dt: Optional[datetime] = None) -> str:
    """Format datetime as RFC 3339 with 'Z' timezone representation required by STIX 2.1."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def generate_stix_pattern(ioc_type: IndicatorType, value: str) -> str:
    """Generate standardized STIX 2.1 comparison pattern for an indicator."""
    sanitized = value.replace("'", "\\'")
    if ioc_type == IndicatorType.IPV4:
        return f"[ipv4-addr:value = '{sanitized}']"
    elif ioc_type == IndicatorType.IPV6:
        return f"[ipv6-addr:value = '{sanitized}']"
    elif ioc_type == IndicatorType.DOMAIN:
        return f"[domain-name:value = '{sanitized}']"
    elif ioc_type == IndicatorType.URL:
        return f"[url:value = '{sanitized}']"
    elif ioc_type == IndicatorType.MD5:
        return f"[file:hashes.'MD5' = '{sanitized}']"
    elif ioc_type == IndicatorType.SHA1:
        return f"[file:hashes.'SHA-1' = '{sanitized}']"
    elif ioc_type == IndicatorType.SHA256:
        return f"[file:hashes.'SHA-256' = '{sanitized}']"
    elif ioc_type == IndicatorType.CVE:
        return f"[vulnerability:name = '{sanitized}']"
    return f"[custom-object:value = '{sanitized}']"


class STIXExternalReference(BaseModel):
    source_name: str
    description: Optional[str] = None
    url: Optional[str] = None
    external_id: Optional[str] = None


class STIXIndicator(BaseModel):
    type: Literal["indicator"] = "indicator"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(default_factory=lambda: f"indicator--{uuid4()}")
    created: str = Field(default_factory=format_stix_datetime)
    modified: str = Field(default_factory=format_stix_datetime)
    name: str
    description: Optional[str] = None
    indicator_types: List[str] = Field(default_factory=lambda: ["malicious-activity"])
    pattern: str
    pattern_type: Literal["stix"] = "stix"
    pattern_version: Literal["2.1"] = "2.1"
    valid_from: str = Field(default_factory=format_stix_datetime)
    valid_until: Optional[str] = None
    confidence: int = Field(default=50, ge=0, le=100)
    labels: List[str] = Field(default_factory=list)
    external_references: Optional[List[STIXExternalReference]] = None
    custom_properties: Optional[Dict[str, Any]] = None


class STIXBundle(BaseModel):
    type: Literal["bundle"] = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{uuid4()}")
    objects: List[STIXIndicator] = Field(default_factory=list)
