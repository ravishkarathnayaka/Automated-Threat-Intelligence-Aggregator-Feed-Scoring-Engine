"""Multi-tenant risk tolerance profiles for configurable SOC scoring policies."""

from dataclasses import dataclass
from typing import Dict


@dataclass
class TenantProfile:
    name: str
    min_enforcement_score: float
    required_consensus: int
    decay_lambda: float
    quarantine_unconfirmed: bool


class TenantProfileManager:
    """Manages risk posture profiles for multi-tenant and MSSP deployments."""

    PROFILES: Dict[str, TenantProfile] = {
        "zero_trust": TenantProfile(
            name="zero_trust",
            min_enforcement_score=85.0,
            required_consensus=3,
            decay_lambda=0.90,
            quarantine_unconfirmed=True,
        ),
        "enterprise_standard": TenantProfile(
            name="enterprise_standard",
            min_enforcement_score=70.0,
            required_consensus=2,
            decay_lambda=0.95,
            quarantine_unconfirmed=True,
        ),
        "threat_hunting": TenantProfile(
            name="threat_hunting",
            min_enforcement_score=40.0,
            required_consensus=1,
            decay_lambda=0.98,
            quarantine_unconfirmed=False,
        ),
    }

    @classmethod
    def get_profile(cls, name: str = "enterprise_standard") -> TenantProfile:
        """Fetch tenant profile with fallback to enterprise_standard."""
        return cls.PROFILES.get(name.lower(), cls.PROFILES["enterprise_standard"])
