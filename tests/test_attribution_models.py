"""Unit tests for threat actor, campaign, sighting, and audit models."""

from cti_core.models.attribution import Campaign, MotivationType, ThreatActor
from cti_core.models.audit import AuditLogRecord
from cti_core.models.sighting import SightingCreate, SightingType


def test_threat_actor_model():
    actor = ThreatActor(
        name="APT29",
        aliases=["Cozy Bear", "NOBELIUM", "The Dukes"],
        origin_country="RU",
        motivation=MotivationType.ESPIONAGE,
        sophistication="nation-state",
        description="Russian state-sponsored cyber espionage group",
    )
    assert actor.name == "APT29"
    assert "Cozy Bear" in actor.aliases
    assert actor.motivation == MotivationType.ESPIONAGE
    assert actor.sophistication == "nation-state"


def test_campaign_model():
    camp = Campaign(
        name="Sunburst SolarWinds",
        threat_actor_name="APT29",
        objective="Supply chain compromise and lateral network access",
        target_sectors=["government", "technology", "defense"],
        target_geographies=["US", "EU"],
        associated_indicators=["198.51.100.22", "avsvmcloud.com"],
    )
    assert camp.name == "Sunburst SolarWinds"
    assert "avsvmcloud.com" in camp.associated_indicators
    assert camp.active is True


def test_sighting_model():
    sighting = SightingCreate(
        indicator_value="198.51.100.1",
        sighting_type=SightingType.FIREWALL_DROP,
        sensor_id="palo-alto-core-01",
        count=42,
        context_data={"dest_port": 443, "action": "reset-server"},
    )
    assert sighting.indicator_value == "198.51.100.1"
    assert sighting.sighting_type == SightingType.FIREWALL_DROP
    assert sighting.count == 42


def test_audit_log_record():
    record = AuditLogRecord(
        action="export_feed",
        actor="soc_analyst_01",
        target_resource="/api/v1/export/firewall.txt",
        details={"ip_count": 150, "format": "plaintext"},
    )
    assert record.action == "export_feed"
    assert record.actor == "soc_analyst_01"
    assert record.details["ip_count"] == 150
