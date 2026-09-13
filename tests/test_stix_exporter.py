"""Unit tests verifying STIX 2.1 schema compliance and pattern generation."""

import json
from datetime import datetime, timezone

from cti_core.exporters.stix_exporter import STIXExporter
from cti_core.models.indicator import IndicatorRead, IndicatorType


def test_stix_bundle_structure():
    """Verify STIX 2.1 Bundle serialization and required properties."""
    sample_indicators = [
        IndicatorRead(
            id="test-1",
            value="185.220.101.5",
            normalized_value="185.220.101.5",
            type=IndicatorType.IPV4,
            confidence_score=95.0,
            tags=["tor", "scanner"],
            is_whitelisted=False,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ),
        IndicatorRead(
            id="test-2",
            value="evil-domain.com",
            normalized_value="evil-domain.com",
            type=IndicatorType.DOMAIN,
            confidence_score=85.0,
            tags=["c2"],
            is_whitelisted=False,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ),
    ]

    bundle = STIXExporter.export_indicators(sample_indicators)
    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    assert len(bundle.objects) == 2

    # Indicator 1 checks
    ind1 = bundle.objects[0]
    assert ind1.type == "indicator"
    assert ind1.spec_version == "2.1"
    assert ind1.id.startswith("indicator--")
    assert ind1.pattern == "[ipv4-addr:value = '185.220.101.5']"
    assert ind1.pattern_type == "stix"
    assert ind1.pattern_version == "2.1"
    assert ind1.confidence == 95
    assert "tor" in ind1.labels

    # Indicator 2 checks
    ind2 = bundle.objects[1]
    assert ind2.pattern == "[domain-name:value = 'evil-domain.com']"
    assert ind2.confidence == 85


def test_stix_json_serialization():
    """Verify export_json produces valid JSON matching STIX 2.1 structure."""
    raw_iocs = [
        {
            "value": "ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f",
            "type": "sha256",
            "confidence_score": 90.0,
            "tags": ["ransomware"],
            "sources": [{"source_name": "virustotal", "reference_url": "https://virustotal.com"}],
        }
    ]

    json_str = STIXExporter.export_json(raw_iocs)
    data = json.loads(json_str)

    assert data["type"] == "bundle"
    assert len(data["objects"]) == 1
    obj = data["objects"][0]
    assert obj["pattern"] == "[file:hashes.'SHA-256' = 'ed01ebf83334a19370a4a22454232639ac4e404a5e252429fb21861e45235a9f']"
    assert obj["confidence"] == 90
    assert obj["external_references"][0]["source_name"] == "virustotal"
