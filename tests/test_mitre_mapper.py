"""Unit tests verifying MITRE ATT&CK mapping from threat tags."""

from cti_core.processors.mitre_mapper import MitreMapper


def test_mitre_tag_mapping():
    """Verify standard tags map to expected MITRE tactics and techniques."""
    tags = ["c2", "cobalt-strike", "brute-force", "random-tag"]
    mappings = MitreMapper.map_tags(tags)

    assert len(mappings) >= 2
    tech_ids = [m["technique_id"] for m in mappings]
    assert "T1071" in tech_ids or "T1071.001" in tech_ids
    assert "T1110" in tech_ids

    # URL format validation
    c2_map = next(m for m in mappings if "T1071" in m["technique_id"])
    assert "https://attack.mitre.org/techniques/" in c2_map["url"]


def test_mitre_enrich_indicator():
    """Verify enrich_indicator adds mitre_attack field."""
    indicator = {
        "value": "185.220.101.5",
        "type": "ipv4",
        "tags": ["tor-exit", "ssh-scan"],
    }
    enriched = MitreMapper.enrich_indicator(indicator)
    assert "mitre_attack" in enriched
    assert len(enriched["mitre_attack"]) == 2
    assert any(m["technique_id"] == "T1090.003" for m in enriched["mitre_attack"])
