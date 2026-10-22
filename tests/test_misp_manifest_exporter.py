"""Unit tests for MISP feed manifest exporter."""

from cti_core.exporters.misp_feed_manifest_exporter import MISPFeedManifestExporter


def test_misp_manifest_generation():
    indicators = [{"value": "1.2.3.4"}, {"value": "evil.com"}]
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    manifest = MISPFeedManifestExporter.generate_manifest(uuid, indicators)

    assert uuid in manifest
    assert manifest[uuid]["attribute_count"] == 2
    assert manifest[uuid]["Orgc"]["name"] == "SENTINEL-CTI"


def test_misp_warninglist_export():
    wl = ["8.8.8.8", "1.1.1.1", "google.com"]
    warninglist = MISPFeedManifestExporter.export_warninglist(wl)
    assert warninglist["name"] == "SENTINEL Whitelist Filter"
    assert len(warninglist["list"]) == 3
    assert "8.8.8.8" in warninglist["list"]
