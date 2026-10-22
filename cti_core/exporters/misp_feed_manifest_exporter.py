"""MISP Feed manifest and warninglist format generator."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class MISPFeedManifestExporter:
    """Generates standard MISP Feed manifest.json and warninglist structures."""

    @classmethod
    def generate_manifest(
        cls,
        event_uuid: str,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        title: str = "SENTINEL-CTI Active Enforcement Manifest",
    ) -> Dict[str, Any]:
        """Generate MISP feed manifest.json."""
        count = sum(1 for _ in indicators)
        return {
            event_uuid: {
                "Title": title,
                "analysis": "2",
                "info": title,
                "threat_level_id": "1",
                "date": "2026-10-22",
                "published": True,
                "Orgc": {"name": "SENTINEL-CTI", "uuid": "4c9d5111-9a4f-4022-8321-c423871101ab"},
                "attribute_count": count,
            }
        }

    @classmethod
    def export_warninglist(
        cls,
        whitelisted_values: List[str],
        name: str = "SENTINEL Whitelist Filter",
    ) -> Dict[str, Any]:
        """Generates MISP-compatible warninglist JSON."""
        return {
            "name": name,
            "version": 1,
            "description": "Suppressed benign indicators from SENTINEL CTI Engine",
            "type": "string",
            "matching_attributes": ["ip-dst", "domain", "hostname"],
            "list": whitelisted_values,
        }
