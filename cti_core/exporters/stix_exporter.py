"""STIX 2.1 JSON bundle exporter compliant with OASIS standard."""

import json
from typing import Any, Dict, Iterable, List, Optional, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead, IndicatorType
from cti_core.models.stix_schema import (
    STIXBundle,
    STIXExternalReference,
    STIXIndicator,
    format_stix_datetime,
    generate_stix_pattern,
)


class STIXExporter:
    """Exports indicators into STIX 2.1 JSON bundle format."""

    @staticmethod
    def export_indicators(
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        bundle_id: Optional[str] = None,
    ) -> STIXBundle:
        """Transform a collection of indicators into a STIX 2.1 Bundle."""
        stix_objects: List[STIXIndicator] = []

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value")
                ioc_type_str = item.get("type", "ipv4")
                score = int(item.get("confidence_score", 50))
                tags = item.get("tags") or []
                first_seen = item.get("first_seen")
                sources = item.get("sources") or []
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type_str = item.type.value
                score = int(item.confidence_score)
                tags = item.tags
                first_seen = item.first_seen
                sources = [s.model_dump() for s in item.sources]
            else:  # IndicatorModel
                norm_val = str(item.normalized_value)
                ioc_type_str = str(item.type)
                score = int(float(item.confidence_score))
                tags = item.tags or []
                first_seen = item.first_seen
                sources = [{"source_name": s.source_name, "reference_url": s.reference_url} for s in (item.sources or [])]

            if not norm_val:
                continue

            try:
                ioc_type = IndicatorType(ioc_type_str.lower())
            except ValueError:
                continue

            pattern = generate_stix_pattern(ioc_type, str(norm_val))

            # References
            external_refs = []
            for src in sources:
                src_name = src.get("source_name", "cti-engine")
                ref_url = src.get("reference_url")
                if ref_url:
                    external_refs.append(STIXExternalReference(source_name=src_name, url=ref_url))

            stix_ind = STIXIndicator(
                name=f"Threat Indicator: {norm_val}",
                description=f"Automated CTI Engine identified {ioc_type_str} with confidence {score}/100.",
                pattern=pattern,
                confidence=score,
                labels=tags if tags else ["threat-indicator"],
                valid_from=format_stix_datetime(first_seen),
                valid_until=None,
                external_references=external_refs if external_refs else None,
            )
            stix_objects.append(stix_ind)

        if bundle_id:
            return STIXBundle(id=bundle_id, objects=stix_objects)
        return STIXBundle(objects=stix_objects)

    @classmethod
    def export_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        indent: int = 2,
    ) -> str:
        """Export indicators directly into a formatted STIX 2.1 JSON string."""
        bundle = cls.export_indicators(indicators)
        return json.dumps(bundle.model_dump(exclude_none=True), indent=indent)
