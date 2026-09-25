"""Zeek (Bro) Intelligence Framework exporter generating tab-delimited intel files."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class ZeekIntelExporter:
    """Exports scored indicators into Zeek Intelligence Framework format (Intel::Type)."""

    TYPE_MAPPING = {
        "ipv4": "Intel::ADDR",
        "ipv6": "Intel::ADDR",
        "domain": "Intel::DOMAIN",
        "url": "Intel::URL",
        "sha256": "Intel::FILE_HASH",
        "md5": "Intel::FILE_HASH",
    }

    @classmethod
    def export_intel(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
    ) -> str:
        """Format non-whitelisted indicators above threshold into Zeek intelligence table."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        rows: List[str] = [
            "# =====================================================================",
            "# Zeek Intelligence Framework Feed - SENTINEL CTI Engine",
            f"# Generated: {now_utc}",
            f"# Minimum Score Threshold: {min_score}",
            "# =====================================================================",
            "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.confidence",
        ]

        seen_indicators = set()

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
                tags = item.get("tags") or []
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value.lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])
            else:  # IndicatorModel
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])

            if is_whitelisted or score < min_score:
                continue

            zeek_type = cls.TYPE_MAPPING.get(ioc_type)
            if not zeek_type:
                continue

            if norm_val in seen_indicators:
                continue
            seen_indicators.add(norm_val)

            desc = f"Threat Tags: {','.join(tags[:3])}" if tags else "Active Threat Indicator"
            # Strip tabs or newlines from fields to ensure strict TSV compliance
            clean_val = norm_val.replace("\t", "").replace("\n", "")
            clean_desc = desc.replace("\t", " ").replace("\n", " ")

            rows.append(f"{clean_val}\t{zeek_type}\tSENTINEL_CTI\t{clean_desc}\t{score:.1f}")

        return "\n".join(rows) + "\n"
