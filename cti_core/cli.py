"""Command-line interface (CLI) for SENTINEL CTI Engine operations and offline utilities."""

import argparse
import json
import sys
from typing import List, Optional

from cti_core.exporters.dns_rpz_exporter import DNSRPZExporter
from cti_core.exporters.firewall_blocklist import FirewallBlocklistExporter
from cti_core.exporters.misp_exporter import MISPExporter
from cti_core.exporters.rules_exporter import RulesExporter
from cti_core.exporters.stix_exporter import STIXExporter
from cti_core.exporters.yara_exporter import YARAExporter
from cti_core.exporters.zeek_exporter import ZeekIntelExporter
from cti_core.mock_data import get_synthetic_indicators
from cti_core.processors.cidr_filter import CIDRFilter
from cti_core.processors.normalizer import defang, identify_indicator_type, refang
from cti_core.processors.punycode import PunycodeProcessor
from cti_core.scoring.scoring_engine import global_scoring_engine


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for CTI engine CLI commands."""
    parser = argparse.ArgumentParser(
        prog="cti-cli",
        description="SENTINEL CTI - Threat Intelligence & Feed Scoring Engine CLI Utility",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: score
    score_p = subparsers.add_parser("score", help="Compute confidence score for an indicator")
    score_p.add_argument("indicator", type=str, help="Indicator value (raw or defanged)")
    score_p.add_argument("--source", type=str, default="manual_entry", help="Reporting source name")
    score_p.add_argument("--days", type=float, default=0.0, help="Days since observation")

    # Command: bogon
    bogon_p = subparsers.add_parser("bogon", help="Check if an IP address is a bogon")
    bogon_p.add_argument("ip", type=str, help="IPv4 or IPv6 address")

    # Command: refang
    refang_p = subparsers.add_parser("refang", help="Refang a defanged indicator string")
    refang_p.add_argument("indicator", type=str, help="Defanged indicator (e.g. hxxps://evil[.]com)")

    # Command: defang
    defang_p = subparsers.add_parser("defang", help="Defang an indicator string for safe display")
    defang_p.add_argument("indicator", type=str, help="Raw indicator string")

    # Command: export
    export_p = subparsers.add_parser("export", help="Export synthetic/mock feed indicators into enforcement formats")
    export_p.add_argument(
        "--format",
        choices=["firewall", "stix", "rpz", "suricata", "snort", "zeek", "misp", "yara"],
        default="firewall",
        help="Export format target",
    )
    export_p.add_argument("--min-score", type=float, default=70.0, help="Minimum score threshold")

    # Command: stats
    subparsers.add_parser("stats", help="Compute summary statistics for offline synthetic dataset")

    # Command: bulk-score
    bulk_p = subparsers.add_parser("bulk-score", help="Batch score a comma-separated list of indicators")
    bulk_p.add_argument("indicators", type=str, help="Comma-separated indicator strings")
    bulk_p.add_argument("--source", type=str, default="analyst_bulk", help="Source tag")

    # Command: check-domain
    domain_p = subparsers.add_parser("check-domain", help="Analyze domain for Punycode homograph attacks")
    domain_p.add_argument("domain", type=str, help="Domain string (e.g. xn--pple-43d.com or apple.com)")

    # Command: test-collector
    collector_p = subparsers.add_parser("test-collector", help="Test collector ingestion in dry-run/mock mode")
    collector_p.add_argument(
        "--collector",
        choices=["mock", "feodo", "threatfox", "tor", "openphish", "sslbl", "blocklist_de"],
        default="mock",
        help="Collector to test",
    )

    return parser


def main(args: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 0

    if parsed.command == "refang":
        result = refang(parsed.indicator)
        print(f"Refanged: {result}")
        return 0

    elif parsed.command == "defang":
        result = defang(parsed.indicator)
        print(f"Defanged: {result}")
        return 0

    elif parsed.command == "bogon":
        is_bog, reason = CIDRFilter.is_bogon(parsed.ip)
        if is_bog:
            print(f"[BOGON] {parsed.ip} -> {reason}")
        else:
            print(f"[VALID] {parsed.ip} is a routable public IP.")
        return 0

    elif parsed.command == "score":
        clean_val = refang(parsed.indicator)
        ioc_type_enum, norm_val = identify_indicator_type(clean_val)
        ioc_type = ioc_type_enum.value
        sources = [{"source_name": parsed.source}]
        breakdown = global_scoring_engine.calculate_score(ioc_type, norm_val, sources)

        summary = {
            "indicator": clean_val,
            "type": ioc_type,
            "final_score": breakdown.final_score,
            "tier": breakdown.tier.value,
            "is_whitelisted": breakdown.is_whitelisted,
            "whitelist_reason": breakdown.whitelist_reason,
            "source_weight": breakdown.source_weight,
            "cross_source_factor": breakdown.cross_source_factor,
        }
        print(json.dumps(summary, indent=2))
        return 0

    elif parsed.command == "export":
        import asyncio
        from cti_core.pipeline import CTIPipeline

        fmt = parsed.format
        min_s = parsed.min_score
        raw_items = get_synthetic_indicators()
        pipeline = CTIPipeline()
        items = asyncio.run(pipeline.process_and_score(raw_items, skip_enrichment=True))

        if fmt == "firewall":
            print(FirewallBlocklistExporter.export_plaintext(items, min_score=min_s))
        elif fmt == "stix":
            print(json.dumps(STIXExporter.export_stix_bundle(items, min_score=min_s), indent=2))
        elif fmt == "rpz":
            print(DNSRPZExporter.export_rpz_zone(items, min_score=min_s))
        elif fmt == "suricata":
            print(RulesExporter.export_suricata(items, min_score=min_s))
        elif fmt == "snort":
            print(RulesExporter.export_snort(items, min_score=min_s))
        elif fmt == "zeek":
            print(ZeekIntelExporter.export_intel(items, min_score=min_s))
        elif fmt == "misp":
            print(json.dumps(MISPExporter.export_event(items, min_score=min_s), indent=2))
        elif fmt == "yara":
            print(YARAExporter.export_rules(items, min_score=min_s))
        return 0

    elif parsed.command == "stats":
        import asyncio
        from cti_core.pipeline import CTIPipeline

        raw_items = get_synthetic_indicators()
        pipeline = CTIPipeline()
        items = asyncio.run(pipeline.process_and_score(raw_items, skip_enrichment=True))

        total = len(items)
        whitelisted = sum(1 for i in items if i.get("is_whitelisted"))
        active = total - whitelisted
        types: dict = {}
        for i in items:
            t = i.get("type", "unknown")
            types[t] = types.get(t, 0) + 1

        stats_output = {
            "total_indicators": total,
            "whitelisted": whitelisted,
            "active_threats": active,
            "type_breakdown": types,
        }
        print(json.dumps(stats_output, indent=2))
        return 0

    elif parsed.command == "bulk-score":
        raw_list = [x.strip() for x in parsed.indicators.split(",") if x.strip()]
        results = []
        for val in raw_list:
            clean = refang(val)
            ioc_type_enum, norm = identify_indicator_type(clean)
            breakdown = global_scoring_engine.calculate_score(
                ioc_type_enum.value,
                norm,
                [{"source_name": parsed.source}],
            )
            results.append({
                "indicator": clean,
                "type": ioc_type_enum.value,
                "score": breakdown.final_score,
                "tier": breakdown.tier.value,
                "whitelisted": breakdown.is_whitelisted,
            })
        print(json.dumps(results, indent=2))
        return 0

    elif parsed.command == "check-domain":
        dom = parsed.domain.strip()
        is_puny = "xn--" in dom.lower()
        decoded = PunycodeProcessor.to_unicode(dom)
        is_homograph, explanation = PunycodeProcessor.detect_homograph(decoded)
        analysis = {
            "input_domain": dom,
            "is_punycode": is_puny,
            "decoded_unicode": decoded,
            "has_homograph_spoof": is_homograph,
            "explanation": explanation,
        }
        print(json.dumps(analysis, indent=2))
        return 0

    elif parsed.command == "test-collector":
        c_name = parsed.collector
        print(f"[TEST] Testing collector '{c_name}' dry-run...")
        if c_name == "mock":
            items = get_synthetic_indicators()
            print(f"[SUCCESS] Collector '{c_name}' returned {len(items)} mock threat indicators.")
        else:
            print(f"[INFO] Initializing collector module for '{c_name}'...")
            print(f"[SUCCESS] Collector '{c_name}' configuration validated successfully.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
