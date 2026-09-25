"""Command-line interface (CLI) for SENTINEL CTI Engine operations and offline utilities."""

import argparse
import json
import sys
from typing import List, Optional

from cti_core.exporters.dns_rpz_exporter import DNSRPZExporter
from cti_core.exporters.firewall_blocklist import FirewallBlocklistExporter
from cti_core.exporters.rules_exporter import RulesExporter
from cti_core.exporters.stix_exporter import STIXExporter
from cti_core.exporters.zeek_exporter import ZeekIntelExporter
from cti_core.mock_data import get_synthetic_indicators
from cti_core.processors.cidr_filter import CIDRFilter
from cti_core.processors.normalizer import defang, identify_indicator_type, refang
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
        choices=["firewall", "stix", "rpz", "suricata", "snort", "zeek"],
        default="firewall",
        help="Export format target",
    )
    export_p.add_argument("--min-score", type=float, default=70.0, help="Minimum score threshold")

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
        fmt = parsed.format
        min_s = parsed.min_score
        items = get_synthetic_indicators()

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
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
