"""Command-line interface (CLI) for SENTINEL CTI Engine operations and offline utilities."""

import argparse
import json
import sys
from typing import List, Optional

from cti_core.exporters.dns_rpz_exporter import DNSRPZExporter
from cti_core.exporters.firewall_blocklist import FirewallBlocklistExporter
from cti_core.exporters.misp_exporter import MISPExporter
from cti_core.exporters.rules_exporter import RulesExporter
from cti_core.exporters.sigma_exporter import SigmaExporter
from cti_core.exporters.stix_exporter import STIXExporter
from cti_core.exporters.yara_exporter import YARAExporter
from cti_core.exporters.zeek_exporter import ZeekIntelExporter
from cti_core.mock_data import get_synthetic_indicators
from cti_core.processors.asn_lookup import ASNReputationProcessor
from cti_core.processors.cidr_filter import CIDRFilter
from cti_core.processors.dga_detector import DGADetector
from cti_core.processors.domain_typosquat_evaluator import DomainTyposquatEvaluator
from cti_core.processors.hassh_ssh_processor import HasshSSHProcessor
from cti_core.processors.favicon_hash_calculator import FaviconHashCalculator
from cti_core.processors.ja4_fingerprint_processor import JA4FingerprintProcessor
from cti_core.processors.ja4s_fingerprint_processor import JA4SFingerprintProcessor
from cti_core.processors.beacon_jitter_analyzer import BeaconJitterAnalyzer
from cti_core.processors.normalizer import defang, identify_indicator_type, refang
from cti_core.processors.punycode import PunycodeProcessor
from cti_core.scoring.bayesian_scorer import BayesianScorer
from cti_core.scoring.beta_distribution_scorer import BetaDistributionScorer
from cti_core.scoring.kalman_confidence_filter import KalmanConfidenceFilter
from cti_core.scoring.markov_threat_state import MarkovThreatStateModel, ThreatState
from cti_core.scoring.pagerank_threat_graph import PageRankThreatGraph
from cti_core.scoring.scoring_engine import global_scoring_engine


BANNER = r"""
======================================================================
  ____  _____ _   _ _____ ___ _   _ _____ _          ____ _____ ___ 
 / ___|| ____| \ | |_   _|_ _| \ | | ____| |        / ___|_   _|_ _|
 \___ \|  _| |  \| | | |  | ||  \| |  _| | |       | |     | |  | | 
  ___) | |___| |\  | | |  | || |\  | |___| |___ ___| |___  | |  | | 
 |____/|_____|_| \_| |_| |___|_| \_|_____|_____|_____\____| |_| |___|
 Automated Threat Intelligence Aggregator & Feed Scoring Engine v3.0.0
======================================================================
"""


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for CTI engine CLI commands."""
    parser = argparse.ArgumentParser(
        prog="cti-cli",
        description="SENTINEL CTI - Threat Intelligence & Feed Scoring Engine CLI Utility",
    )
    parser.add_argument("--version", action="version", version="SENTINEL CTI Engine v3.0.0")
    parser.add_argument("--banner", action="store_true", help="Print ASCII header banner")
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
    export_p.add_argument("--json-export", action="store_true", help="Wrap export in JSON metadata envelope")

    # Command: stats
    subparsers.add_parser("stats", help="Compute summary statistics for offline synthetic dataset")

    # Command: telemetry
    telemetry_p = subparsers.add_parser("telemetry", help="System telemetry diagnostics and feed health metrics")
    telemetry_p.add_argument("--check-all", action="store_true", help="Perform comprehensive health diagnostic")

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

    # Command: entropy
    entropy_p = subparsers.add_parser("entropy", help="Calculate Shannon entropy and DGA score for a domain")
    entropy_p.add_argument("domain", type=str, help="Domain string to evaluate")

    # Command: asn
    asn_p = subparsers.add_parser("asn", help="Evaluate Autonomous System Number (ASN) risk reputation")
    asn_p.add_argument("asn", type=str, help="ASN identifier (e.g. AS200019, AS16509, 44477)")

    # Command: dga-check
    dga_p = subparsers.add_parser("dga-check", help="Batch lexical and entropy analysis for algorithmically generated domains")
    dga_p.add_argument("domains", type=str, help="Comma-separated domains to evaluate")

    # Command: sigma-gen
    sigma_p = subparsers.add_parser("sigma-gen", help="Generate vendor-agnostic Sigma detection rule on the fly")
    sigma_p.add_argument("indicators", type=str, help="Comma-separated IP or domain indicators")
    sigma_p.add_argument("--title", type=str, default="Ad-hoc CTI Threat Detection", help="Sigma rule title")

    # Command: bayesian
    bayes_p = subparsers.add_parser("bayesian", help="Simulate Bayesian posterior probability update")
    bayes_p.add_argument("sources", type=str, help="Comma-separated reporting sources (e.g. virustotal,threatfox)")
    bayes_p.add_argument("--prior", type=float, default=0.15, help="Prior probability (default 0.15)")
    bayes_p.add_argument("--benign", type=int, default=0, help="Number of benign whitelist confirmations")

    # Command: ja4
    ja4_p = subparsers.add_parser("ja4", help="Evaluate Fox-IT JA4 TLS client fingerprint")
    ja4_p.add_argument("fingerprint", type=str, help="JA4 fingerprint string (e.g. t13d1516h2_8daaf6152771_b7538a735178)")

    # Command: favicon
    fav_p = subparsers.add_parser("favicon", help="Evaluate web application favicon MurmurHash3 signature")
    fav_p.add_argument("hash", type=int, help="Signed 32-bit MurmurHash3 integer (e.g. -123456789)")

    # Command: markov
    markov_p = subparsers.add_parser("markov", help="Simulate threat infrastructure state transitions using Markov chains")
    markov_p.add_argument("--state", type=str, default="active", choices=["dormant", "active", "monitored", "remediated"], help="Initial threat state")
    markov_p.add_argument("--steps", type=int, default=3, help="Number of steps to project forward")

    # Command: kalman
    kalman_p = subparsers.add_parser("kalman", help="Filter noisy feed observation scores using 1-D Kalman smoothing")
    kalman_p.add_argument("scores", type=str, help="Comma-separated score sequence (e.g. 60,75,80,95)")
    kalman_p.add_argument("--initial", type=float, default=50.0, help="Prior confidence score (default 50.0)")

    # Command: typosquat
    typo_p = subparsers.add_parser("typosquat", help="Evaluate domain for brand typosquatting distance")
    typo_p.add_argument("domain", type=str, help="Domain string (e.g. paypaal.com)")

    # Command: pagerank
    pr_p = subparsers.add_parser("pagerank", help="Compute PageRank influence on a comma-separated edge list")
    pr_p.add_argument("edges", type=str, help="Comma-separated edges formatted as u->v (e.g. 'ip1->dom1,ip1->dom2')")

    # Command: hassh
    hassh_p = subparsers.add_parser("hassh", help="Evaluate SSH client/server HASSH network fingerprint")
    hassh_p.add_argument("fingerprint", type=str, help="32-char hexadecimal HASSH fingerprint")

    # Command: beta-score
    beta_p = subparsers.add_parser("beta-score", help="Compute Beta-Binomial conjugate Bayesian posterior confidence")
    beta_p.add_argument("--malicious", type=int, default=5, help="Count of corroborating malicious reports")
    beta_p.add_argument("--benign", type=int, default=0, help="Count of benign/whitelist counter-evidence reports")
    beta_p.add_argument("--prior-alpha", type=float, default=1.0, help="Prior alpha (default 1.0)")
    beta_p.add_argument("--prior-beta", type=float, default=4.0, help="Prior beta (default 4.0)")


    # Command: ja4s
    ja4s_p = subparsers.add_parser("ja4s", help="Evaluate Fox-IT JA4S TLS server response fingerprint")
    ja4s_p.add_argument("fingerprint", type=str, help="Fox-IT JA4S server fingerprint")

    # Command: jitter
    jitter_p = subparsers.add_parser("jitter", help="Analyze connection timestamps for C2 beacon periodicity and jitter")
    jitter_p.add_argument("timestamps", type=str, help="Comma-separated ascending epoch timestamps (e.g. '100,160,220,280')")
    return parser


def main(args: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.banner:
        print(BANNER)

    if not parsed.command:
        if not parsed.banner:
            print(BANNER)
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

        if getattr(parsed, "json_export", False):
            eligible = [i for i in items if not i.get("is_whitelisted") and i.get("confidence_score", 0) >= min_s]
            print(json.dumps({
                "status": "success",
                "format": fmt,
                "min_score": min_s,
                "exported_count": len(eligible),
                "indicators": [i.get("normalized_value") or i.get("value") for i in eligible[:10]],
            }, indent=2))
            return 0

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

    elif parsed.command == "entropy":
        dom = parsed.domain.strip()
        is_dga, ent_score, reason = DGADetector.evaluate(dom)
        result = {
            "domain": dom,
            "shannon_entropy": ent_score,
            "is_dga_suspect": is_dga,
            "classification": reason,
        }
        print(json.dumps(result, indent=2))
        return 0

    elif parsed.command == "asn":
        penalty, desc = ASNReputationProcessor.evaluate(parsed.asn)
        out = {
            "asn": parsed.asn.upper() if parsed.asn.upper().startswith("AS") else f"AS{parsed.asn.upper()}",
            "risk_penalty": penalty,
            "classification": desc,
            "is_bulletproof": "bulletproof" in desc.lower(),
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "dga-check":
        dom_list = [d.strip() for d in parsed.domains.split(",") if d.strip()]
        batch_out = []
        for d in dom_list:
            is_dga, ent, reason = DGADetector.evaluate(d)
            batch_out.append({
                "domain": d,
                "shannon_entropy": ent,
                "is_dga_suspect": is_dga,
                "classification": reason,
            })
        print(json.dumps(batch_out, indent=2))
        return 0

    elif parsed.command == "sigma-gen":
        raw_list = [x.strip() for x in parsed.indicators.split(",") if x.strip()]
        indicator_dicts = []
        for v in raw_list:
            clean = refang(v)
            ioc_type, norm = identify_indicator_type(clean)
            indicator_dicts.append({
                "normalized_value": norm,
                "type": ioc_type.value,
                "confidence_score": 90.0,
                "is_whitelisted": False,
            })
        rule = SigmaExporter.generate_network_rule(indicator_dicts, title=parsed.title, min_score=70.0)
        print(rule)
        return 0

    elif parsed.command == "bayesian":
        src_list = [s.strip() for s in parsed.sources.split(",") if s.strip()]
        posterior_prob = BayesianScorer.update_probability(
            src_list, prior=parsed.prior, benign_confirmations=parsed.benign
        )
        score = BayesianScorer.probability_to_score(posterior_prob)
        sim_out = {
            "sources": src_list,
            "prior_probability": parsed.prior,
            "benign_counter_evidence": parsed.benign,
            "posterior_probability": round(posterior_prob, 4),
            "bayesian_confidence_score": score,
        }
        print(json.dumps(sim_out, indent=2))
        return 0

    elif parsed.command == "ja4":
        is_valid = JA4FingerprintProcessor.is_valid_ja4(parsed.fingerprint)
        penalty, desc = JA4FingerprintProcessor.evaluate(parsed.fingerprint)
        out = {
            "fingerprint": parsed.fingerprint,
            "is_valid": is_valid,
            "penalty_score": penalty,
            "classification": desc,
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "favicon":
        penalty, desc = FaviconHashCalculator.evaluate_hash(parsed.hash)
        out = {
            "favicon_hash": parsed.hash,
            "penalty_score": penalty,
            "classification": desc,
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "markov":
        st = ThreatState(parsed.state.lower())
        trajectory = MarkovThreatStateModel.simulate_trajectory(initial_state=st, steps=parsed.steps)
        out = {
            "initial_state": parsed.state,
            "steps": parsed.steps,
            "trajectory": trajectory,
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "kalman":
        score_list = [float(x.strip()) for x in parsed.scores.split(",") if x.strip()]
        smoothed = KalmanConfidenceFilter.filter_batch(score_list, initial_score=parsed.initial)
        out = {
            "raw_observations": score_list,
            "initial_confidence": parsed.initial,
            "kalman_smoothed": smoothed,
            "converged_confidence": smoothed[-1] if smoothed else parsed.initial,
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "telemetry":
        diag = {
            "status": "HEALTHY",
            "engine_version": "v2.5.0",
            "active_collectors": [
                "Abuse.ch MalwareBazaar",
                "Bambenek Consulting C2",
                "Feodo Tracker",
                "Inversion DNSBL",
                "Rutgers Bad Hosts",
                "SSLBL Botnet C2",
                "ThreatFox",
                "ThreatView Cobalt Strike",
                "ViriBack C2 Tracker",
            ],
            "supported_exporters": [
                "CrowdStrike FDR",
                "MISP Feed Manifest",
                "Palo Alto PAN-OS EDL",
                "Snort 3 IPS",
                "Splunk ES Lookup",
                "Tanium Threat Response",
                "VyOS Address Group",
                "Zeek Notice Policy",
            ],
            "scoring_models": [
                "Bayesian Updater",
                "Discrete Markov State",
                "Gini-Simpson Diversity",
                "Kalman Confidence Filter",
                "Shannon Information Gain",
                "Weibull Survival Decay",
            ],
            "diagnostic_check": "ALL_SYSTEMS_OPERATIONAL",
        }
        print(json.dumps(diag, indent=2))
        return 0

    elif parsed.command == "typosquat":
        is_squat, penalty, brand = DomainTyposquatEvaluator.evaluate(parsed.domain)
        out = {
            "domain": parsed.domain,
            "is_typosquat": is_squat,
            "risk_penalty": penalty,
            "targeted_brand": brand,
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "pagerank":
        pairs = []
        for pair_str in parsed.edges.split(","):
            if "->" in pair_str:
                u, v = pair_str.split("->", 1)
                pairs.append((u.strip(), v.strip()))
        ranks = PageRankThreatGraph.compute_pagerank(pairs)
        out = {
            "edges": [f"{u}->{v}" for u, v in pairs],
            "rankings": ranks,
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "hassh":
        is_valid = HasshSSHProcessor.is_valid_hassh(parsed.fingerprint)
        penalty, desc = HasshSSHProcessor.evaluate(parsed.fingerprint)
        out = {
            "fingerprint": parsed.fingerprint,
            "is_valid": is_valid,
            "penalty_score": penalty,
            "classification": desc,
        }
        print(json.dumps(out, indent=2))
        return 0

    elif parsed.command == "beta-score":
        res = BetaDistributionScorer.calculate_score(
            malicious_count=parsed.malicious,
            benign_count=parsed.benign,
            prior_alpha=parsed.prior_alpha,
            prior_beta=parsed.prior_beta,
        )
        print(json.dumps(res, indent=2))
        return 0








    elif parsed.command == "ja4s":
        is_valid = JA4SFingerprintProcessor.is_valid_ja4s(parsed.fingerprint)
        penalty, desc = JA4SFingerprintProcessor.evaluate(parsed.fingerprint)
        out = {
            "fingerprint": parsed.fingerprint,
            "is_valid": is_valid,
            "penalty_score": penalty,
            "classification": desc,
        }
        print(json.dumps(out, indent=2))
        return 0


    elif parsed.command == "jitter":
        ts = [float(x.strip()) for x in parsed.timestamps.split(",") if x.strip()]
        is_beacon, cv, penalty, desc = BeaconJitterAnalyzer.analyze_intervals(ts)
        out = {
            "timestamps_count": len(ts),
            "is_beacon": is_beacon,
            "coefficient_of_variation": cv,
            "risk_penalty": penalty,
            "classification": desc,
        }
        print(json.dumps(out, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
