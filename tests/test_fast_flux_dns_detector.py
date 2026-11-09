"""Unit tests for Fast-Flux DNS botnet proxy rotation detector."""

from cti_core.processors.fast_flux_dns_detector import FastFluxDNSDetector


def test_fast_flux_evaluation():
    # High-confidence multi-ASN fast flux
    flux_ips = [f"198.51.100.{i}" for i in range(1, 11)]
    is_flux, penalty, desc = FastFluxDNSDetector.evaluate_flux(
        resolved_ips=flux_ips,
        min_ttl_seconds=60,
        unique_asns_count=6,
    )
    assert is_flux is True
    assert penalty == 35.0
    assert "fast_flux_botnet" in desc

    # Single-flux proxy rotation
    mod_ips = [f"203.0.113.{i}" for i in range(1, 6)]
    is_flux2, penalty2, desc2 = FastFluxDNSDetector.evaluate_flux(
        resolved_ips=mod_ips,
        min_ttl_seconds=240,
        unique_asns_count=3,
    )
    assert is_flux2 is True
    assert penalty2 == 25.0

    # Normal CDN / static hosting (single ASN or high TTL)
    is_flux3, penalty3, desc3 = FastFluxDNSDetector.evaluate_flux(
        resolved_ips=["192.0.2.1", "192.0.2.2"],
        min_ttl_seconds=3600,
        unique_asns_count=1,
    )
    assert is_flux3 is False
    assert penalty3 == 0.0
