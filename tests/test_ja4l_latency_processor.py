"""Unit tests for Fox-IT JA4L latency and hop distance anomaly processor."""

from cti_core.processors.ja4l_latency_processor import JA4LLatencyProcessor


def test_ja4l_latency_evaluation():
    # Proxy / Tor latency inflation (claimed 100km -> ~490us, actual 180,000us)
    is_anom, penalty, desc = JA4LLatencyProcessor.evaluate_latency(
        measured_rtt_us=180000.0,
        claimed_geo_distance_km=100.0,
        os_ttl=52,
    )
    assert is_anom is True
    assert penalty == 25.0
    assert "inflation" in desc

    # Physically impossible low latency for claimed distance (GeoIP spoofing)
    is_anom2, penalty2, desc2 = JA4LLatencyProcessor.evaluate_latency(
        measured_rtt_us=1000.0,
        claimed_geo_distance_km=8000.0,
        os_ttl=58,
    )
    assert is_anom2 is True
    assert penalty2 == 30.0
    assert "spoofed" in desc2

    # Normal latency profile
    is_anom3, penalty3, desc3 = JA4LLatencyProcessor.evaluate_latency(
        measured_rtt_us=6000.0,
        claimed_geo_distance_km=800.0,
        os_ttl=56,
    )
    assert is_anom3 is False
    assert penalty3 == 0.0
