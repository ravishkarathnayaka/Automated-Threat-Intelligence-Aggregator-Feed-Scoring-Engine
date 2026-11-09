"""Fox-IT JA4L latency-based network distance and VPN/proxy hop anomaly detector."""

from typing import Optional, Tuple


class JA4LLatencyProcessor:
    """Evaluates Fox-IT JA4L light-distance/latency telemetry to detect proxy chains and Tor relays."""

    # Approximate propagation delay in microseconds per km in fiber (~4.9 us/km)
    FIBER_US_PER_KM = 4.9

    @classmethod
    def evaluate_latency(
        cls,
        measured_rtt_us: float,
        claimed_geo_distance_km: Optional[float] = None,
        os_ttl: int = 64,
    ) -> Tuple[bool, float, str]:
        """Detects mismatch between claimed GeoIP distance and physical TCP/QUIC handshake RTT.

        Args:
            measured_rtt_us: Half-RTT or handshake latency in microseconds.
            claimed_geo_distance_km: Expected geographic distance in kilometers.
            os_ttl: Observed IPv4/IPv6 hop TTL.

        Returns:
            Tuple[bool, float, str]: (is_anomalous, risk_penalty, classification)
        """
        if measured_rtt_us <= 0:
            return False, 0.0, "invalid_latency_measurement"

        # Infer hop count from standard initial TTLs (64, 128, 255)
        initial_ttl = 64 if os_ttl <= 64 else (128 if os_ttl <= 128 else 255)
        hops = max(0, initial_ttl - os_ttl)

        if claimed_geo_distance_km is not None and claimed_geo_distance_km > 0:
            min_physical_us = claimed_geo_distance_km * cls.FIBER_US_PER_KM
            # If measured RTT is > 4x expected physical fiber latency, likely multi-hop proxy/Tor
            if measured_rtt_us > max(50000.0, min_physical_us * 4.5):
                return True, 25.0, "ja4l_proxy_or_tor_relay_latency_inflation"
            # If measured RTT is physically impossible (< 0.8x speed of light in fiber), GeoIP spoofed
            if measured_rtt_us < min_physical_us * 0.8:
                return True, 30.0, "ja4l_spoofed_anycast_or_geoip_mismatch"

        if hops >= 24:
            return True, 15.0, "ja4l_excessive_routing_hops"

        return False, 0.0, "normal_ja4l_distance_profile"
