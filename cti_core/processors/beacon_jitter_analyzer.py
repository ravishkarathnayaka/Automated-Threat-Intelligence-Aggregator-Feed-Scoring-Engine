"""C2 beacon inter-arrival regularity and jitter variance estimator."""

import math
from typing import List, Tuple


class BeaconJitterAnalyzer:
    """Analyzes network connection inter-arrival times to detect automated C2 periodic beaconing."""

    @classmethod
    def analyze_intervals(cls, timestamps: List[float]) -> Tuple[bool, float, float, str]:
        """Analyzes a sequence of ascending epoch timestamps (in seconds).

        Returns:
            Tuple[bool, float, float, str]: (is_beacon, coefficient_of_variation, risk_penalty, classification)
        """
        if len(timestamps) < 4:
            return False, 0.0, 0.0, "insufficient_samples"

        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if any(dt <= 0 for dt in intervals):
            return False, 0.0, 0.0, "invalid_non_monotonic_timestamps"

        n = len(intervals)
        mean_interval = sum(intervals) / n
        if mean_interval == 0:
            return False, 0.0, 0.0, "zero_mean_interval"

        variance = sum((dt - mean_interval) ** 2 for dt in intervals) / n
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval  # Coefficient of Variation

        # Highly regular beaconing: CV < 0.15 (very low jitter)
        if cv < 0.15:
            return True, round(cv, 4), 35.0, "strict_periodic_c2_beaconing"
        # Low to moderate jitter: CV < 0.35 (e.g. Cobalt Strike 20-30% jitter)
        elif cv < 0.35:
            return True, round(cv, 4), 25.0, "jittered_c2_beaconing"

        return False, round(cv, 4), 0.0, "normal_sporadic_network_traffic"
