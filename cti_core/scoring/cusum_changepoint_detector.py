"""Tabular Cumulative Sum (CUSUM) sequential change-point detector for APT campaign bursts."""

from typing import Iterable, List, Tuple


class CUSUMChangePointDetector:
    """Detects abrupt step-changes in threat indicator reporting rate using Page's tabular CUSUM."""

    @classmethod
    def detect_burst(
        cls,
        observations: Iterable[float],
        target_mean: float = 10.0,
        allowable_slack_k: float = 2.0,
        decision_threshold_h: float = 15.0,
    ) -> Tuple[bool, float, List[float], str]:
        """Evaluates a sequence of hourly/daily indicator counts for upward regime shifts.

        Formula: S_t = max(0, S_{t-1} + (x_t - target_mean - k))

        Returns:
            Tuple[bool, float, List[float], str]: (alarm_triggered, max_cusum, trajectory, status)
        """
        s_pos = 0.0
        max_s = 0.0
        trajectory: List[float] = []
        alarm = False

        for x in observations:
            val = float(x)
            s_pos = max(0.0, s_pos + (val - target_mean - allowable_slack_k))
            s_rounded = round(s_pos, 4)
            trajectory.append(s_rounded)
            if s_rounded > max_s:
                max_s = s_rounded
            if s_rounded >= decision_threshold_h:
                alarm = True

        status = "cusum_apt_velocity_surge_detected" if alarm else "nominal_baseline_rate"
        return alarm, max_s, trajectory, status
