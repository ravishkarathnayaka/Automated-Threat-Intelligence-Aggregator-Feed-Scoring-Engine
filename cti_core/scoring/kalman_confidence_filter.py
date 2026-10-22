"""1-Dimensional Kalman filter for optimal threat confidence state estimation."""

from typing import Dict, List, Optional, Tuple


class KalmanConfidenceFilter:
    """Estimates latent threat confidence from sequentially arrived noisy feed observations."""

    def __init__(
        self,
        initial_confidence: float = 50.0,
        initial_variance: float = 100.0,
        process_noise_variance: float = 4.0,  # Q: Drift rate of adversary infrastructure
        default_measurement_noise: float = 25.0,  # R: Sensor noise variance
    ):
        self.state_estimate = initial_confidence
        self.error_covariance = initial_variance
        self.q = process_noise_variance
        self.default_r = default_measurement_noise

    def predict(self, time_drift: float = 1.0) -> Tuple[float, float]:
        """Time update step: increases uncertainty proportionally to time elapsed."""
        self.error_covariance += self.q * max(1.0, time_drift)
        return self.state_estimate, self.error_covariance

    def update(
        self,
        measurement: float,
        measurement_noise: Optional[float] = None,
    ) -> Tuple[float, float]:
        """Measurement update step incorporating a new feed confidence score."""
        r = measurement_noise if measurement_noise is not None else self.default_r

        # Kalman Gain
        k = self.error_covariance / (self.error_covariance + r)

        # State update
        innovation = measurement - self.state_estimate
        self.state_estimate += k * innovation
        self.state_estimate = max(0.0, min(100.0, self.state_estimate))

        # Covariance update
        self.error_covariance = (1.0 - k) * self.error_covariance

        return round(self.state_estimate, 2), round(self.error_covariance, 3)

    @classmethod
    def filter_batch(
        cls,
        measurements: List[float],
        initial_score: float = 50.0,
    ) -> List[float]:
        """Runs batch Kalman smoothing over a sequence of feed observations."""
        kf = cls(initial_confidence=initial_score)
        smoothed = []
        for m in measurements:
            kf.predict()
            est, _ = kf.update(m)
            smoothed.append(est)
        return smoothed
