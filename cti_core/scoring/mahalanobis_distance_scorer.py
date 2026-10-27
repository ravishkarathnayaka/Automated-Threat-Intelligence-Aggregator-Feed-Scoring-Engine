"""Mahalanobis distance multivariate anomaly detector for multi-featured threat telemetry."""

import math
from typing import Dict, List, Optional, Tuple


class MahalanobisDistanceScorer:
    """Computes Mahalanobis distance across multivariate threat features (e.g. query rate, entropy, TTL)

    taking into account inter-feature correlations and covariance.
    """

    def __init__(self, ridge_lambda: float = 1e-4):
        self.ridge_lambda = ridge_lambda
        self.means: List[float] = []
        self.inv_cov: List[List[float]] = []
        self.dim = 0

    @staticmethod
    def _invert_matrix(matrix: List[List[float]]) -> List[List[float]]:
        """Inverts a square matrix using Gauss-Jordan elimination."""
        n = len(matrix)
        # Augment with identity
        aug = [row[:] + [1.0 if i == j else 0.0 for j in range(n)] for i, row in enumerate(matrix)]

        for i in range(n):
            # Pivot
            pivot = aug[i][i]
            if abs(pivot) < 1e-12:
                # Find non-zero pivot
                for k in range(i + 1, n):
                    if abs(aug[k][i]) > abs(pivot):
                        aug[i], aug[k] = aug[k], aug[i]
                        pivot = aug[i][i]
                        break

            if abs(pivot) < 1e-12:
                raise ValueError("Singular matrix cannot be inverted")

            # Scale pivot row
            for j in range(2 * n):
                aug[i][j] /= pivot

            # Eliminate other rows
            for k in range(n):
                if k != i:
                    factor = aug[k][i]
                    for j in range(2 * n):
                        aug[k][j] -= factor * aug[i][j]

        # Extract right half
        return [row[n:] for row in aug]

    def fit(self, samples: List[List[float]]) -> "MahalanobisDistanceScorer":
        """Fits mean vector and regularized inverse covariance matrix from historical feature vectors."""
        if not samples or not samples[0]:
            raise ValueError("Samples cannot be empty")

        n = len(samples)
        d = len(samples[0])
        self.dim = d

        # Compute means
        self.means = [sum(samples[i][j] for i in range(n)) / n for j in range(d)]

        if n < 2:
            # Identity fallback
            self.inv_cov = [[1.0 if i == j else 0.0 for j in range(d)] for i in range(d)]
            return self

        # Compute covariance matrix
        cov = [[0.0 for _ in range(d)] for _ in range(d)]
        for s in samples:
            diff = [s[j] - self.means[j] for j in range(d)]
            for i in range(d):
                for j in range(d):
                    cov[i][j] += diff[i] * diff[j]

        for i in range(d):
            for j in range(d):
                cov[i][j] /= (n - 1)
            # Add Tikhonov ridge regularization
            cov[i][i] += self.ridge_lambda

        self.inv_cov = self._invert_matrix(cov)
        return self

    def distance(self, point: List[float]) -> float:
        """Calculates D_M(x) = sqrt((x - mu)^T * Sigma^{-1} * (x - mu))."""
        if len(point) != self.dim:
            raise ValueError(f"Expected point of dimension {self.dim}, got {len(point)}")

        delta = [point[j] - self.means[j] for j in range(self.dim)]

        # z = Sigma^{-1} * delta
        z = [
            sum(self.inv_cov[i][j] * delta[j] for j in range(self.dim))
            for i in range(self.dim)
        ]

        # dist_sq = delta^T * z
        dist_sq = sum(delta[i] * z[i] for i in range(self.dim))
        return math.sqrt(max(0.0, dist_sq))

    def evaluate_point(self, point: List[float]) -> Dict[str, object]:
        """Calculates distance and maps it to an outlier anomaly score."""
        dist = self.distance(point)
        # Approximate chi-square anomaly: for 3-4 DOF, dist > 3 is ~99th percentile outlier
        anomaly_score = min(100.0, round((dist / 3.5) * 100.0, 2))
        return {
            "mahalanobis_distance": round(dist, 4),
            "anomaly_score": anomaly_score,
            "is_outlier": dist > 3.0,
        }

    @classmethod
    def evaluate(
        cls, baseline_samples: List[List[float]], test_vector: List[float]
    ) -> Dict[str, object]:
        """Convenience method to fit and test in a single call."""
        model = cls().fit(baseline_samples)
        return model.evaluate_point(test_vector)
