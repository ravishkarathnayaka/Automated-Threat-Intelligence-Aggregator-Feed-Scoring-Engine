"""Unit tests for Kullback-Leibler and Jensen-Shannon relative entropy evaluator."""

import pytest
from cti_core.scoring.kl_divergence_evaluator import KLDivergenceEvaluator


def test_identical_distributions():
    p = [0.25, 0.25, 0.25, 0.25]
    kl = KLDivergenceEvaluator.compute_kl(p, p)
    jsd = KLDivergenceEvaluator.compute_jsd(p, p)
    assert pytest.approx(kl, abs=1e-5) == 0.0
    assert pytest.approx(jsd, abs=1e-5) == 0.0


def test_different_lengths_raises():
    with pytest.raises(ValueError):
        KLDivergenceEvaluator.compute_kl([0.5, 0.5], [1.0])


def test_drift_detection():
    baseline = {"c2": 100, "phishing": 100, "scanner": 100}
    # Identical current -> no drift
    res_stable = KLDivergenceEvaluator.detect_drift(baseline, {"c2": 95, "phishing": 105, "scanner": 100})
    assert not res_stable["is_drifted"]
    assert res_stable["drift_severity"] == "LOW"

    # Heavily shifted distribution -> drift
    res_drifted = KLDivergenceEvaluator.detect_drift(baseline, {"c2": 1000, "phishing": 0, "scanner": 0})
    assert res_drifted["is_drifted"]
    assert res_drifted["drift_severity"] in ("MODERATE", "HIGH")
    assert res_drifted["jsd"] > 0.15
