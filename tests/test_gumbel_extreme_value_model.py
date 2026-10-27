"""Unit tests for Gumbel distribution extreme value model."""

import pytest
from cti_core.scoring.gumbel_extreme_value_model import GumbelExtremeValueModel


def test_invalid_beta():
    with pytest.raises(ValueError):
        GumbelExtremeValueModel(0.0, -1.0)


def test_fit_from_samples():
    peaks = [10.0, 12.0, 15.0, 11.0, 14.0, 13.0]
    model = GumbelExtremeValueModel.fit_from_samples(peaks)
    assert model.beta > 0.0
    assert 5.0 < model.mu < 20.0


def test_surge_detection():
    # Historical peaks around 20-30
    peaks = [20.0, 25.0, 22.0, 28.0, 24.0, 26.0]
    res_normal = GumbelExtremeValueModel.evaluate_surge(peaks, 24.0)
    res_extreme = GumbelExtremeValueModel.evaluate_surge(peaks, 150.0)

    # Extreme surge should have very low exceedance probability and high anomaly score
    assert res_extreme["exceedance_probability"] < 0.001
    assert res_extreme["surge_anomaly_score"] > 99.0
    assert res_extreme["return_period"] > res_normal["return_period"]
