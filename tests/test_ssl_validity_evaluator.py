"""Unit tests for X.509 certificate validity lifespan anomaly evaluator."""

import pytest
from cti_core.processors.ssl_validity_evaluator import SSLCertificateValidityEvaluator


def test_standard_validity():
    anomalous, penalty, expl = SSLCertificateValidityEvaluator.evaluate_lifespan(90.0)
    assert not anomalous
    assert penalty == 0.0
    assert "standard_cab_forum_validity" in expl


def test_ten_year_self_signed():
    anomalous, penalty, expl = SSLCertificateValidityEvaluator.evaluate_lifespan(3650.0)
    assert anomalous
    assert penalty == 30.0
    assert "abnormally_long" in expl


def test_deprecated_extended_lifespan():
    anomalous, penalty, expl = SSLCertificateValidityEvaluator.evaluate_lifespan(900.0)
    assert anomalous
    assert penalty == 15.0
    assert "deprecated_extended_lifespan" in expl


def test_disposable_ephemeral_lifespan():
    anomalous, penalty, expl = SSLCertificateValidityEvaluator.evaluate_lifespan(2.0)
    assert anomalous
    assert penalty == 25.0
    assert "disposable_ephemeral" in expl


def test_expired_or_zero_lifespan():
    anomalous, penalty, expl = SSLCertificateValidityEvaluator.evaluate_lifespan(-5.0)
    assert anomalous
    assert penalty == 25.0
    assert "expired_or_invalid" in expl
