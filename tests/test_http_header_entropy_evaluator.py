"""Unit tests for HTTP header anomaly evaluator."""

from cti_core.processors.http_header_entropy_evaluator import HTTPHeaderEntropyEvaluator


def test_http_header_evaluation():
    # Suspicious SimpleHTTP C2 staging
    headers_suspicious = {
        "Server": "SimpleHTTP/0.6 Python/3.8",
        "Content-Type": "application/octet-stream",
    }
    penalty, anomalies = HTTPHeaderEntropyEvaluator.evaluate(headers_suspicious)
    assert penalty >= 30.0
    assert any("Python SimpleHTTPServer" in a for a in anomalies)
    assert "abnormally_sparse_response_headers" in anomalies

    # Standard clean production response
    headers_clean = {
        "Server": "cloudflare",
        "Date": "Sun, 24 Oct 2026 12:00:00 GMT",
        "Content-Type": "text/html; charset=UTF-8",
        "Connection": "keep-alive",
        "Strict-Transport-Security": "max-age=31536000",
    }
    penalty_clean, anomalies_clean = HTTPHeaderEntropyEvaluator.evaluate(headers_clean)
    assert penalty_clean == 0.0
    assert len(anomalies_clean) == 0
