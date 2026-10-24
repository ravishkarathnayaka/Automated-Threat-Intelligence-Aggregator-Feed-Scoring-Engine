"""HTTP response header ordering, entropy, and C2 fingerprint evaluator."""

from typing import Dict, List, Tuple


class HTTPHeaderEntropyEvaluator:
    """Evaluates HTTP response headers for missing standard headers and known C2 server anomalies."""

    STANDARD_PRODUCTION_HEADERS = {
        "content-type", "content-length", "date", "server",
        "connection", "cache-control", "strict-transport-security"
    }

    SUSPICIOUS_SERVER_HEADERS = {
        "simplehttp": (30.0, "Python SimpleHTTPServer payload delivery"),
        "apache/2.2": (20.0, "Legacy Apache scanner redirector"),
        "darkhttpd": (25.0, "Minimal darkhttpd C2 payload staging"),
    }

    @classmethod
    def evaluate(cls, headers: Dict[str, str]) -> Tuple[float, List[str]]:
        """Evaluates header dictionary for C2 anomalies.

        Returns:
            Tuple[float, List[str]]: (risk_penalty, detected_anomalies)
        """
        if not headers:
            return 15.0, ["empty_headers"]

        normalized = {k.lower(): v for k, v in headers.items()}
        anomalies: List[str] = []
        penalty = 0.0

        # Check for presence of Server header
        server_val = normalized.get("server", "").lower()
        for pattern, (pts, desc) in cls.SUSPICIOUS_SERVER_HEADERS.items():
            if pattern in server_val:
                penalty += pts
                anomalies.append(desc)

        # Check for abnormally sparse headers (C2 beacons often only return 1-2 headers)
        if len(normalized) <= 2:
            penalty += 20.0
            anomalies.append("abnormally_sparse_response_headers")

        # Missing basic Date header in HTTP/1.1 response
        if "date" not in normalized:
            penalty += 10.0
            anomalies.append("missing_rfc_date_header")

        return round(min(50.0, penalty), 2), anomalies
