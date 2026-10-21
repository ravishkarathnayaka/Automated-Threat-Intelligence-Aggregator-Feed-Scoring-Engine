"""CVSS v3.1 vector parser and vulnerability metrics extractor for CVE indicators."""

from typing import Dict, Optional


class CVSSParser:
    """Parses CVSS v3.1 vector strings into structured vulnerability impact metrics."""

    AV_MAP = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
    AC_MAP = {"L": "LOW", "H": "HIGH"}
    PR_MAP = {"N": "NONE", "L": "LOW", "H": "HIGH"}
    UI_MAP = {"N": "NONE", "R": "REQUIRED"}
    SEV_MAP = {"N": "NONE", "L": "LOW", "H": "HIGH"}

    @classmethod
    def parse_vector(cls, vector_str: str) -> Optional[Dict[str, str]]:
        """Parse CVSS:3.1 vector string into granular impact dictionary."""
        if not vector_str or "CVSS:3." not in vector_str:
            return None

        metrics = {}
        tokens = vector_str.strip().split("/")
        for token in tokens:
            if ":" not in token:
                continue
            key, val = token.split(":", 1)
            metrics[key.upper()] = val.upper()

        av = cls.AV_MAP.get(metrics.get("AV", ""), "UNKNOWN")
        ac = cls.AC_MAP.get(metrics.get("AC", ""), "UNKNOWN")
        pr = cls.PR_MAP.get(metrics.get("PR", ""), "UNKNOWN")
        ui = cls.UI_MAP.get(metrics.get("UI", ""), "UNKNOWN")
        c = cls.SEV_MAP.get(metrics.get("C", ""), "UNKNOWN")
        i = cls.SEV_MAP.get(metrics.get("I", ""), "UNKNOWN")
        a = cls.SEV_MAP.get(metrics.get("A", ""), "UNKNOWN")

        # Remote unauthenticated RCE is critical
        is_remote_unauth = av == "NETWORK" and pr == "NONE" and ui == "NONE"
        is_full_takeover = c == "HIGH" and i == "HIGH" and a == "HIGH"

        severity = "CRITICAL" if (is_remote_unauth and is_full_takeover) else ("HIGH" if is_remote_unauth else "MEDIUM")

        return {
            "attack_vector": av,
            "attack_complexity": ac,
            "privileges_required": pr,
            "user_interaction": ui,
            "confidentiality_impact": c,
            "integrity_impact": i,
            "availability_impact": a,
            "severity_estimate": severity,
            "is_unauthenticated_rce": is_remote_unauth and is_full_takeover,
        }
