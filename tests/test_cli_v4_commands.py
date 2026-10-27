"""Unit tests for v4 CLI subcommands (ja4s, jitter, dirichlet, doh)."""

import json
from io import StringIO
from unittest.mock import patch

from cti_core.cli import main


def test_cli_ja4s():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["ja4s", "t1302h2_1301_a56c5b992b27"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["is_valid"] is True
        assert data["penalty_score"] == 30.0
        assert "Cobalt Strike" in data["classification"]


def test_cli_jitter():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["jitter", "100.0, 160.0, 220.0, 280.0, 340.0"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["is_beacon"] is True
        assert data["timestamps_count"] == 5
        assert data["risk_penalty"] == 35.0


def test_cli_dirichlet():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["dirichlet", "c2=25,malware=5,benign=1"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["dominant_category"] == "c2"
        assert data["composite_threat_score"] > 80.0
        assert "entropy" in data


def test_cli_doh():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["doh", "dns.google", "--type", "domain"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["is_doh_evasion"] is True
        assert data["risk_penalty"] == 15.0
