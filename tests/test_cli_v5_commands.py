"""Unit tests for v5 CLI subcommands (ja4h, ja4t, dns-tunnel, rpki, dempster, hawkes, cusum)."""

import json
from io import StringIO
from unittest.mock import patch

from cti_core.cli import main


def test_cli_ja4h():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["ja4h", "ge11nn040000_8daaf6152771_000000000000_000000000000"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["is_valid"] is True
        assert data["penalty_score"] == 35.0


def test_cli_ja4t():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["ja4t", "1024_2_1460_0"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["is_valid"] is True
        assert data["penalty_score"] == 35.0


def test_cli_dns_tunnel():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["dns-tunnel", "4a6f686e446f6553656372657450617373776f726431323334.9f8e7d6c5b4a.c2.evil.com"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["is_tunneling"] is True
        assert data["risk_penalty"] == 35.0


def test_cli_rpki():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["rpki", "AS12345", "--status", "invalid"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["is_hijack_risk"] is True
        assert data["risk_penalty"] == 35.0


def test_cli_dempster():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["dempster", "0.75,0.05;0.80,0.05"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["belief_malicious"] > 0.85


def test_cli_hawkes():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["hawkes", "9.1,9.4,9.6,9.8,10.0"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["intensity_lambda"] > 2.0


def test_cli_cusum():
    with patch("sys.stdout", new=StringIO()) as fake_out:
        rc = main(["cusum", "9,10,11,25,26,28"])
        assert rc == 0
        data = json.loads(fake_out.getvalue())
        assert data["alarm_triggered"] is True
