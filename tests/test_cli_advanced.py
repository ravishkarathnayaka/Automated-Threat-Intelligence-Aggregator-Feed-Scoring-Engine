"""Unit tests for advanced CLI subcommands (asn, dga-check, sigma-gen, bayesian)."""

import json
from cti_core.cli import main


def test_cli_asn_subcommand(capsys):
    exit_code = main(["asn", "AS200019"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["asn"] == "AS200019"
    assert data["risk_penalty"] == 35.0
    assert data["is_bulletproof"] is True


def test_cli_dga_check_subcommand(capsys):
    exit_code = main(["dga-check", "apple.com,xqjkzxpvnm91823a.biz"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 2
    assert data[0]["domain"] == "apple.com"
    assert data[0]["is_dga_suspect"] is False
    assert data[1]["domain"] == "xqjkzxpvnm91823a.biz"
    assert data[1]["is_dga_suspect"] is True


def test_cli_sigma_gen_subcommand(capsys):
    exit_code = main(["sigma-gen", "185.220.101.5,apt-c2-node.biz", "--title", "CLI Test Rule"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "title: CLI Test Rule" in captured.out
    assert "category: network_connection" in captured.out
    assert "185.220.101.5" in captured.out


def test_cli_bayesian_subcommand(capsys):
    exit_code = main(["bayesian", "virustotal,threatfox", "--prior", "0.20"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["prior_probability"] == 0.20
    assert data["posterior_probability"] > 0.90
    assert data["bayesian_confidence_score"] > 90.0
