"""Unit tests for v3 CLI subcommands (typosquat, pagerank, hassh, beta-score)."""

import json
from cti_core.cli import main


def test_cli_typosquat_subcommand(capsys):
    exit_code = main(["typosquat", "paypaal.com"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["domain"] == "paypaal.com"
    assert data["is_typosquat"] is True
    assert data["targeted_brand"] == "paypal"
    assert data["risk_penalty"] == 35.0


def test_cli_pagerank_subcommand(capsys):
    exit_code = main(["pagerank", "198.51.100.1->c2-bad.com,198.51.100.1->apt-payload"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["edges"]) == 2
    assert "198.51.100.1" in data["rankings"]
    assert data["rankings"]["198.51.100.1"] == 1.0


def test_cli_hassh_subcommand(capsys):
    exit_code = main(["hassh", "b123456789abcdef0123456789abcdef"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["fingerprint"] == "b123456789abcdef0123456789abcdef"
    assert data["is_valid"] is True
    assert data["penalty_score"] == 25.0
    assert "Hydra" in data["classification"]


def test_cli_beta_score_subcommand(capsys):
    exit_code = main(["beta-score", "--malicious", "12", "--benign", "1"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["alpha"] == 13.0
    assert data["beta"] == 5.0
    assert data["confidence_score"] > 70.0
    assert data["epistemic_variance"] < 0.05
