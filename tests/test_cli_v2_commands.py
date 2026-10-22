"""Unit tests for v2 CLI subcommands (ja4, favicon, markov, kalman)."""

import json
from cti_core.cli import main


def test_cli_ja4_subcommand(capsys):
    exit_code = main(["ja4", "t13d1516h2_8daaf6152771_b7538a735178"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["fingerprint"] == "t13d1516h2_8daaf6152771_b7538a735178"
    assert data["is_valid"] is True
    assert data["penalty_score"] == 30.0
    assert "Cobalt Strike" in data["classification"]


def test_cli_favicon_subcommand(capsys):
    exit_code = main(["favicon", "-123456789"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["favicon_hash"] == -123456789
    assert data["penalty_score"] == 30.0
    assert "Cobalt Strike" in data["classification"]


def test_cli_markov_subcommand(capsys):
    exit_code = main(["markov", "--state", "active", "--steps", "2"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["initial_state"] == "active"
    assert data["steps"] == 2
    assert len(data["trajectory"]) == 3
    assert data["trajectory"][0]["active"] == 1.0


def test_cli_kalman_subcommand(capsys):
    exit_code = main(["kalman", "70,80,85,90", "--initial", "50"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["raw_observations"]) == 4
    assert data["initial_confidence"] == 50.0
    assert len(data["kalman_smoothed"]) == 4
    assert data["converged_confidence"] > 70.0
