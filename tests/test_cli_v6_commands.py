"""Unit tests for v4.5 / v6 CLI commands (ja4ssh, domain-fronting, subdomain-takeover, mdp-mitigate)."""

import json
from unittest.mock import patch
import pytest

from cti_core.cli import main


def test_cli_ja4ssh_command(capsys):
    ret = main(["ja4ssh", "c_1_0_0_0"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["fingerprint"] == "c_1_0_0_0"
    assert data["is_valid"] is True
    assert data["penalty_score"] == 35.0
    assert "Hydra" in data["classification"]


def test_cli_domain_fronting_command(capsys):
    ret = main(["domain-fronting", "cdn.cloudflare.com", "c2.evil-adversary.com"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_fronting"] is True
    assert data["risk_penalty"] == 35.0
    assert "cdn_domain_fronting" in data["description"]


def test_cli_subdomain_takeover_command(capsys):
    ret = main(["subdomain-takeover", "portal.github.io", "--body", "There isn't a GitHub Pages site here"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_takeover_vulnerable"] is True
    assert data["risk_penalty"] == 35.0
    assert "verified_subdomain_takeover" in data["description"]


def test_cli_mdp_mitigate_command(capsys):
    ret = main(["mdp-mitigate", "92.5", "--impact", "1.2"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["confidence_score"] == 92.5
    assert data["recommended_action"] == "BLOCK_IMMEDIATE"
    assert data["is_blocking"] is True
