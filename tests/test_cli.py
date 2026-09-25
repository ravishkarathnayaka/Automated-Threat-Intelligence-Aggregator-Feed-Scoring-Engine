"""Unit tests verifying command-line interface (CLI) commands and outputs."""

from cti_core.cli import main


def test_cli_help(capsys):
    """Verify CLI without arguments outputs usage."""
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "usage: cti-cli" in captured.out


def test_cli_refang_and_defang(capsys):
    """Verify refang and defang commands."""
    ret_refang = main(["refang", "hxxps://malware-test[.]org/bin"])
    assert ret_refang == 0
    out_refang = capsys.readouterr().out
    assert "https://malware-test.org/bin" in out_refang

    ret_defang = main(["defang", "https://malware-test.org/bin"])
    assert ret_defang == 0
    out_defang = capsys.readouterr().out
    assert "[.]" in out_defang or "hxxp" in out_defang


def test_cli_bogon_detection(capsys):
    """Verify bogon command flags unroutable IPs."""
    ret_bogon = main(["bogon", "10.0.0.1"])
    assert ret_bogon == 0
    out_bogon = capsys.readouterr().out
    assert "[BOGON]" in out_bogon

    ret_valid = main(["bogon", "185.220.101.5"])
    assert ret_valid == 0
    out_valid = capsys.readouterr().out
    assert "[VALID]" in out_valid


def test_cli_score_indicator(capsys):
    """Verify scoring an indicator via CLI."""
    ret = main(["score", "185[.]220[.]101[.]5", "--source", "abuseipdb"])
    assert ret == 0
    out = capsys.readouterr().out
    assert '"indicator": "185.220.101.5"' in out
    assert '"tier":' in out


def test_cli_export_firewall(capsys):
    """Verify exporting firewall blocklist via CLI."""
    ret = main(["export", "--format", "firewall", "--min-score", "60"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "# Automated Threat Intelligence Firewall Blocklist" in out
    assert "185.220.101.5" in out


def test_cli_export_zeek(capsys):
    """Verify exporting Zeek intel feed via CLI."""
    ret = main(["export", "--format", "zeek", "--min-score", "60"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "#fields\tindicator\tindicator_type" in out
