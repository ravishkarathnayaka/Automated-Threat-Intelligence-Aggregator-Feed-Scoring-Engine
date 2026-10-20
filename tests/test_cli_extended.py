"""Unit tests for extended CLI commands (stats, bulk-score, check-domain, test-collector, yara)."""

from cti_core.cli import main


def test_cli_stats(capsys):
    ret = main(["stats"])
    assert ret == 0
    out = capsys.readouterr().out
    assert '"total_indicators":' in out
    assert '"whitelisted":' in out
    assert '"active_threats":' in out


def test_cli_bulk_score(capsys):
    ret = main(["bulk-score", "198.51.100.4,malicious.biz"])
    assert ret == 0
    out = capsys.readouterr().out
    assert '"score":' in out
    assert '"tier":' in out
    assert "198.51.100.4" in out


def test_cli_check_domain(capsys):
    ret = main(["check-domain", "xn--pple-43d.com"])
    assert ret == 0
    out = capsys.readouterr().out
    assert '"is_punycode": true' in out
    assert '"decoded_unicode":' in out


def test_cli_test_collector(capsys):
    ret = main(["test-collector", "--collector", "mock"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "[SUCCESS] Collector 'mock' returned" in out


def test_cli_export_yara(capsys):
    ret = main(["export", "--format", "yara", "--min-score", "60"])
    assert ret == 0
    out = capsys.readouterr().out
    assert 'import "hash"' in out or "rule" in out
