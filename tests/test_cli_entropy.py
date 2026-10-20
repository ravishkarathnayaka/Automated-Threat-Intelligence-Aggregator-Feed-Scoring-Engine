"""Unit tests for CLI entropy subcommand."""

import json
from cti_core.cli import main


def test_cli_entropy_subcommand(capsys):
    ret = main(["entropy", "threat-intelligence-engine.com"])
    assert ret == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "shannon_entropy" in data
    assert data["is_dga_suspect"] is False

    ret_dga = main(["entropy", "xzkqj918abcfmpqtw.net"])
    assert ret_dga == 0
    out_dga = capsys.readouterr().out
    data_dga = json.loads(out_dga)
    assert data_dga["is_dga_suspect"] is True
