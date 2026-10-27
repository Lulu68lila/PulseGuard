"""Unit tests for the PulseGuard CLI commands."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pulseguard.cli.main import cli
from pulseguard.engine.signatures import EICAR_BYTE_STRING


def test_cli_help_and_version() -> None:
    runner = CliRunner()
    res = runner.invoke(cli, ["--help"])
    assert res.exit_code == 0
    assert "PulseGuard" in res.output

    v_res = runner.invoke(cli, ["--version"])
    assert v_res.exit_code == 0
    assert "0.1.0" in v_res.output


def test_cli_scan_clean_file(tmp_path: Path) -> None:
    clean_file = tmp_path / "benign.txt"
    clean_file.write_text("All good here.", encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(clean_file)])
    assert res.exit_code == 0
    assert "CLEAN" in res.output


def test_cli_scan_json_output(tmp_path: Path) -> None:
    clean_file = tmp_path / "benign.txt"
    clean_file.write_text("Hello world", encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(clean_file), "--json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert isinstance(data, list)
    assert data[0]["status"] == "CLEAN"


def test_cli_scan_infected_and_quarantine(tmp_path: Path) -> None:
    infected_file = tmp_path / "ransom_test.bin"
    infected_file.write_bytes(b"DATA_HEADER::PULSEGUARD_TEST_RANSOM_MARKER::DATA_FOOTER")

    runner = CliRunner()
    # Without quarantine flag, exit code should be 1
    res = runner.invoke(cli, ["scan", str(infected_file)])
    assert res.exit_code == 1
    assert "INFECTED" in res.output
    assert "Ransom" in res.output

    # With quarantine flag, it should isolate the file
    res_q = runner.invoke(cli, ["scan", str(infected_file), "--quarantine"])
    assert res_q.exit_code == 1
    assert "quarantined 1 threat" in res_q.output.lower()
    assert not infected_file.exists()


def test_cli_status_command() -> None:
    runner = CliRunner()
    res = runner.invoke(cli, ["status"])
    assert res.exit_code == 0
    assert "PulseGuard Antivirus Status" in res.output
    assert "Signatures Loaded" in res.output


def test_cli_quarantine_subcommands(tmp_path: Path) -> None:
    runner = CliRunner()

    # List empty
    res_list = runner.invoke(cli, ["quarantine", "list"])
    assert res_list.exit_code == 0

    # Test delete nonexistent record
    res_del_fail = runner.invoke(cli, ["quarantine", "delete", "nonexistent-id"])
    assert res_del_fail.exit_code == 2

    # Test restore nonexistent record
    res_res_fail = runner.invoke(cli, ["quarantine", "restore", "nonexistent-id"])
    assert res_res_fail.exit_code == 2


@patch("pulseguard.cli.main.PulseGuardService")
def test_cli_watch_command(mock_service_class: MagicMock, tmp_path: Path) -> None:
    mock_instance = MagicMock()
    mock_service_class.return_value = mock_instance

    runner = CliRunner()
    res = runner.invoke(cli, ["watch", str(tmp_path)])
    assert res.exit_code == 0
    assert "Real-Time Protection active" in res.output
    mock_instance.start.assert_called_once_with(block=True)
