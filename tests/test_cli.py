"""Tests for CLI-only commands."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from click.testing import CliRunner
from pytest import MonkeyPatch

from bulwark_mcp import __version__
from bulwark_mcp.cli import main


def test_version_command_prints_extended_info(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    result = CliRunner().invoke(main, ["version", "--db-path", str(db_path)])

    assert result.exit_code == 0
    assert f"bulwark-mcp {__version__}" in result.output
    assert "Python " in result.output
    assert "Platform: " in result.output
    assert "Rules loaded: " in result.output
    assert "Detector: off (config default)" in result.output
    assert "DB schema: v2" in result.output
    assert "Install path: " in result.output


def test_short_version_flag_is_unchanged() -> None:
    result = CliRunner().invoke(main, ["--version"], prog_name="bulwark")

    assert result.exit_code == 0
    assert result.output == f"bulwark, version {__version__}\n"


def _settings(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        db_path=tmp_path / "audit.db",
        detector=SimpleNamespace(
            llm_enabled=True,
            ollama_url="http://localhost:11434",
            ollama_model="qwen2.5:3b",
        ),
    )


def test_detect_ollama_unreachable_prints_friendly_error_and_exits_2(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    async def _fake_run_detect(*args: object, **kwargs: object) -> Any:
        return SimpleNamespace(
            verdict="PASS",
            note="error:ConnectError",
            score=0.0,
            latency_ms=0,
            rules_hit=[],
            classifier=None,
            matched_policy=None,
            action="allow",
        )

    monkeypatch.setattr("bulwark_mcp.cli.resolve_settings", lambda **_: _settings(tmp_path))
    monkeypatch.setattr("bulwark_mcp.cli._run_detect", _fake_run_detect)

    result = CliRunner().invoke(main, ["detect", "hello", "--verbose"])

    assert result.exit_code == 2
    assert "Could not reach Ollama at http://localhost:11434." in result.output
    assert "Start Ollama: ollama serve" in result.output
    assert "Or pull the model: ollama pull qwen2.5:3b" in result.output
    assert 'Or run rules-only: bulwark detect "..." --no-llm' in result.output
    assert "Or run bulwark doctor to diagnose your setup." in result.output


def test_detect_no_llm_flag_does_not_trigger_ollama_unreachable_handling(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    async def _fake_run_detect(*args: object, **kwargs: object) -> Any:
        return SimpleNamespace(
            verdict="PASS",
            note="error:ConnectError",
            score=0.0,
            latency_ms=0,
            rules_hit=[],
            classifier=None,
            matched_policy=None,
            action="allow",
        )

    monkeypatch.setattr("bulwark_mcp.cli.resolve_settings", lambda **_: _settings(tmp_path))
    monkeypatch.setattr("bulwark_mcp.cli._run_detect", _fake_run_detect)

    result = CliRunner().invoke(main, ["detect", "hello", "--no-llm"])

    assert result.exit_code == 0
    assert "Could not reach Ollama" not in result.output
