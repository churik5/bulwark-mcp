"""Tests for `bulwark config-validate` (issue #5).

The point of the command is to catch what ``resolve_settings()`` accepts
in silence, so most of these fixtures are configs the loader is perfectly
happy with. ``TestSilentFallback`` is the regression that matters.
"""

from __future__ import annotations

import inspect
import os
import re
from pathlib import Path

import pytest
from click.testing import CliRunner
from click.testing import Result as CliResult

from bulwark_mcp import config as config_module
from bulwark_mcp.cli import main
from bulwark_mcp.config import ENV_CONFIG, ENV_DB
from bulwark_mcp.config_validate import (
    _CHECK_FIELDS,
    _CHECK_FILE,
    _CHECK_KEYS,
    _CHECK_LOADER,
    _CHECK_POLICY,
    _CHECK_RULES,
    _CHECK_SECTIONS,
    _CHECK_YAML,
    KNOWN_SECTIONS,
    Finding,
    error_count,
    validate_config,
    warning_count,
)

VALID_CONFIG = """\
storage:
  db_path: "data/log.db"
  queue_max: 10000
detector:
  enabled: true
  max_latency_ms: 200
  llm:
    enabled: false
    timeout_ms: 1000
capability:
  server_name: "filesystem"
  allowed_tools:
    - filesystem.read
"""

VALID_POLICY = """\
default: allow
rules:
  - name: block_high_score
    when:
      detector_score_at_least: 0.9
    action: block
"""


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _rows(findings: list[Finding], name: str) -> list[Finding]:
    return [f for f in findings if f.name == name]


def _statuses(findings: list[Finding], name: str) -> list[str]:
    return [f.status for f in _rows(findings, name)]


def _details(findings: list[Finding], name: str) -> str:
    return " ".join(f.detail for f in _rows(findings, name))


def _flat(text: str) -> str:
    """Rich wraps table cells to the terminal width; compare on one line."""
    return " ".join(text.split())


def _run(path: Path) -> CliResult:
    # A wide console keeps details on one line so assertions stay readable.
    return CliRunner().invoke(main, ["config-validate", str(path)], env={"COLUMNS": "200"})


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


class TestValidConfig:
    def test_every_check_passes(self, tmp_path: Path) -> None:
        findings = validate_config(_write(tmp_path / "c.yaml", VALID_CONFIG))

        assert error_count(findings) == 0
        assert warning_count(findings) == 0
        assert [f.name for f in findings] == [
            _CHECK_FILE,
            _CHECK_YAML,
            _CHECK_KEYS,
            _CHECK_SECTIONS,
            _CHECK_FIELDS,
            _CHECK_LOADER,
            _CHECK_POLICY,
            _CHECK_RULES,
        ]

    def test_rule_count_is_computed_not_assumed(self, tmp_path: Path) -> None:
        findings = validate_config(_write(tmp_path / "c.yaml", VALID_CONFIG))
        detail = _details(findings, _CHECK_RULES)

        # Whatever the built-in pack currently holds, it is a real count read
        # off the loaded engine — never a number baked into this command.
        match = re.search(r"(\d+) rule\(s\) from (\d+) pack\(s\)", detail)
        assert match is not None
        assert int(match.group(1)) > 0
        assert int(match.group(2)) > 0

    def test_cli_exits_zero_and_reports_pass(self, tmp_path: Path) -> None:
        result = _run(_write(tmp_path / "c.yaml", VALID_CONFIG))

        assert result.exit_code == 0
        assert "overall: PASS" in _flat(result.output)


# ---------------------------------------------------------------------
# The regression this command exists for
# ---------------------------------------------------------------------


class TestSilentFallback:
    def test_non_mapping_section_is_an_error(self, tmp_path: Path) -> None:
        findings = validate_config(_write(tmp_path / "c.yaml", "detector: yes\n"))

        assert _statuses(findings, _CHECK_SECTIONS) == ["fail"]
        assert "silently fall back" in _details(findings, _CHECK_SECTIONS)
        assert error_count(findings) == 1

    def test_the_loader_itself_still_accepts_it(self, tmp_path: Path) -> None:
        # This is the whole justification for check 4: the loader shrugs,
        # so the validator has to be the one to object.
        findings = validate_config(_write(tmp_path / "c.yaml", "detector: yes\n"))

        assert _statuses(findings, _CHECK_LOADER) == ["pass"]
        assert "detector off" in _details(findings, _CHECK_LOADER)

    def test_nested_llm_section_is_covered_too(self, tmp_path: Path) -> None:
        config = "detector:\n  enabled: true\n  llm: yes\n"
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_SECTIONS) == ["fail"]
        assert "detector.llm" in _details(findings, _CHECK_SECTIONS)

    def test_cli_exits_one_and_names_the_silent_fallback(self, tmp_path: Path) -> None:
        result = _run(_write(tmp_path / "c.yaml", "detector: yes\n"))

        assert result.exit_code == 1
        output = _flat(result.output)
        assert "silently fall back" in output
        assert "overall: FAIL (1 error)" in output


# ---------------------------------------------------------------------
# File and YAML
# ---------------------------------------------------------------------


class TestFileAndYaml:
    def test_missing_file_fails_and_skips_the_rest(self, tmp_path: Path) -> None:
        findings = validate_config(tmp_path / "absent.yaml")

        assert _statuses(findings, _CHECK_FILE) == ["fail"]
        assert all(f.status == "skip" for f in findings[1:])
        assert error_count(findings) == 1

    def test_directory_is_not_a_config_file(self, tmp_path: Path) -> None:
        findings = validate_config(tmp_path)

        assert _statuses(findings, _CHECK_FILE) == ["fail"]
        assert "directory" in _details(findings, _CHECK_FILE)

    def test_broken_syntax_fails_and_skips_dependents(self, tmp_path: Path) -> None:
        broken = "detector:\n  enabled: true\n    bad indent: 1\n"
        findings = validate_config(_write(tmp_path / "c.yaml", broken))

        assert _statuses(findings, _CHECK_YAML) == ["fail"]
        assert _statuses(findings, _CHECK_KEYS) == ["skip"]
        assert _statuses(findings, _CHECK_RULES) == ["skip"]
        # Skips are neither errors nor warnings — one problem, one error.
        assert error_count(findings) == 1
        assert warning_count(findings) == 0

    def test_broken_syntax_exits_one(self, tmp_path: Path) -> None:
        broken = "detector:\n  enabled: true\n    bad indent: 1\n"
        result = _run(_write(tmp_path / "c.yaml", broken))

        assert result.exit_code == 1
        assert "parse failed" in _flat(result.output)

    def test_non_mapping_top_level_fails(self, tmp_path: Path) -> None:
        findings = validate_config(_write(tmp_path / "c.yaml", "- one\n- two\n"))

        assert _statuses(findings, _CHECK_YAML) == ["fail"]
        assert "not a mapping" in _details(findings, _CHECK_YAML)

    def test_empty_file_warns_rather_than_fails(self, tmp_path: Path) -> None:
        findings = validate_config(_write(tmp_path / "c.yaml", ""))

        assert _statuses(findings, _CHECK_YAML) == ["warn"]
        assert error_count(findings) == 0


# ---------------------------------------------------------------------
# Unknown top-level keys
# ---------------------------------------------------------------------


class TestTopLevelKeys:
    def test_typo_warns_and_suggests_the_real_section(self, tmp_path: Path) -> None:
        findings = validate_config(_write(tmp_path / "c.yaml", "detctor:\n  enabled: true\n"))

        assert _statuses(findings, _CHECK_KEYS) == ["warn"]
        assert "did you mean 'detector'" in _details(findings, _CHECK_KEYS)
        assert error_count(findings) == 0

    def test_typo_exits_zero(self, tmp_path: Path) -> None:
        result = _run(_write(tmp_path / "c.yaml", "detctor:\n  enabled: true\n"))

        assert result.exit_code == 0
        output = _flat(result.output)
        assert "WARN" in output
        assert "overall: PASS (1 warning)" in output

    def test_documented_but_unread_section_warns_on_its_own_terms(self, tmp_path: Path) -> None:
        findings = validate_config(_write(tmp_path / "c.yaml", 'logging:\n  level: "DEBUG"\n'))

        assert _statuses(findings, _CHECK_KEYS) == ["warn"]
        assert "no effect" in _details(findings, _CHECK_KEYS)

    def test_one_warning_row_per_unknown_key(self, tmp_path: Path) -> None:
        config = "detctor:\n  enabled: true\nstorge:\n  queue_max: 1\n"
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_KEYS) == ["warn", "warn"]
        assert warning_count(findings) == 2


# ---------------------------------------------------------------------
# Numeric field types
# ---------------------------------------------------------------------


class TestFieldTypes:
    @pytest.mark.parametrize(
        ("value", "expected_phrase"),
        [
            ('"1s"', "raises ValueError"),
            ("true", "silently coerces it to 1"),
            ("1.9", "silently truncates"),
            ("[1, 2]", "raises TypeError"),
            ("null", "raises TypeError"),
        ],
    )
    def test_bad_numeric_value_is_an_error(
        self, tmp_path: Path, value: str, expected_phrase: str
    ) -> None:
        config = f"detector:\n  llm:\n    timeout_ms: {value}\n"
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_FIELDS) == ["fail"]
        detail = _details(findings, _CHECK_FIELDS)
        assert "detector.llm.timeout_ms" in detail
        assert expected_phrase in detail

    @pytest.mark.parametrize("value", ["1000", '"1000"', "0"])
    def test_values_the_loader_handles_cleanly_pass(self, tmp_path: Path, value: str) -> None:
        config = f"detector:\n  llm:\n    timeout_ms: {value}\n"
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_FIELDS) == ["pass"]

    def test_float_field_accepts_an_int(self, tmp_path: Path) -> None:
        config = "detector:\n  short_circuit_threshold: 1\n"
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_FIELDS) == ["pass"]

    def test_loader_row_is_skipped_so_one_mistake_counts_once(self, tmp_path: Path) -> None:
        # The loader would raise the same ValueError; reporting it twice would
        # inflate the error count for a single typo.
        config = "detector:\n  llm:\n    timeout_ms: '1s'\n"
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_LOADER) == ["skip"]
        assert error_count(findings) == 1


# ---------------------------------------------------------------------
# The real loader
# ---------------------------------------------------------------------


class TestLoader:
    def test_capability_allowlist_error_is_reported(self, tmp_path: Path) -> None:
        config = 'capability:\n  allowed_tools: "fs.read"\n'
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_LOADER) == ["fail"]
        assert "must be a list" in _details(findings, _CHECK_LOADER)
        assert _statuses(findings, _CHECK_POLICY) == ["skip"]
        assert _statuses(findings, _CHECK_RULES) == ["skip"]

    def test_bad_allowlist_entry_is_reported(self, tmp_path: Path) -> None:
        config = "capability:\n  allowed_tools:\n    - not_namespaced\n"
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_LOADER) == ["fail"]
        assert "not_namespaced" in _details(findings, _CHECK_LOADER)

    def test_type_error_from_the_loader_does_not_escape(self, tmp_path: Path) -> None:
        # Path([1]) raises TypeError, not ValueError — the validator must
        # still report it as a finding rather than blow up with a traceback.
        findings = validate_config(_write(tmp_path / "c.yaml", "storage:\n  db_path: [1]\n"))

        assert _statuses(findings, _CHECK_LOADER) == ["fail"]
        assert "TypeError" in _details(findings, _CHECK_LOADER)


# ---------------------------------------------------------------------
# Policy file
# ---------------------------------------------------------------------


class TestPolicyFile:
    def test_missing_policy_file_is_an_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "policies.yaml"
        config = f'detector:\n  policies_file: "{missing}"\n'
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_POLICY) == ["fail"]
        assert "not found" in _details(findings, _CHECK_POLICY)

    def test_missing_policy_file_exits_one(self, tmp_path: Path) -> None:
        missing = tmp_path / "policies.yaml"
        config = f'detector:\n  policies_file: "{missing}"\n'
        result = _run(_write(tmp_path / "c.yaml", config))

        assert result.exit_code == 1

    def test_malformed_policy_file_is_an_error(self, tmp_path: Path) -> None:
        policy = _write(tmp_path / "policies.yaml", "default: nonsense\nrules: []\n")
        config = f'detector:\n  policies_file: "{policy}"\n'
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_POLICY) == ["fail"]
        assert "invalid default action" in _details(findings, _CHECK_POLICY)

    def test_valid_policy_file_passes_with_its_rule_count(self, tmp_path: Path) -> None:
        policy = _write(tmp_path / "policies.yaml", VALID_POLICY)
        config = f'detector:\n  policies_file: "{policy}"\n'
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_POLICY) == ["pass"]
        assert "1 rule(s)" in _details(findings, _CHECK_POLICY)


# ---------------------------------------------------------------------
# Rule packs
# ---------------------------------------------------------------------


class TestRulePacks:
    def test_missing_rules_dir_is_an_error(self, tmp_path: Path) -> None:
        config = f'detector:\n  rules_dir: "{tmp_path / "no-such-dir"}"\n'
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_RULES) == ["fail"]

    def test_broken_pack_is_an_error(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        _write(rules_dir / "bad.yaml", "rules:\n  - id: x\n    pattern: '('\n    score: 0.5\n")
        config = f'detector:\n  rules_dir: "{rules_dir}"\n'
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_RULES) == ["fail"]
        assert "bulwark rules lint" in (_rows(findings, _CHECK_RULES)[0].suggestion or "")


# ---------------------------------------------------------------------
# All findings, not just the first
# ---------------------------------------------------------------------


class TestCollectsEveryFinding:
    def test_two_independent_errors_are_both_reported(self, tmp_path: Path) -> None:
        missing = tmp_path / "policies.yaml"
        config = f'storage: "nope"\ndetector:\n  policies_file: "{missing}"\n'
        findings = validate_config(_write(tmp_path / "c.yaml", config))

        assert _statuses(findings, _CHECK_SECTIONS) == ["fail"]
        assert _statuses(findings, _CHECK_POLICY) == ["fail"]
        assert error_count(findings) == 2

    def test_cli_counts_both_in_the_overall_line(self, tmp_path: Path) -> None:
        missing = tmp_path / "policies.yaml"
        config = f'storage: "nope"\ndetector:\n  policies_file: "{missing}"\n'
        result = _run(_write(tmp_path / "c.yaml", config))

        assert result.exit_code == 1
        output = _flat(result.output)
        assert "silently fall back" in output
        assert "not found" in output
        assert "overall: FAIL (2 errors)" in output

    def test_errors_and_warnings_are_counted_separately(self, tmp_path: Path) -> None:
        config = "detector: yes\ndetctor:\n  enabled: true\n"
        result = _run(_write(tmp_path / "c.yaml", config))

        assert result.exit_code == 1
        assert "overall: FAIL (1 error, 1 warning)" in _flat(result.output)


# ---------------------------------------------------------------------
# Environment isolation — the named file is the only input
# ---------------------------------------------------------------------


class TestEnvironmentIsolation:
    def test_bulwark_config_cannot_redirect_the_validation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        decoy = _write(tmp_path / "decoy.yaml", VALID_CONFIG)
        target = _write(tmp_path / "target.yaml", "detector: yes\n")
        monkeypatch.setenv(ENV_CONFIG, str(decoy))

        findings = validate_config(target)

        assert _statuses(findings, _CHECK_SECTIONS) == ["fail"]
        assert os.environ[ENV_CONFIG] == str(decoy)

    def test_bulwark_db_does_not_shadow_the_files_db_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from_env = tmp_path / "from-env.db"
        from_file = tmp_path / "from-file.db"
        monkeypatch.setenv(ENV_DB, str(from_env))
        config = f'storage:\n  db_path: "{from_file}"\n'

        findings = validate_config(_write(tmp_path / "c.yaml", config))

        detail = _details(findings, _CHECK_LOADER)
        assert "from-file.db" in detail
        assert "from-env.db" not in detail
        assert os.environ[ENV_DB] == str(from_env)

    def test_environment_is_restored_even_when_the_loader_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_CONFIG, "/does/not/matter.yaml")
        monkeypatch.setenv(ENV_DB, "/does/not/matter.db")
        config = 'capability:\n  allowed_tools: "fs.read"\n'

        validate_config(_write(tmp_path / "c.yaml", config))

        assert os.environ[ENV_CONFIG] == "/does/not/matter.yaml"
        assert os.environ[ENV_DB] == "/does/not/matter.db"


# ---------------------------------------------------------------------
# Drift guard
# ---------------------------------------------------------------------


class TestKnownSections:
    def test_known_sections_match_what_the_loader_reads(self) -> None:
        # If resolve_settings() grows a section, this fails until
        # KNOWN_SECTIONS learns about it — otherwise the new section would be
        # reported as an unknown-key typo.
        source = inspect.getsource(config_module.resolve_settings)
        read_by_loader = set(re.findall(r'file_data\.get\("([^"]+)"', source))

        assert read_by_loader == set(KNOWN_SECTIONS)
