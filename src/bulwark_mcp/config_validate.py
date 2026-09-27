"""bulwark config-validate — static validation of a config file.

Why this exists as a separate pass rather than "call the loader and see
if it throws": :func:`bulwark_mcp.config.resolve_settings` is deliberately
forgiving. A section that is not a mapping is replaced with ``{}``::

    detector_section = file_data.get("detector", {}) ...
    if not isinstance(detector_section, dict):
        detector_section = {}

So ``detector: yes`` loads without a murmur and the firewall stays OFF
while the author believes they turned it on. Unknown top-level keys
(``detctor:``) are ignored for the same reason. A validator that only
wrapped the loader would print PASS on exactly those files.

This module therefore runs its own checks *first* and then additionally
calls the real loader to pick up the errors it does raise (capability
allowlist shape, unparseable numbers, …). It never changes the loader:
the proxy's startup contract is out of scope here.

Check order — each one may skip its dependents:

1. the file exists and is readable;
2. the YAML parses and the top level is a mapping;
3. top-level keys are sections the loader actually reads (WARN otherwise);
4. every known section present is a mapping (ERROR otherwise — this is
   the silent-fallback case above);
5. numeric fields hold numbers (the loader raises on *some* of these and
   silently coerces others — see :func:`_numeric_problem`);
6. the real loader runs without raising;
7. a referenced ``detector.policies_file`` exists and parses;
8. the rule packs load, with the real rule count.

Checks 7 and 8 reuse the loaders behind ``bulwark doctor`` and
``bulwark rules lint`` — nothing about policy or rule parsing is
reimplemented here.
"""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from .config import ENV_CONFIG, ENV_DB, Settings, resolve_settings
from .detectors.rules import RulesEngine
from .lint import lint_path
from .policy import Policy

FindingStatus = Literal["pass", "warn", "fail", "skip"]

# Top-level sections ``resolve_settings`` actually reads. Kept in sync with
# config.py by ``tests/test_config_validate.py::TestKnownSections``, which
# re-derives this set from the loader's source.
KNOWN_SECTIONS: tuple[str, ...] = ("storage", "detector", "capability")

# Section names the loader never reads (may linger in older configs). Worth a
# WARN of its own: the values look live and are not.
INERT_SECTIONS: tuple[str, ...] = ("logging",)

# Sections (including nested ones) that the loader replaces with ``{}``
# when they are not mappings.
_MAPPING_SECTIONS: tuple[tuple[str, ...], ...] = (
    ("storage",),
    ("detector",),
    ("capability",),
    ("detector", "llm"),
)

# Fields the loader pushes through ``int()`` / ``float()``.
_NUMERIC_FIELDS: tuple[tuple[tuple[str, ...], str, Literal["int", "float"]], ...] = (
    (("storage",), "queue_max", "int"),
    (("storage",), "batch_size", "int"),
    (("storage",), "batch_interval_ms", "int"),
    (("detector",), "max_latency_ms", "int"),
    (("detector",), "short_circuit_threshold", "float"),
    (("detector", "llm"), "timeout_ms", "int"),
    (("detector", "llm"), "cache_ttl_s", "int"),
    (("detector", "llm"), "circuit_threshold", "int"),
    (("detector", "llm"), "circuit_open_s", "int"),
)

_CHECK_FILE = "Config file"
_CHECK_YAML = "YAML syntax"
_CHECK_KEYS = "Top-level keys"
_CHECK_SECTIONS = "Section types"
_CHECK_FIELDS = "Field types"
_CHECK_LOADER = "Config loader"
_CHECK_POLICY = "Policy file"
_CHECK_RULES = "Rule packs"

# Display order, used to emit SKIP rows for whatever a failed check makes
# impossible.
_AFTER_FILE = (
    _CHECK_YAML,
    _CHECK_KEYS,
    _CHECK_SECTIONS,
    _CHECK_FIELDS,
    _CHECK_LOADER,
    _CHECK_POLICY,
    _CHECK_RULES,
)
_AFTER_YAML = _AFTER_FILE[1:]


@dataclass(frozen=True)
class Finding:
    """One row of the report. ``skip`` counts as neither error nor warning."""

    name: str
    status: FindingStatus
    detail: str
    suggestion: str | None = None


def validate_config(path: Path) -> list[Finding]:
    """Validate the config file at ``path`` and return every finding.

    Never raises: a validator that crashes on a malformed file is useless.
    Findings are returned in display order, all of them — the caller decides
    how to render and how to exit.
    """
    path = Path(path)
    findings: list[Finding] = []

    file_finding, text = _check_file(path)
    findings.append(file_finding)
    if text is None:
        return findings + _skips(_AFTER_FILE, "the config file could not be read")

    yaml_finding, data = _check_yaml(text)
    findings.append(yaml_finding)
    if data is None:
        return findings + _skips(_AFTER_YAML, "the YAML did not parse into a mapping")

    findings.extend(_check_top_level_keys(data))
    findings.extend(_check_section_types(data))

    field_findings = _check_field_types(data)
    findings.extend(field_findings)
    field_errors = any(f.status == "fail" for f in field_findings)

    settings, load_error = _load(path)
    if field_errors:
        findings.append(
            Finding(
                name=_CHECK_LOADER,
                status="skip",
                detail="skipped — fix the field types above first",
            )
        )
    elif load_error is not None:
        findings.append(
            Finding(
                name=_CHECK_LOADER,
                status="fail",
                detail=f"{type(load_error).__name__}: {_one_line(load_error)}",
                suggestion=(
                    "This error comes from resolve_settings() itself — the proxy "
                    "would refuse to start with this file."
                ),
            )
        )
    else:
        findings.append(_loader_pass(settings))

    if settings is None:
        reason = "the config did not load"
        findings.extend(_skips((_CHECK_POLICY, _CHECK_RULES), reason))
        return findings

    findings.append(_check_policy(settings))
    findings.append(_check_rules(settings))
    return findings


def error_count(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.status == "fail")


def warning_count(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.status == "warn")


# ---------------------------------------------------------------------
# 1. File
# ---------------------------------------------------------------------


def _check_file(path: Path) -> tuple[Finding, str | None]:
    if path.is_dir():
        return (
            Finding(
                name=_CHECK_FILE,
                status="fail",
                detail=f"{path} is a directory, not a file",
            ),
            None,
        )
    if not path.exists():
        return (
            Finding(
                name=_CHECK_FILE,
                status="fail",
                detail=f"no such file: {path}",
                suggestion=(
                    "Pass the path to an existing YAML file. "
                    "Note that the proxy treats a missing config file as an "
                    "empty one and starts with built-in defaults."
                ),
            ),
            None,
        )
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return (
            Finding(
                name=_CHECK_FILE,
                status="fail",
                detail=f"{path} is not valid UTF-8 ({_one_line(exc)})",
            ),
            None,
        )
    except OSError as exc:
        return (
            Finding(
                name=_CHECK_FILE,
                status="fail",
                detail=f"cannot read {path} ({type(exc).__name__}: {_one_line(exc)})",
            ),
            None,
        )
    return Finding(name=_CHECK_FILE, status="pass", detail=f"readable: {path}"), text


# ---------------------------------------------------------------------
# 2. YAML
# ---------------------------------------------------------------------


def _check_yaml(text: str) -> tuple[Finding, dict[str, Any] | None]:
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return (
            Finding(
                name=_CHECK_YAML,
                status="fail",
                detail=f"parse failed — {_one_line(exc)}",
                suggestion="Fix the YAML syntax; no further check can run until it parses.",
            ),
            None,
        )
    if loaded is None:
        return (
            Finding(
                name=_CHECK_YAML,
                status="warn",
                detail="file is empty — every setting falls back to its built-in default",
            ),
            {},
        )
    if not isinstance(loaded, dict):
        return (
            Finding(
                name=_CHECK_YAML,
                status="fail",
                detail=f"top level is a {type(loaded).__name__}, not a mapping",
                suggestion=(
                    "The file must start with section keys such as `storage:` or `detector:`."
                ),
            ),
            None,
        )
    return (
        Finding(
            name=_CHECK_YAML,
            status="pass",
            detail=f"parses; {len(loaded)} top-level key(s)",
        ),
        loaded,
    )


# ---------------------------------------------------------------------
# 3. Top-level keys
# ---------------------------------------------------------------------


def _check_top_level_keys(data: dict[str, Any]) -> list[Finding]:
    unknown = [key for key in data if key not in KNOWN_SECTIONS]
    if not unknown:
        return [
            Finding(
                name=_CHECK_KEYS,
                status="pass",
                detail=f"all {len(data)} key(s) are sections the loader reads",
            )
        ]
    findings: list[Finding] = []
    for key in unknown:
        if key in INERT_SECTIONS:
            findings.append(
                Finding(
                    name=_CHECK_KEYS,
                    status="warn",
                    detail=(f"'{key}' is not read by the loader — anything under it has no effect"),
                )
            )
            continue
        close = difflib.get_close_matches(str(key), KNOWN_SECTIONS, n=1, cutoff=0.6)
        hint = f" — did you mean '{close[0]}'?" if close else ""
        findings.append(
            Finding(
                name=_CHECK_KEYS,
                status="warn",
                detail=f"unknown key '{key}', silently ignored by the loader{hint}",
                suggestion=(
                    f"Known sections: {', '.join(KNOWN_SECTIONS)}. A typo here is "
                    "not an error at runtime — the setting simply never applies."
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------
# 4. Section types — the silent-fallback case
# ---------------------------------------------------------------------


def _check_section_types(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    checked: list[str] = []
    for section in _MAPPING_SECTIONS:
        parent = _parent_of(data, section)
        if parent is None or section[-1] not in parent:
            continue
        dotted = ".".join(section)
        value = parent[section[-1]]
        if isinstance(value, dict):
            checked.append(dotted)
            continue
        findings.append(
            Finding(
                name=_CHECK_SECTIONS,
                status="fail",
                detail=(
                    f"'{dotted}' is a {type(value).__name__} ({value!r}), not a mapping — "
                    f"the runtime would silently fall back to defaults for this whole section"
                ),
                suggestion=(
                    f"Write `{dotted}:` followed by an indented block of keys. As written, "
                    f"resolve_settings() replaces the section with {{}} and raises nothing, "
                    "so the proxy starts with settings you did not choose."
                ),
            )
        )
    if findings:
        return findings
    if not checked:
        return [Finding(name=_CHECK_SECTIONS, status="pass", detail="no known section present")]
    return [
        Finding(
            name=_CHECK_SECTIONS,
            status="pass",
            detail=f"mappings: {', '.join(checked)}",
        )
    ]


# ---------------------------------------------------------------------
# 5. Field types
# ---------------------------------------------------------------------


def _check_field_types(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    checked = 0
    for section, field, expected in _NUMERIC_FIELDS:
        parent = _parent_of(data, (*section, field))
        if parent is None or field not in parent:
            continue
        checked += 1
        problem = _numeric_problem(parent[field], expected)
        if problem is None:
            continue
        dotted = ".".join((*section, field))
        findings.append(
            Finding(
                name=_CHECK_FIELDS,
                status="fail",
                detail=f"{dotted} {problem}",
                suggestion=f"Give {dotted} a plain unquoted {expected} value.",
            )
        )
    if findings:
        return findings
    detail = (
        f"{checked} numeric field(s) present and well-typed"
        if checked
        else "no numeric field set; built-in defaults apply"
    )
    return [Finding(name=_CHECK_FIELDS, status="pass", detail=detail)]


def _numeric_problem(value: Any, expected: Literal["int", "float"]) -> str | None:
    """Describe what the loader does with ``value``, or None when it is fine.

    Three distinct behaviours, all worth reporting: a hard raise (the loader
    already rejects it), a silent truncation, and a silent bool→0/1 coercion.
    The last two never reach the user at runtime, which is the point.
    """
    if isinstance(value, bool):
        return f"is a bool ({value!r}); the loader silently coerces it to {int(value)}"
    if isinstance(value, int):
        return None
    if isinstance(value, float):
        if expected == "float":
            return None
        return f"is a float ({value!r}); the loader silently truncates it to an int"
    if isinstance(value, str):
        try:
            if expected == "int":
                int(value)
            else:
                float(value)
        except ValueError:
            return (
                f"is the string {value!r}, which is not a valid {expected}; "
                f"the loader raises ValueError"
            )
        return None
    return f"is a {type(value).__name__}; the loader raises TypeError"


# ---------------------------------------------------------------------
# 6. The real loader
# ---------------------------------------------------------------------


def _load(path: Path) -> tuple[Settings | None, Exception | None]:
    """Run ``resolve_settings`` against ``path`` and nothing else.

    ``BULWARK_CONFIG`` and ``BULWARK_DB`` are removed for the duration so
    the verdict describes the file the user named, not the environment the
    validator happens to run in. Single-threaded CLI use only.
    """
    saved = {name: os.environ.pop(name) for name in (ENV_CONFIG, ENV_DB) if name in os.environ}
    try:
        return resolve_settings(cli_config=path), None
    except Exception as exc:  # the loader raises ValueError and TypeError alike
        return None, exc
    finally:
        os.environ.update(saved)


def _loader_pass(settings: Settings | None) -> Finding:
    if settings is None:  # pragma: no cover — defensive; _load never returns (None, None)
        return Finding(name=_CHECK_LOADER, status="skip", detail="skipped")
    detector = "on" if settings.detector.enabled else "off"
    allowlist = len(settings.capability.allowed_tools)
    capability = f"{allowlist} tool(s) allowlisted" if allowlist else "fail-open (no allowlist)"
    return Finding(
        name=_CHECK_LOADER,
        status="pass",
        detail=(
            f"resolve_settings() accepts it — detector {detector}, "
            f"capability {capability}, db {settings.db_path}"
        ),
    )


# ---------------------------------------------------------------------
# 7. Policy file
# ---------------------------------------------------------------------


def _check_policy(settings: Settings) -> Finding:
    policies_file = settings.detector.policies_file
    if policies_file is None:
        return Finding(
            name=_CHECK_POLICY,
            status="pass",
            detail="detector.policies_file not set — the built-in policy is used",
        )
    try:
        policy = Policy.from_file(policies_file)
    except FileNotFoundError:
        return Finding(
            name=_CHECK_POLICY,
            status="fail",
            detail=f"detector.policies_file not found: {policies_file}",
            suggestion=(
                "Relative paths resolve against the working directory, not the "
                "config file — an absolute path is safer."
            ),
        )
    except Exception as exc:
        return Finding(
            name=_CHECK_POLICY,
            status="fail",
            detail=f"{policies_file}: {type(exc).__name__}: {_one_line(exc)}",
            suggestion="See docs/RUNBOOK.md → 'Authoring a custom policy' for the schema.",
        )
    return Finding(
        name=_CHECK_POLICY,
        status="pass",
        detail=(f"{policies_file}: {len(policy)} rule(s) over default '{policy.default}'"),
    )


# ---------------------------------------------------------------------
# 8. Rule packs
# ---------------------------------------------------------------------


def _check_rules(settings: Settings) -> Finding:
    rules_dir = settings.detector.rules_dir
    errors = [issue for issue in lint_path(rules_dir) if issue.severity == "error"]
    if errors:
        return Finding(
            name=_CHECK_RULES,
            status="fail",
            detail=f"{len(errors)} error(s) in {rules_dir}: {_one_line(errors[0].message)}",
            suggestion=f"Run `bulwark rules lint {rules_dir}` for the full list.",
        )
    try:
        engine = RulesEngine.from_directory(rules_dir)
    except Exception as exc:
        return Finding(
            name=_CHECK_RULES,
            status="fail",
            detail=f"rules loader raised {type(exc).__name__}: {_one_line(exc)}",
        )
    packs = sorted(Path(rules_dir).rglob("*.yaml"))
    names = ", ".join(pack.name for pack in packs)
    return Finding(
        name=_CHECK_RULES,
        status="pass",
        detail=f"{len(engine)} rule(s) from {len(packs)} pack(s) in {rules_dir} ({names})",
    )


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _parent_of(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Return the mapping that would hold ``path[-1]``, or None.

    None means an ancestor is absent or is not a mapping — either way the
    leaf is not something this check can speak about (a non-mapping ancestor
    is already reported by :func:`_check_section_types`).
    """
    node: Any = data
    for key in path[:-1]:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node if isinstance(node, dict) else None


def _skips(names: tuple[str, ...], reason: str) -> list[Finding]:
    return [Finding(name=name, status="skip", detail=f"skipped — {reason}") for name in names]


def _one_line(value: object) -> str:
    """Collapse a multi-line exception message (PyYAML loves those) to one line."""
    return " ".join(str(value).split())
