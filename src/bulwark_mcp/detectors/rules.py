# ruff: noqa: RUF001, RUF002 — Cyrillic/Greek homoglyphs are the file's purpose
"""YAML-driven rules detector (ADR-0004 §2).

A rule pack is a YAML file with this shape::

    rules:
      - id: role_hijack.ignore_previous
        description: "'Ignore previous instructions' family"
        pattern: '(?i)ignore\\s+(?:all\\s+)?previous\\s+instructions?'
        score: 0.85
        apply_to: [server_to_client]
        source: "https://simonwillison.net/..."

The loader compiles every regex up front so detection itself does no
parsing. A single :class:`RulesEngine` is shared by all directions; per
call we filter by ``apply_to`` so c2s frames never run s2c-only patterns
and vice versa.
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, get_args

import yaml

from .base import Direction, RulesResult

# Unicode characters that are commonly used to obfuscate prompt-injection
# payloads. Stripped during normalisation so a payload like
# "i​g​nore previous" still matches `(?i)ignore\s+previous`.
# Includes zero-width spaces, RTL/LTR marks, BOM, soft hyphen, and the
# whole TAG block (U+E0000-U+E007F) which is invisible to humans.
_INVISIBLE_CHARS_RE = re.compile(
    r"["
    r"­"  # soft hyphen
    r"​-‏"  # zero-width spaces, LRM, RLM
    r"‪-‮"  # bidi overrides
    r"⁠-⁤"  # word joiner, invisible operators
    r"⁦-⁩"  # bidi isolates
    r"﻿"  # BOM
    r"\U000e0000-\U000e007f"  # TAG characters
    r"]"
)

# Cross-script homoglyph fold (Week-4 audit fix).
#
# A compact mapping of the highest-impact look-alikes from Cyrillic and
# Greek that NFKC keeps separate by design. Shipping the full Unicode
# `confusables.txt` would be ~10 MB of data — for v0.4 we hand-pick the
# ~40 letters that actually appear in published prompt-injection PoCs.
# Add a confusable in a community PR if your locale needs it.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lowercase → Latin
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "ѕ": "s",
    # Cyrillic uppercase → Latin
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "У": "Y",
    "Х": "X",
    "І": "I",
    "Ј": "J",
    # Greek lowercase → Latin
    "α": "a",
    "ε": "e",
    "ι": "i",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "ν": "v",
    "χ": "x",
    # Greek uppercase → Latin
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


def _fold_homoglyphs(text: str) -> str:
    """Replace common cross-script look-alikes with their Latin counterparts."""
    return text.translate(_HOMOGLYPH_TABLE)


logger = logging.getLogger(__name__)

_VALID_DIRECTIONS: frozenset[str] = frozenset(get_args(Direction))


@dataclass(frozen=True)
class CompiledRule:
    id: str
    description: str
    pattern: re.Pattern[str]
    score: float
    apply_to: tuple[Direction, ...]
    source: str | None = None


class RulesEngine:
    """In-memory bag of compiled rules.

    Construction is the only point that may raise. Detection itself is
    pure CPU work and never throws — at worst it returns an empty result.
    """

    def __init__(self, rules: Iterable[CompiledRule]) -> None:
        self._rules: tuple[CompiledRule, ...] = tuple(rules)

    @property
    def rules(self) -> tuple[CompiledRule, ...]:
        return self._rules

    def __len__(self) -> int:
        return len(self._rules)

    @classmethod
    def from_directory(cls, directory: Path) -> RulesEngine:
        """Load every ``*.yaml`` under ``directory`` recursively."""
        directory = Path(directory)
        if not directory.is_dir():
            raise FileNotFoundError(f"rules directory not found: {directory}")
        compiled: list[CompiledRule] = []
        seen_ids: set[str] = set()
        for yaml_file in sorted(directory.rglob("*.yaml")):
            for rule in _load_pack(yaml_file):
                if rule.id in seen_ids:
                    raise ValueError(f"duplicate rule id {rule.id!r} (last seen in {yaml_file})")
                seen_ids.add(rule.id)
                compiled.append(rule)
        logger.info("rules: loaded %d rules from %s", len(compiled), directory)
        return cls(compiled)

    def detect(self, text: str, *, direction: Direction) -> RulesResult:
        """Scan ``text`` and return matching rule ids + the max score.

        Three-pass scan (Week-3 audit fix). Each applicable rule is
        evaluated against three views of the input:

        1. **Raw** — preserves Week-2 behaviour for Unicode-shaped
           rules like ``unicode.zero_width_run`` and
           ``unicode.tag_chars`` that *want* to see the obfuscation.
        2. **Within-word normalised** — NFKC + invisible chars
           **removed**. Catches char-level obfuscation: ``I​gnore``
           (zero-width inside the word) → ``Ignore``, fires
           ``role_hijack.ignore_previous``.
        3. **Between-word normalised** — NFKC + invisible chars
           replaced with a space + whitespace runs collapsed.
           Catches word-boundary obfuscation: ``Ignore​all`` →
           ``Ignore all``, fires the same rule.

        Hits from any pass are unioned; the score is the max.
        Dropping any one pass leaves a real evasion path open — see
        ``tests/test_detectors_rules.py::TestNormalisationBypass`` for
        the canonical examples.

        Cost: ~0.05 ms p95 for the raw pass + ~0.03 ms for the two
        normalised forms. Total budget for rules is still well under
        the 5 ms ADR-0004 §7 ceiling.
        """
        if not text:
            return RulesResult()
        if direction == "client_to_server":
            # Argv-style array arguments serialise without spaces between
            # tokens (["rm","-rf","/"] → "rm","-rf","/"), evading the
            # whitespace-dependent shell patterns. Surface them to the regex
            # as a space-joined string; the original frame is unchanged.
            extra = _extract_arguments_text(text)
            if extra:
                text = f"{text} {extra}"
        within = _normalise_within_word(text)
        between = _normalise_between_word(text)
        # Distinct passes only — most benign text yields three identical
        # strings, in which case we collapse to one regex run per rule.
        passes: tuple[str, ...] = tuple(
            dict.fromkeys((text, within, between))  # preserves order, dedupes
        )
        hits: list[str] = []
        seen: set[str] = set()
        max_score = 0.0
        for rule in self._rules:
            if direction not in rule.apply_to:
                continue
            for variant in passes:
                if rule.pattern.search(variant):
                    if rule.id not in seen:
                        hits.append(rule.id)
                        seen.add(rule.id)
                    if rule.score > max_score:
                        max_score = rule.score
                    break  # one match is enough; don't double-count
        return RulesResult(hits=tuple(hits), score=max_score)


def _normalise_within_word(text: str) -> str:
    """NFKC + homoglyph fold + drop invisible / formatting chars.

    Used to catch attackers who place zero-width or TAG characters
    *inside* a keyword (``I\\u200bgnore`` → ``Ignore``) AND attackers who
    swap individual letters for cross-script look-alikes (Cyrillic
    ``Ѕgnore`` → ``Sgnore`` after homoglyph fold; the rule still has
    to match this exactly, hence the additional NFKC pass).
    """
    folded = _fold_homoglyphs(unicodedata.normalize("NFKC", text))
    return _INVISIBLE_CHARS_RE.sub("", folded)


_WHITESPACE_RUN_RE = re.compile(r"\s+")


def _normalise_between_word(text: str) -> str:
    """NFKC + homoglyph fold + replace invisibles with space + collapse runs.

    Used to catch attackers who use zero-width or TAG characters
    *between* words: ``Ignore\\u200ball`` → ``Ignore all``. Homoglyph
    folding happens here too so ``Іgnore все instructions`` (Cyrillic
    ``І``, Cyrillic ``все``) collapses through this pass.
    """
    folded = _fold_homoglyphs(unicodedata.normalize("NFKC", text))
    spaced = _INVISIBLE_CHARS_RE.sub(" ", folded)
    return _WHITESPACE_RUN_RE.sub(" ", spaced)


def _extract_arguments_text(frame_text: str) -> str:
    """Closes c2s shell-rule evasion via argv-style array arguments
    (pre-fix: list-form ``rm -rf /`` passed with score 0.0).

    For a client_to_server ``tools/call`` request, walk ``params.arguments``
    and return every nested array's string elements joined with single
    spaces. The caller appends this to the text fed to the regex pass so
    ``["rm","-rf","/"]`` is scanned as ``rm -rf /``; the original frame is
    never modified. Returns ``""`` for non-``tools/call`` frames,
    unparseable frames, or arguments with no string arrays.

    Scope is deliberately narrow — ONLY ``params.arguments`` of a
    ``tools/call`` request. Arrays elsewhere in the frame are left alone.
    """
    try:
        payload = json.loads(frame_text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return ""
    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        return ""
    params = payload.get("params")
    if not isinstance(params, dict):
        return ""
    arguments = params.get("arguments")
    if arguments is None:
        return ""
    chunks: list[str] = []
    try:
        _collect_array_strings(arguments, chunks)
    except RecursionError:
        # Arguments nested past the interpreter's recursion limit overflow the
        # recursive walk. detect() has no guard and Inspector.inspect() calls
        # it outside its try, so an escaping RecursionError would crash the c2s
        # pump. Degrade to "no argument text extracted" instead of raising.
        return ""
    return " ".join(chunks)


def _collect_array_strings(node: Any, chunks: list[str]) -> None:
    """Recursively gather the string elements of any array nested in
    ``node``, appending each array's space-join to ``chunks``.

    Dicts are recursed into (never coerced to strings); non-string scalars
    inside arrays are ignored; arrays of dicts are recursed element-wise.

    Deliberately array-only: scalar dict values are NOT collected. Folding them
    in would let a command split across fields (``{"cmd":"rm","args":["-rf",
    "/"]}``) reassemble and fire the shell rules (audit #9) — but it would
    equally join legitimately separate fields (``{"keep":["rm"],"flags":
    ["-rf","/"]}``) into a phantom ``rm -rf /`` and raise a false positive
    (audit #14). Argv-regex cannot reconcile the two, so this stays array-only;
    the reliable control against dangerous tool calls is the capability
    allowlist (blocks by tool name, not argument content). The limit is pinned
    by ``tests/test_detectors_rules.py::TestArgvShellDetectionLimits``.
    """
    if isinstance(node, dict):
        for value in node.values():
            _collect_array_strings(value, chunks)
    elif isinstance(node, list):
        strings = [element for element in node if isinstance(element, str)]
        if strings:
            chunks.append(" ".join(strings))
        for element in node:
            if isinstance(element, dict | list):
                _collect_array_strings(element, chunks)


def _load_pack(path: Path) -> list[CompiledRule]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected mapping at top level")
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"{path}: 'rules' must be a list")
    return [_compile_rule(path, rule) for rule in raw_rules]


def _compile_rule(source_file: Path, raw: Any) -> CompiledRule:
    if not isinstance(raw, dict):
        raise ValueError(f"{source_file}: each rule must be a mapping")

    rule_id = _required_str(raw, "id", source_file)
    pattern_str = _required_str(raw, "pattern", source_file)
    description = str(raw.get("description", ""))

    score_raw = raw.get("score", 0.5)
    try:
        score = float(score_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{source_file}: rule {rule_id!r} score must be a number") from exc
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"{source_file}: rule {rule_id!r} score {score} outside [0.0, 1.0]")

    apply_to_raw = raw.get("apply_to", ["server_to_client"])
    if isinstance(apply_to_raw, str):
        apply_to_raw = [apply_to_raw]
    if not isinstance(apply_to_raw, list):
        raise ValueError(f"{source_file}: rule {rule_id!r} apply_to must be a string or list")
    bad = [d for d in apply_to_raw if d not in _VALID_DIRECTIONS]
    if bad:
        raise ValueError(f"{source_file}: rule {rule_id!r} apply_to has unknown directions: {bad}")
    apply_to: tuple[Direction, ...] = tuple(apply_to_raw)

    try:
        pattern = re.compile(pattern_str, re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"{source_file}: rule {rule_id!r} pattern invalid: {exc}") from exc

    source = raw.get("source")
    return CompiledRule(
        id=rule_id,
        description=description,
        pattern=pattern,
        score=score,
        apply_to=apply_to,
        source=str(source) if source is not None else None,
    )


def _required_str(mapping: dict[str, Any], key: str, source_file: Path) -> str:
    if key not in mapping:
        raise ValueError(f"{source_file}: rule missing required field {key!r}")
    value = mapping[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source_file}: rule field {key!r} must be a non-empty string")
    return value
