"""Tests for the capability filter (name-based tool allowlist).

Three layers of coverage:

1. **Unit** — :meth:`CapabilityFilter.check` decision/reason semantics,
   exact-match (no prefix, no case fold), and namespacing.
2. **Config** — the YAML ``capability:`` section parses, validates, rejects
   malformed ``<server>.<tool>`` names, and collapses duplicates.
3. **Proxy integration** — the real CLI in a subprocess (mirrors
   ``tests/test_proxy_block.py``): a not-allowlisted ``tools/call`` gets a
   ``-32603`` error, never reaches the server, and is audited as
   ``blocked_by_capability``; ``tools/list`` is untouched; capability
   composes with — and never overrides — the rules layer; and an empty
   allowlist emits the documented fail-open startup warning.

The LLM classifier is never involved; everything here is deterministic.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
import yaml

from bulwark_mcp.capability import CapabilityFilter, CapabilitySettings
from bulwark_mcp.config import resolve_settings
from bulwark_mcp.proxy import _scan_capability
from bulwark_mcp.storage import Storage

# ---------------------------------------------------------------------
# Unit: CapabilityFilter.check
# ---------------------------------------------------------------------


class TestCapabilityCheck:
    def test_empty_allowlist_is_fail_open(self) -> None:
        f = CapabilityFilter(CapabilitySettings())
        decision = f.check("filesystem.read")
        assert decision.allowed is True
        assert decision.reason == "no_allowlist"
        assert f.active is False

    def test_tool_present_is_allowed(self) -> None:
        f = CapabilityFilter(CapabilitySettings(allowed_tools=("filesystem.read",)))
        decision = f.check("filesystem.read")
        assert decision.allowed is True
        assert decision.reason == "in_allowlist"
        assert f.active is True

    def test_tool_absent_is_blocked(self) -> None:
        f = CapabilityFilter(CapabilitySettings(allowed_tools=("filesystem.read",)))
        decision = f.check("filesystem.write")
        assert decision.allowed is False
        assert decision.reason == "not_in_allowlist"

    def test_match_is_exact_not_prefix(self) -> None:
        # filesystem.read must NOT match filesystem.read_file — no substring
        # or prefix matching is permitted.
        f = CapabilityFilter(CapabilitySettings(allowed_tools=("filesystem.read",)))
        assert f.check("filesystem.read_file").allowed is False
        assert f.check("filesystem.read_file").reason == "not_in_allowlist"

    def test_match_is_case_sensitive(self) -> None:
        f = CapabilityFilter(CapabilitySettings(allowed_tools=("filesystem.read",)))
        assert f.check("filesystem.READ").allowed is False

    def test_namespaced_prepends_server_name(self) -> None:
        f = CapabilityFilter(CapabilitySettings(allowed_tools=("fs.read",), server_name="fs"))
        assert f.namespaced("read") == "fs.read"
        assert f.check(f.namespaced("read")).reason == "in_allowlist"

    def test_namespaced_without_server_name_is_bare(self) -> None:
        f = CapabilityFilter(CapabilitySettings(allowed_tools=("fs.read",)))
        assert f.namespaced("read") == "read"


# ---------------------------------------------------------------------
# Raw-payload extraction: _scan_capability (audit #10 / #13)
# ---------------------------------------------------------------------


class TestCapabilityRawPayloadExtraction:
    """``_scan_capability`` inspects the RAW payload, not the parse type.

    A ``tools/call`` carries its tool name in ``params.name`` regardless of the
    ``id``. A fractional id (``1.5``) makes the frame fail :class:`MCPRequest`
    validation, and a notification has no ``id`` at all — yet both are still
    ``tools/call`` with a name, so both are subject to the allowlist. Before the
    fix each yielded ``None`` (not blocked) and was forwarded to the server;
    these tests pin the closed bypass and the reply metadata a block needs.
    """

    _CAP = CapabilityFilter(CapabilitySettings(allowed_tools=("srv.safe_tool",), server_name="srv"))

    @staticmethod
    def _member(**payload: object) -> str:
        return json.dumps({"jsonrpc": "2.0", **payload}, separators=(",", ":"))

    def test_fractional_id_tools_call_is_blocked(self) -> None:
        # Audit #10: id=1.5 is not a valid MCPRequest id, but the call is still
        # blocked and the raw id is preserved so the -32603 reply can echo it.
        member = self._member(id=1.5, method="tools/call", params={"name": "danger"})
        (hit,) = _scan_capability([member], self._CAP)
        assert hit is not None
        assert hit.blocked is True
        assert hit.reply_expected is True  # id present → a block may reply
        assert hit.reply_id == 1.5  # echoed back verbatim in the reply

    def test_notification_tools_call_is_blocked(self) -> None:
        # Audit #13: no id at all (notification), yet params.name is present.
        member = self._member(method="tools/call", params={"name": "danger"})
        (hit,) = _scan_capability([member], self._CAP)
        assert hit is not None
        assert hit.blocked is True
        assert hit.reply_expected is False  # notification → no reply, still blocked
        assert hit.reply_id is None

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(
                {"id": 1.5, "method": "tools/call", "params": {"name": "safe_tool"}},
                id="fractional_id",
            ),
            pytest.param(
                {"method": "tools/call", "params": {"name": "safe_tool"}},
                id="notification",
            ),
        ],
    )
    def test_allowlisted_tool_passes_in_both_forms(self, payload: dict[str, object]) -> None:
        # The fix must not start blocking allowlisted tools: an allowlisted name
        # passes (blocked=False) whether its id is fractional or absent.
        (hit,) = _scan_capability([self._member(**payload)], self._CAP)
        assert hit is not None
        assert hit.blocked is False

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({"id": 2, "method": "tools/list", "params": {}}, id="tools_list"),
            pytest.param({"id": 3, "method": "initialize", "params": {}}, id="initialize"),
            pytest.param({"id": 4, "method": "tools/call", "params": {}}, id="tools_call_no_name"),
            pytest.param({"method": "notifications/initialized"}, id="unrelated_notification"),
            pytest.param(
                {"id": 5, "method": "tools/call", "params": {"name": 42}}, id="non_string_name"
            ),
        ],
    )
    def test_nameless_shapes_yield_none(self, payload: dict[str, object]) -> None:
        # Unchanged behaviour: without a string params.name there is nothing to
        # name, so the member is not subject to the allowlist (yields None).
        (hit,) = _scan_capability([self._member(**payload)], self._CAP)
        assert hit is None


# ---------------------------------------------------------------------
# Config: the capability: YAML section
# ---------------------------------------------------------------------


class TestCapabilityConfig:
    def test_missing_section_is_empty_allowlist(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.yaml"
        cfg.write_text("storage:\n  db_path: x.db\n", encoding="utf-8")
        settings = resolve_settings(cli_config=cfg)
        assert settings.capability.allowed_tools == ()
        assert settings.capability.server_name == ""

    def test_valid_section_parses(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            yaml.safe_dump(
                {"capability": {"server_name": "fs", "allowed_tools": ["fs.read", "fs.write"]}}
            ),
            encoding="utf-8",
        )
        settings = resolve_settings(cli_config=cfg)
        assert settings.capability.server_name == "fs"
        assert settings.capability.allowed_tools == ("fs.read", "fs.write")

    def test_duplicates_collapsed(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            yaml.safe_dump({"capability": {"allowed_tools": ["fs.read", "fs.read", "fs.write"]}}),
            encoding="utf-8",
        )
        settings = resolve_settings(cli_config=cfg)
        assert settings.capability.allowed_tools == ("fs.read", "fs.write")

    @pytest.mark.parametrize(
        "bad_name",
        [
            pytest.param("nodot", id="no_dot"),
            pytest.param(".read", id="empty_server"),
            pytest.param("fs.", id="empty_tool"),
            pytest.param("fs .read", id="whitespace"),
            pytest.param("a.b.c", id="multi_dot"),
        ],
    )
    def test_malformed_tool_name_rejected(self, tmp_path: Path, bad_name: str) -> None:
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            yaml.safe_dump({"capability": {"allowed_tools": [bad_name]}}),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="not a valid"):
            resolve_settings(cli_config=cfg)

    def test_allowed_tools_must_be_a_list(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.yaml"
        cfg.write_text("capability:\n  allowed_tools: 'fs.read'\n", encoding="utf-8")
        with pytest.raises(ValueError, match="must be a list"):
            resolve_settings(cli_config=cfg)


# ---------------------------------------------------------------------
# Proxy integration (real CLI subprocess; mirrors test_proxy_block.py)
# ---------------------------------------------------------------------


async def _run_proxy_subprocess(
    *,
    db_path: Path,
    config_path: Path,
    server_cmd: str,
    frames: list[str],
    timeout: float = 8.0,
) -> tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "bulwark_mcp",
        "run",
        "--server",
        server_cmd,
        "--db-path",
        str(db_path),
        "--config",
        str(config_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdin is not None
    payload = "\n".join(frames).encode() + b"\n"
    proc.stdin.write(payload)
    await proc.stdin.drain()
    proc.stdin.close()
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        pytest.fail("proxy did not exit within the timeout")
    assert proc.returncode is not None
    return proc.returncode, stdout, stderr


def _write_capability_config(
    path: Path,
    *,
    allowed_tools: list[str],
    server_name: str = "testserver",
    detector: bool = False,
) -> None:
    cfg: dict[str, object] = {
        "capability": {"server_name": server_name, "allowed_tools": allowed_tools},
    }
    if detector:
        cfg["detector"] = {"enabled": True, "llm": {"enabled": False}, "max_latency_ms": 200}
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")


def _tools_call(*, frame_id: int, name: str, arguments: dict[str, object]) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": frame_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        separators=(",", ":"),
    )


async def test_c2s_tool_not_in_allowlist_is_blocked(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    _write_capability_config(cfg, allowed_tools=["testserver.allowed_tool"])

    frame = _tools_call(frame_id=11, name="blocked_tool", arguments={"path": "/etc/passwd"})
    rc, stdout, _stderr = await _run_proxy_subprocess(
        db_path=db, config_path=cfg, server_cmd="cat", frames=[frame]
    )
    assert rc == 0

    # The client must see exactly one line: a -32603 capability error.
    # `cat` echoing the request would add a second line — its absence proves
    # the frame was never forwarded to the server.
    out_lines = [line for line in stdout.decode().splitlines() if line.strip()]
    assert len(out_lines) == 1
    received = json.loads(out_lines[0])
    assert received["id"] == 11
    assert received["error"]["code"] == -32603
    assert "testserver.blocked_tool" in received["error"]["message"]
    assert "allowlist" in received["error"]["message"]
    assert "result" not in received  # never an echo of the original call

    # Audit log: a blocked_by_capability row with the tool name, a trace id,
    # and the truncated arguments.
    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=10)
    cap_rows = [
        r
        for r in rows
        if r["direction"] == "client_to_server"
        and (r["note"] or "").startswith("blocked_by_capability")
    ]
    assert len(cap_rows) == 1
    row = cap_rows[0]
    assert "tool=testserver.blocked_tool" in row["note"]
    assert "trace=" in row["note"]
    assert row["method"] == "tools/call"
    assert row["params_json"] is not None
    assert "/etc/passwd" in row["params_json"]


async def test_tools_list_is_not_filtered(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    _write_capability_config(cfg, allowed_tools=["testserver.allowed_tool"])

    # tools/list carries no params.name, so capability does not apply — the
    # frame is forwarded and `cat` echoes it back verbatim.
    frame = json.dumps(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
        separators=(",", ":"),
    )
    rc, stdout, _stderr = await _run_proxy_subprocess(
        db_path=db, config_path=cfg, server_cmd="cat", frames=[frame]
    )
    assert rc == 0
    out_lines = [line for line in stdout.decode().splitlines() if line.strip()]
    assert len(out_lines) == 1
    received = json.loads(out_lines[0])
    assert "error" not in received
    assert received == json.loads(frame)  # untouched echo


async def test_capability_passes_then_rules_still_block(tmp_path: Path) -> None:
    """Layer-independence: an allowlisted tool whose arguments carry a
    shell-injection payload passes capability but is still blocked by the
    rules layer — capability does not override (or suppress) rules."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    _write_capability_config(cfg, allowed_tools=["testserver.allowed_tool"], detector=True)

    frame = _tools_call(
        frame_id=9,
        name="allowed_tool",
        arguments={"cmd": "rm -rf --no-preserve-root /"},
    )
    rc, stdout, _stderr = await _run_proxy_subprocess(
        db_path=db, config_path=cfg, server_cmd="cat", frames=[frame]
    )
    assert rc == 0
    out_lines = [line for line in stdout.decode().splitlines() if line.strip()]
    assert len(out_lines) == 1
    received = json.loads(out_lines[0])
    assert received["id"] == 9
    # A RULES block is -32099, not the capability filter's -32603.
    assert received["error"]["code"] == -32099
    assert "blocked by bulwark-mcp" in received["error"]["message"]

    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=10)
    # Capability did not block — no blocked_by_capability row.
    assert not [r for r in rows if (r["note"] or "").startswith("blocked_by_capability")]
    # The rules layer did — the c2s row is a detector block.
    c2s = [r for r in rows if r["direction"] == "client_to_server"]
    assert any(r["det_action"] == "block" for r in c2s)


async def test_empty_allowlist_emits_fail_open_warning(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("capability:\n  allowed_tools: []\n", encoding="utf-8")

    frame = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        separators=(",", ":"),
    )
    rc, _stdout, stderr = await _run_proxy_subprocess(
        db_path=db, config_path=cfg, server_cmd="cat", frames=[frame]
    )
    assert rc == 0
    # Decision 2: never block silently when unconfigured — warn loudly.
    assert "capability filter inactive" in stderr.decode()


async def test_fractional_id_call_is_blocked_end_to_end(tmp_path: Path) -> None:
    """Audit #10: a fractional-id ``tools/call`` fails MCPRequest validation but
    must still be blocked by capability — never forwarded — with the raw id
    echoed back so the client can correlate the -32603 reply."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    _write_capability_config(cfg, allowed_tools=["testserver.safe_tool"])

    frame = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1.5,
            "method": "tools/call",
            "params": {"name": "danger", "arguments": {"path": "/etc/passwd"}},
        },
        separators=(",", ":"),
    )
    rc, stdout, _stderr = await _run_proxy_subprocess(
        db_path=db, config_path=cfg, server_cmd="cat", frames=[frame]
    )
    assert rc == 0

    # Exactly one line — the -32603 reply. `cat` echoing the request would add
    # a second line; its absence proves the frame was never forwarded.
    out_lines = [line for line in stdout.decode().splitlines() if line.strip()]
    assert len(out_lines) == 1
    received = json.loads(out_lines[0])
    assert received["id"] == 1.5  # raw fractional id echoed back verbatim
    assert received["error"]["code"] == -32603
    assert "testserver.danger" in received["error"]["message"]
    assert "result" not in received

    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=10)
    cap_rows = [r for r in rows if (r["note"] or "").startswith("blocked_by_capability")]
    assert len(cap_rows) == 1
    assert "tool=testserver.danger" in cap_rows[0]["note"]


async def test_notification_call_is_blocked_with_no_reply(tmp_path: Path) -> None:
    """Audit #13: a notification (no id) carries the tool name in params.name.
    It must be blocked — never forwarded — and, because JSON-RPC forbids
    replying to a notification, generate no client reply at all."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    _write_capability_config(cfg, allowed_tools=["testserver.safe_tool"])

    frame = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",  # no id → notification
            "params": {"name": "danger", "arguments": {"path": "/etc/passwd"}},
        },
        separators=(",", ":"),
    )
    rc, stdout, _stderr = await _run_proxy_subprocess(
        db_path=db, config_path=cfg, server_cmd="cat", frames=[frame]
    )
    assert rc == 0

    # Zero output lines: no reply (notification) AND `cat` never echoed it
    # (never forwarded). Together they prove a silent, non-forwarding block.
    out_lines = [line for line in stdout.decode().splitlines() if line.strip()]
    assert out_lines == []

    # ...but it WAS blocked — the audit trail records it, with no msg_id.
    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=10)
    cap_rows = [r for r in rows if (r["note"] or "").startswith("blocked_by_capability")]
    assert len(cap_rows) == 1
    assert "tool=testserver.danger" in cap_rows[0]["note"]
    assert cap_rows[0]["msg_id"] is None  # notification carried no id


async def test_allowlisted_notification_is_forwarded(tmp_path: Path) -> None:
    """Guard against over-blocking: an allowlisted tool invoked as a
    notification passes capability and is forwarded verbatim (echoed by `cat`),
    proving the raw-payload path did not start blocking allowlisted tools."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    _write_capability_config(cfg, allowed_tools=["testserver.safe_tool"])

    frame = json.dumps(
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "safe_tool"}},
        separators=(",", ":"),
    )
    rc, stdout, _stderr = await _run_proxy_subprocess(
        db_path=db, config_path=cfg, server_cmd="cat", frames=[frame]
    )
    assert rc == 0
    out_lines = [line for line in stdout.decode().splitlines() if line.strip()]
    assert len(out_lines) == 1
    received = json.loads(out_lines[0])
    assert received == json.loads(frame)  # untouched echo — forwarded, not blocked

    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=10)
    assert not [r for r in rows if (r["note"] or "").startswith("blocked_by_capability")]
