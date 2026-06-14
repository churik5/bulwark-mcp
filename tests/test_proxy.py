"""End-to-end test for the proxy.

We launch ``python -m bulwark_mcp run --server "cat"`` as a subprocess so
the test exercises the *real* CLI entry point, not just internal helpers.
``cat`` is a poor-man's MCP server — it echoes everything we send back to
stdout, so we can assert on round-trip behaviour and on what landed in the
audit log.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from bulwark_mcp.proxy import _AsyncStreamReader, _pump
from bulwark_mcp.storage import EventBuffer, Storage

pytestmark = pytest.mark.asyncio


class _CollectingWriter:
    """Minimal :class:`bulwark_mcp.proxy._LineWriter` that records writes.

    Lets us drive :func:`_pump` in-process and inspect exactly what reached
    the destination peer without a real transport.
    """

    def __init__(self) -> None:
        self.lines: list[bytes] = []
        self._closed = False

    async def write_line(self, data: bytes) -> bool:
        self.lines.append(data)
        return True

    def close(self) -> None:
        self._closed = True

    async def aclose(self) -> None:
        self._closed = True

    def is_closing(self) -> bool:
        return self._closed


async def _run_proxy_subprocess(
    *,
    db_path: Path,
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


async def test_round_trips_three_frames_and_persists_both_directions(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    frames = [
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
    ]
    rc, stdout, _ = await _run_proxy_subprocess(db_path=db, server_cmd="cat", frames=frames)
    assert rc == 0

    forwarded = stdout.decode().splitlines()
    assert len(forwarded) == 3
    for line, original in zip(forwarded, frames, strict=True):
        assert json.loads(line) == json.loads(original)

    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=20)
    methods = [r["method"] for r in rows]
    directions = [r["direction"] for r in rows]
    assert methods == [
        "ping",
        "notifications/initialized",
        "tools/list",
        "ping",
        "notifications/initialized",
        "tools/list",
    ]
    assert directions[:3] == ["client_to_server"] * 3
    assert directions[3:] == ["server_to_client"] * 3


async def test_large_server_response_under_limit_passes_intact(tmp_path: Path) -> None:
    """Regression (fix A): a server response far larger than asyncio's default
    64 KiB StreamReader limit — but under the proxy's line limit — round-trips
    intact through ``cat``.

    Before the server reader shared the configured line limit it kept asyncio's
    64 KiB default, so a >64 KiB single-line response overran and crashed the
    s2c pump (the overrun surfaces as ``ValueError``). This ~100 KiB frame
    proves the server reader now uses the project limit AND that the frame is
    forwarded unchanged (not truncated or dropped).
    """
    db = tmp_path / "log.db"
    big_value = "z" * 100_000  # ~100 KiB, comfortably over the 64 KiB default
    frame = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"blob": big_value}})
    assert len(frame) > 64 * 1024

    rc, stdout, _ = await _run_proxy_subprocess(db_path=db, server_cmd="cat", frames=[frame])
    assert rc == 0

    forwarded = stdout.decode().splitlines()
    assert len(forwarded) == 1
    assert json.loads(forwarded[0]) == json.loads(frame)


async def test_pump_survives_oversized_server_response(storage: Storage) -> None:
    """Core regression (fix B): an over-limit server line makes asyncio's
    ``StreamReader.readline`` raise ``ValueError`` (NOT ``LimitOverrunError``).

    The pump's handler now catches both, records the frame as oversized, and
    KEEPS PUMPING — so the following normal frame still reaches the client.
    The old handler caught only ``LimitOverrunError`` and would let the
    ``ValueError`` escape and kill this pump task. We drive ``_pump`` directly
    with a real async reader at a tiny limit so the test is cheap and exercises
    the genuine asyncio overflow path.
    """
    session_id = await storage.start_session(server_command="cat", client_pid=0)

    raw = asyncio.StreamReader(limit=64)  # tiny limit so the overflow is cheap
    oversized = b"X" * 200 + b"\n"  # 200 bytes >> 64-byte limit
    follow = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'
    raw.feed_data(oversized + follow)
    raw.feed_eof()
    src = _AsyncStreamReader(raw)

    dst = _CollectingWriter()
    reverse_dst = _CollectingWriter()

    async with EventBuffer(storage, queue_max=256, batch_size=16, batch_interval_s=0.05) as buffer:
        # Must return normally — no ValueError may escape and crash the pump.
        await _pump(
            src=src,
            dst=dst,
            reverse_dst=reverse_dst,
            direction="server_to_client",
            inspector=None,
            capability=None,
            client_write_lock=asyncio.Lock(),
            is_client_target=True,
            buffer=buffer,
            session_id=session_id,
            stop_event=asyncio.Event(),
        )

    # The normal frame after the oversized one survived and was forwarded.
    assert follow in dst.lines
    # The oversized frame was recorded as oversized, not silently swallowed.
    rows = await storage.latest_events(limit=20)
    assert "line_limit_exceeded" in [r["note"] for r in rows]


async def test_invalid_json_is_logged_as_parse_error_not_dropped(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    frames = ["not-valid-json", '{"jsonrpc":"2.0","id":1,"method":"ping"}']
    rc, _, _ = await _run_proxy_subprocess(db_path=db, server_cmd="cat", frames=frames)
    assert rc == 0
    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=20)
    kinds = [r["kind"] for r in rows]
    assert "parse_error" in kinds
    # The valid frame must still appear in both directions
    assert kinds.count("request") == 2
