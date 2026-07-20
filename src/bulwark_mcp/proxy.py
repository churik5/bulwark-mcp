"""stdio proxy between an MCP client (e.g. Claude Desktop) and an MCP server.

See ADR-0001. The shape is intentionally small:

- We launch the real server as a subprocess with no shell (argv form).
- Two pumps copy newline-delimited frames between the client and the server.
- Every frame is parsed best-effort and pushed onto an :class:`EventBuffer`
  for asynchronous, batched persistence.
- We never write our own diagnostics to stdout — that channel belongs to
  the JSON-RPC frames flowing to the client.

I/O abstraction
---------------

In production the proxy is launched by Claude Desktop, so stdin/stdout are
anonymous pipes — :func:`asyncio.AbstractEventLoop.connect_read_pipe` and
``connect_write_pipe`` accept those happily. When the proxy is launched from
a normal shell or under test runners, those fds may be a tty or a regular
file, which the asyncio pipe transports refuse with ``ValueError``. We fall
back to blocking I/O on a worker thread, exposed through the same async
:class:`_LineReader` / :class:`_LineWriter` interface so the pump code stays
unchanged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import IO, Any, Literal, Protocol, cast

from .capability import CapabilityFilter
from .config import Settings
from .detectors.base import InspectionResult
from .detectors.llm import OllamaClassifier
from .detectors.rules import RulesEngine
from .health import HealthState
from .health import serve as serve_health
from .inspector import Inspector
from .models import EventRecord, MCPRequest, parse_frame, split_batch
from .policy import Policy, default_policy
from .storage import EventBuffer, Storage
from .telemetry import TelemetryClient
from .telemetry import is_enabled as telemetry_enabled

Direction = Literal["client_to_server", "server_to_client"]

logger = logging.getLogger(__name__)

DEFAULT_LINE_LIMIT_BYTES = 8 * 1024 * 1024  # 8 MiB — generous for tool results


@dataclass(frozen=True)
class ProxyResult:
    exit_code: int
    events_dropped: int


class _LineReader(Protocol):
    async def readline(self) -> bytes: ...
    def close(self) -> None: ...


class _LineWriter(Protocol):
    async def write_line(self, data: bytes) -> bool:
        """Write ``data`` and flush. Returns ``False`` once the peer is gone."""
        ...

    def close(self) -> None: ...
    async def aclose(self) -> None:
        """Close and wait for the underlying transport to actually shut.

        Implementations that wrap :class:`asyncio.StreamWriter` need this so
        the peer sees EOF promptly; for blocking writers it is a no-op.
        """
        ...

    def is_closing(self) -> bool: ...


async def run_proxy(
    server_command: str,
    *,
    settings: Settings,
    line_limit: int = DEFAULT_LINE_LIMIT_BYTES,
    health_port: int = 0,
) -> ProxyResult:
    """Run the proxy until either side closes. Returns the child's exit code."""
    argv = shlex.split(server_command)
    if not argv:
        raise ValueError("--server must contain an executable")

    storage = Storage(settings.db_path)
    await storage.open()
    try:
        session_id = await storage.start_session(
            server_command=server_command,
            client_pid=os.getppid(),
        )

        child = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr.fileno(),
            # Give child.stdout's StreamReader the SAME line limit as the
            # client reader. Without this it keeps asyncio's 64 KiB default,
            # so any server response over 64 KiB on one line overruns and
            # crashes the s2c pump — yet large tool results are routine.
            limit=line_limit,
        )
        if child.stdin is None or child.stdout is None:
            raise RuntimeError("subprocess pipes were not created — check argv")

        await _patch_session_with_server_pid(storage, session_id, child.pid)

        client_reader = await _open_client_reader(line_limit)
        client_writer = await _open_client_writer()
        server_reader = _AsyncStreamReader(child.stdout)
        server_writer = _AsyncStreamWriter(child.stdin)

        async with EventBuffer(
            storage,
            queue_max=settings.queue_max,
            batch_size=settings.batch_size,
            batch_interval_s=settings.batch_interval_s,
        ) as buffer:
            stop_event = asyncio.Event()
            _install_signal_handlers(stop_event)

            # ADR-0004 §1: build the inspector if detector is enabled.
            inspector, classifier = await _build_inspector(settings, storage)
            client_write_lock = asyncio.Lock()

            # Name-based capability filter — checked on c2s frames BEFORE the
            # inspector. Fail-open: with no allowlist we warn loudly and pass
            # everything through (never block silently when unconfigured).
            capability_filter = CapabilityFilter(settings.capability)
            if capability_filter.active:
                logger.info(
                    "capability: %d tool(s) allowlisted%s",
                    len(settings.capability.allowed_tools),
                    f" for server '{settings.capability.server_name}'"
                    if settings.capability.server_name
                    else "",
                )
            else:
                logger.warning(
                    "capability filter inactive — no allowlist configured. All tool "
                    "calls will pass through without name filtering. See "
                    "https://github.com/churik5/bulwark-mcp#capability-filter to enable."
                )

            # ADR-0005 §3: opt-in telemetry side-car.
            telemetry_client: TelemetryClient | None = None
            telemetry_task: asyncio.Task[None] | None = None
            if telemetry_enabled():
                telemetry_client = TelemetryClient(settings=settings)
                telemetry_task = asyncio.create_task(
                    _telemetry_loop(telemetry_client, storage),
                    name="telemetry",
                )

            # ADR-0005 §2: optional loopback health endpoint.
            health_server: asyncio.AbstractServer | None = None
            if health_port > 0:
                try:
                    health_state = HealthState(started_at=datetime.now(UTC), storage=storage)
                    health_server = await serve_health(health_state, port=health_port)
                    logger.info("health: listening on 127.0.0.1:%d/health", health_port)
                except OSError as exc:
                    logger.warning(
                        "health: failed to bind 127.0.0.1:%d (%s); endpoint disabled",
                        health_port,
                        exc,
                    )

            try:
                client_to_server = asyncio.create_task(
                    _pump(
                        src=client_reader,
                        dst=server_writer,
                        reverse_dst=client_writer,
                        direction="client_to_server",
                        inspector=inspector,
                        capability=capability_filter,
                        client_write_lock=client_write_lock,
                        is_client_target=False,
                        buffer=buffer,
                        session_id=session_id,
                        stop_event=stop_event,
                    ),
                    name="pump-c2s",
                )
                server_to_client = asyncio.create_task(
                    _pump(
                        src=server_reader,
                        dst=client_writer,
                        reverse_dst=server_writer,
                        direction="server_to_client",
                        inspector=inspector,
                        capability=None,  # capability filtering is c2s-only
                        client_write_lock=client_write_lock,
                        is_client_target=True,
                        buffer=buffer,
                        session_id=session_id,
                        stop_event=stop_event,
                    ),
                    name="pump-s2c",
                )
                stop_waiter = asyncio.create_task(stop_event.wait(), name="stop-waiter")

                done, _ = await asyncio.wait(
                    {client_to_server, server_to_client, stop_waiter},
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in done:
                    if task is stop_waiter:
                        continue
                    task_exc = task.exception()
                    if task_exc is not None and not isinstance(task_exc, asyncio.CancelledError):
                        logger.error("pump task %s failed: %r", task.get_name(), task_exc)

                if stop_waiter in done:
                    # Forced shutdown — kill both directions immediately.
                    for task in (client_to_server, server_to_client):
                        task.cancel()
                elif client_to_server in done and server_to_client not in done:
                    # Client EOF. Half-close server stdin (await wait_closed so the
                    # peer actually sees EOF) and let the server drain any pending
                    # replies before we tear down s2c.
                    await server_writer.aclose()
                    try:
                        await asyncio.wait_for(server_to_client, timeout=10.0)
                    except TimeoutError:
                        logger.warning("server did not flush within 10s; cancelling")
                        server_to_client.cancel()
                elif server_to_client in done and client_to_server not in done:
                    # Server EOF / crash. Stop reading from client.
                    client_to_server.cancel()

                # stop_waiter may still be pending — always cancel before awaiting
                # so we never block the shutdown path on an idle event.
                stop_waiter.cancel()
                for task in (client_to_server, server_to_client, stop_waiter):
                    with suppress(asyncio.CancelledError, Exception):
                        await task

                with suppress(ProcessLookupError):
                    if child.returncode is None:
                        await server_writer.aclose()
                        try:
                            await asyncio.wait_for(child.wait(), timeout=2.0)
                        except TimeoutError:
                            child.terminate()
                            try:
                                await asyncio.wait_for(child.wait(), timeout=2.0)
                            except TimeoutError:
                                child.kill()
                                await child.wait()

                exit_code = child.returncode if child.returncode is not None else -1
                dropped = buffer.dropped
            finally:
                if health_server is not None:
                    health_server.close()
                    with suppress(Exception):
                        await health_server.wait_closed()
                if telemetry_task is not None:
                    telemetry_task.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await telemetry_task
                if telemetry_client is not None:
                    await telemetry_client.aclose()
                if classifier is not None:
                    await classifier.aclose()

        await storage.end_session(session_id, exit_code=exit_code)
        return ProxyResult(exit_code=exit_code, events_dropped=dropped)
    finally:
        await storage.close()


async def _pump(
    *,
    src: _LineReader,
    dst: _LineWriter,
    reverse_dst: _LineWriter,
    direction: Direction,
    inspector: Inspector | None,
    capability: CapabilityFilter | None,
    client_write_lock: asyncio.Lock,
    is_client_target: bool,
    buffer: EventBuffer,
    session_id: int,
    stop_event: asyncio.Event,
) -> None:
    """Copy newline-delimited frames from ``src`` to ``dst``, optionally
    inspecting and substituting them along the way (ADR-0004 §1).

    Parameters
    ----------
    dst
        The "primary" peer for this direction — server stdin for c2s,
        client stdout for s2c.
    reverse_dst
        The other peer. Used when the inspector decides to BLOCK a c2s
        request (ADR-0004 §5) OR when the capability filter blocks a c2s
        tool call — both send a synthetic JSON-RPC error back to the client.
    capability
        Name-based allowlist applied to c2s ``tools/call`` frames BEFORE
        the inspector. ``None`` for the s2c pump (capability is c2s-only).
        A capability block short-circuits the detector cascade entirely.
    is_client_target
        ``True`` when ``dst`` is the client writer. We hold
        ``client_write_lock`` for every write to a client-bound writer
        so the c2s synthetic-block path cannot interleave with normal
        s2c forwarding.
    """
    try:
        while not stop_event.is_set():
            try:
                line = await src.readline()
            except (asyncio.LimitOverrunError, ValueError) as exc:
                # Two readers signal an oversized line two ways: the blocking
                # reader raises LimitOverrunError, the async StreamReader
                # re-raises asyncio's overflow as a plain ValueError. Treat
                # both as the same "oversized frame" case instead of letting
                # the ValueError escape and kill the pump. The try wraps ONLY
                # readline, so no unrelated ValueError is swallowed here.
                consumed = await _drain_oversized(src, _consumed_from_overflow(exc))
                _record_raw(
                    buffer,
                    session_id=session_id,
                    direction=direction,
                    raw=consumed.decode("utf-8", errors="replace"),
                    note="line_limit_exceeded",
                )
                if not await _safe_write(
                    dst,
                    consumed,
                    lock=client_write_lock if is_client_target else None,
                ):
                    return
                continue
            except (ConnectionResetError, BrokenPipeError):
                return

            if not line:
                return  # EOF

            decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if not decoded.strip():
                if not await _safe_write(
                    dst,
                    line,
                    lock=client_write_lock if is_client_target else None,
                ):
                    return
                continue

            # Week-3 audit fix: a JSON-RPC batch is one wire frame but
            # several logical messages. We inspect each member separately
            # so the audit log shows per-member verdicts; if ANY member
            # blocks, we replace the entire batch (wrapped as an array
            # to keep JSON-RPC format valid).
            members = split_batch(decoded)
            is_batch = len(members) > 1

            # Capability filter (c2s only) — a name-based allowlist checked
            # BEFORE the detector cascade. A block here is fail-fast: it
            # short-circuits the inspector entirely (no rules, no LLM, no
            # policy) and the frame is never forwarded to the server.
            if capability is not None and capability.active:
                cap_hits = _scan_capability(members, capability)
                blocked_hits = [
                    (member, hit)
                    for member, hit in zip(members, cap_hits, strict=True)
                    if hit is not None and hit.blocked
                ]
                if blocked_hits:
                    trace_id = _capability_trace_id()
                    # A blocked call is NEVER forwarded to the server. The reply
                    # to the client is best-effort per JSON-RPC: a batch, and any
                    # id-bearing single call, get an error reply echoing the id;
                    # a single blocked notification (no id) gets no reply at all
                    # — but is still not forwarded.
                    reply_text: str | None
                    if is_batch:
                        reply_text = (
                            "[" + ",".join(_build_capability_batch(members, cap_hits)) + "]"
                        )
                    else:
                        first_hit = blocked_hits[0][1]
                        if first_hit.reply_expected:
                            reply_text = _capability_error_reply(
                                request_id=first_hit.reply_id, full_name=first_hit.full_name
                            )
                        else:
                            reply_text = None
                    if reply_text is not None:
                        replacement_bytes = (reply_text + "\n").encode("utf-8")
                        if not await _safe_write(
                            reverse_dst, replacement_bytes, lock=client_write_lock
                        ):
                            return
                    for member, hit in zip(members, cap_hits, strict=True):
                        if hit is not None and hit.blocked:
                            _record_capability_block(
                                buffer,
                                session_id=session_id,
                                member=member,
                                hit=hit,
                                trace_id=trace_id,
                            )
                        else:
                            # Benign sibling in an aborted batch — log as a
                            # plain row so the audit trail stays complete.
                            _log_per_member(
                                buffer,
                                session_id=session_id,
                                direction=direction,
                                members=[member],
                                inspections=[None],
                            )
                    continue

            inspections: list[InspectionResult | None] = []
            if inspector is not None:
                for member in members:
                    parsed_msg, _ = parse_frame(member)
                    method_hint: str | None = getattr(parsed_msg, "method", None)
                    insp = await inspector.inspect(
                        raw=member,
                        parsed=parsed_msg,
                        direction=direction,
                        method_hint=method_hint,
                    )
                    inspections.append(insp)
            else:
                inspections = [None] * len(members)

            blocking = next(
                (
                    i
                    for i in inspections
                    if i is not None and i.action == "block" and i.replacement is not None
                ),
                None,
            )

            if blocking is not None:
                # Week-4 audit fix: build a per-id reply array so the
                # client sees a JSON-RPC response for *every* request id
                # in the batch, not just the first blocked one. Blocked
                # members get their actual sanitised replacement;
                # non-blocked s2c members are forwarded verbatim;
                # non-blocked c2s members get a synthesised
                # "batch_aborted_by_sibling" error so no request is left
                # hanging.
                if is_batch:
                    output_members = _build_batch_replacement(
                        members=members,
                        inspections=inspections,
                        direction=direction,
                    )
                    replacement_text = "[" + ",".join(output_members) + "]"
                else:
                    replacement_text = blocking.replacement or ""
                replacement_bytes = (replacement_text + "\n").encode("utf-8")

                if direction == "server_to_client":
                    if not await _safe_write(dst, replacement_bytes, lock=client_write_lock):
                        return
                else:
                    if not await _safe_write(
                        reverse_dst, replacement_bytes, lock=client_write_lock
                    ):
                        return
                    _record_synthetic(
                        buffer,
                        session_id=session_id,
                        raw=blocking.replacement or "",
                        inspection=blocking,
                    )
                _log_per_member(
                    buffer,
                    session_id=session_id,
                    direction=direction,
                    members=members,
                    inspections=inspections,
                )
                continue

            # Normal forward (allow / warn / block-downgraded-to-warn).
            if not await _safe_write(
                dst, line, lock=client_write_lock if is_client_target else None
            ):
                return
            _log_per_member(
                buffer,
                session_id=session_id,
                direction=direction,
                members=members,
                inspections=inspections,
            )
    finally:
        if not dst.is_closing():
            dst.close()


def _build_batch_replacement(
    *,
    members: list[str],
    inspections: list[InspectionResult | None],
    direction: Direction,
) -> list[str]:
    """Build the per-member output array for a batch where any member blocks.

    s2c: keep benign members as-is, replace blocked ones with their
    sanitised reply.

    c2s: never forward to the server (one bad sibling aborts the batch),
    so synthesise per-id error replies for ALL members. Blocked ones
    get their inspector-supplied replacement; non-blocked members get
    a ``-32099 / batch_aborted_by_sibling`` reply with the same id so
    the client's request ↔ response correlation is preserved.

    Notifications (no JSON-RPC id) are dropped from c2s output —
    they have no expected reply by spec, so there is nothing to
    synthesise.
    """
    out: list[str] = []
    for member, inspection in zip(members, inspections, strict=True):
        if (
            inspection is not None
            and inspection.action == "block"
            and inspection.replacement is not None
        ):
            out.append(inspection.replacement)
            continue
        if direction == "server_to_client":
            # Forward the benign server response verbatim.
            out.append(member)
            continue
        # c2s benign sibling: synthesize an error reply with the same id
        # so the client doesn't hang on an unanswered request.
        synth = _compose_batch_aborted_reply(member)
        if synth is not None:
            out.append(synth)
    return out


def _compose_batch_aborted_reply(member: str) -> str | None:
    """Build a JSON-RPC error reply for a benign c2s batch member that
    will not be forwarded because a sibling triggered a block.

    Returns ``None`` for notifications (no id, no expected reply).
    """
    parsed, _ = parse_frame(member)
    if not isinstance(parsed, MCPRequest):
        return None
    body: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": parsed.id,
        "error": {
            "code": -32099,
            "message": "batch aborted: a sibling request was blocked by bulwark-mcp",
        },
    }
    return json.dumps(body, separators=(",", ":"))


# --------------------------------------------------------------------------
# Capability filter (c2s tool-name allowlist) — see capability.py
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _CapHit:
    """One c2s ``tools/call`` member resolved against the capability filter.

    ``reply_id`` is the raw JSON ``id`` exactly as it arrived — an int, a
    string, or (for the malformed-id bypass) a float like ``1.5`` — or ``None``
    when the frame carries no ``id`` at all. ``reply_expected`` records whether
    an ``id`` key was present: ``True`` → a block answers the client with a
    ``-32603`` reply echoing ``reply_id``; ``False`` (a notification) → a block
    sends no reply (JSON-RPC forbids one) but still never forwards.
    """

    reply_id: Any
    reply_expected: bool
    full_name: str
    args_truncated: str
    blocked: bool


def _scan_capability(members: list[str], capability: CapabilityFilter) -> list[_CapHit | None]:
    """Per-member capability decisions for a c2s frame.

    Capability inspects the **raw** payload — not the parsed message type — for
    ``method == "tools/call"`` and a string ``params.name``. A tool name can
    ride in on shapes that never validate as :class:`MCPRequest`: a
    notification (no ``id``) or a request with a malformed ``id`` (a fractional
    ``1.5``, an array, any non int|str|null value pydantic rejects). Trusting
    the parse type there let those forms skip the allowlist entirely — the
    bypass this closes. ``params.name`` carries the tool name regardless of the
    ``id``, so we read it straight from the raw JSON.

    Every other shape yields ``None`` and is left for the inspector / normal
    forwarding: ``tools/list``, ``initialize``, any non-``tools/call`` method,
    unparseable frames, and a ``tools/call`` whose ``params.name`` is missing
    or non-string (we cannot name it, so we do not block it).

    Whether an ``id`` key is present — captured in ``_CapHit.reply_expected`` —
    decides only how a *block* answers the client, never whether it blocks: an
    id-bearing call gets a ``-32603`` reply echoing that id; a notification
    gets none but is still never forwarded.
    """
    hits: list[_CapHit | None] = []
    for member in members:
        hit: _CapHit | None = None
        try:
            raw = json.loads(member)
        except (json.JSONDecodeError, ValueError, RecursionError):
            raw = None
        if isinstance(raw, dict) and raw.get("method") == "tools/call":
            params = raw.get("params")
            tool = params.get("name") if isinstance(params, dict) else None
            if isinstance(tool, str) and tool:
                full_name = capability.namespaced(tool)
                decision = capability.check(full_name)
                args = params.get("arguments") if isinstance(params, dict) else None
                args_json = json.dumps(args, separators=(",", ":"), ensure_ascii=False, default=str)
                hit = _CapHit(
                    reply_id=raw.get("id"),
                    reply_expected="id" in raw,
                    full_name=full_name,
                    args_truncated=args_json[:500],
                    blocked=not decision.allowed,
                )
        hits.append(hit)
    return hits


def _build_capability_batch(members: list[str], cap_hits: list[_CapHit | None]) -> list[str]:
    """Per-id reply array for a c2s batch where any member is capability-blocked.

    The whole batch is aborted (never forwarded). Blocked members get the
    -32603 capability error; benign sibling requests get the shared
    ``batch_aborted_by_sibling`` reply so no request id is left unanswered;
    notifications are dropped (no id, no reply expected).
    """
    out: list[str] = []
    for member, hit in zip(members, cap_hits, strict=True):
        if hit is not None and hit.blocked:
            # An id-bearing blocked call answers with the -32603 error; a
            # blocked notification (no id) gets no reply — the batch is aborted
            # and never forwarded, so it is simply dropped from the output.
            if hit.reply_expected:
                out.append(
                    _capability_error_reply(request_id=hit.reply_id, full_name=hit.full_name)
                )
            continue
        synth = _compose_batch_aborted_reply(member)
        if synth is not None:
            out.append(synth)
    return out


def _capability_error_reply(*, request_id: Any, full_name: str) -> str:
    """JSON-RPC -32603 error telling the client the tool is not allowlisted
    and exactly how to allow it. The original call is never forwarded."""
    message = (
        f"Tool '{full_name}' blocked by bulwark capability filter. "
        "This tool is not in your allowlist. To allow it, add to config:\n"
        "  capability:\n"
        "    allowed_tools:\n"
        f"    - {full_name}\n"
        "See https://github.com/churik5/bulwark-mcp#capability-filter for details."
    )
    body: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32603, "message": message},
    }
    return json.dumps(body, separators=(",", ":"))


def _capability_trace_id() -> str:
    """8-hex-digit correlation id for a capability-block audit row."""
    return os.urandom(4).hex()


def _record_capability_block(
    buffer: EventBuffer,
    *,
    session_id: int,
    member: str,
    hit: _CapHit,
    trace_id: str,
) -> None:
    """Audit row for a capability-blocked c2s tool call.

    Carries the blocking marker ``blocked_by_capability`` plus the
    namespaced tool name and trace id in ``note``, the first 500 chars of
    the JSON-serialised arguments in ``params_json``, and the original
    frame in ``raw`` for forensics — mirroring how detector blocks are
    logged. ``ts`` is the row's timestamp.
    """
    record = EventRecord(
        session_id=session_id,
        direction="client_to_server",
        kind="request",
        msg_id=None if hit.reply_id is None else str(hit.reply_id),
        method="tools/call",
        params_json=hit.args_truncated,
        raw=member,
        note=f"blocked_by_capability tool={hit.full_name} trace={trace_id}",
        det_verdict="BLOCK",
        det_action="block",
    )
    buffer.record(record)


async def _safe_write(
    writer: _LineWriter,
    data: bytes,
    *,
    lock: asyncio.Lock | None,
) -> bool:
    """Write ``data`` through ``writer``, optionally serialised by a lock."""
    if lock is None:
        return await writer.write_line(data)
    async with lock:
        return await writer.write_line(data)


def _consumed_from_overflow(exc: Exception) -> int:
    """Bytes already consumed when a reader reports an oversized line.

    :class:`asyncio.LimitOverrunError` (raised by :class:`_BlockingReader`)
    carries a ``.consumed`` count. The async reader signals the same overflow
    as a plain :class:`ValueError`, which has no such attribute, so we report
    ``0`` — asyncio's ``StreamReader.readline`` has already discarded the
    overflow from its own buffer, leaving nothing for :func:`_drain_oversized`.
    """
    return int(getattr(exc, "consumed", 0))


async def _drain_oversized(src: _LineReader, consumed: int) -> bytes:
    """Drain leftover bytes after an oversized-line error — a no-op in practice.

    The two readers signal an oversized line differently, and BOTH leave
    nothing for this function to drain:

    - :class:`_AsyncStreamReader` surfaces the overflow as a ``ValueError``;
      asyncio's ``StreamReader.readline`` discards/advances its own buffer
      before raising, so the pump passes ``consumed == 0`` and
      ``_readexactly(0)`` returns empty bytes.
    - :class:`_BlockingReader` drains its own overflow synchronously in the
      worker thread *before* raising :class:`asyncio.LimitOverrunError`,
      leaving the stream positioned at the next frame. It exposes no
      ``_readexactly``, so there is nothing left to drain either.

    We probe for ``_readexactly`` via ``getattr`` and degrade gracefully; the
    branch stays in place for any reader that raises with overflow still
    buffered. Either way the single :func:`_pump` handler works for both.
    """
    readexactly = getattr(src, "_readexactly", None)
    if readexactly is not None:
        try:
            return cast(bytes, await readexactly(consumed))
        except Exception as exc:
            logger.debug("oversized drain failed: %r", exc)
    return b""


def _log_per_member(
    buffer: EventBuffer,
    *,
    session_id: int,
    direction: Direction,
    members: list[str],
    inspections: list[InspectionResult | None],
) -> None:
    """Log every JSON-RPC member with its own detector verdict.

    Week-3 audit fix: in a batch frame we now have one inspection per
    member instead of one shared verdict. ``members`` and ``inspections``
    must be the same length; the caller (``_pump``) guarantees this by
    deriving both from the same :func:`split_batch` result.
    """
    if len(members) != len(inspections):
        raise ValueError(
            f"_log_per_member: {len(members)} members vs {len(inspections)} "
            "inspections; the caller must provide one per member"
        )
    for member, inspection in zip(members, inspections, strict=True):
        parsed, kind = parse_frame(member)
        record = EventRecord.from_parsed(
            session_id=session_id,
            direction=direction,
            parsed=parsed,
            kind=kind,
            raw=member,
        )
        if inspection is not None:
            record = record.model_copy(
                update={
                    "det_verdict": inspection.verdict,
                    "det_score": inspection.score,
                    "det_rules": (list(inspection.rules_hit) if inspection.rules_hit else None),
                    "det_classifier": inspection.classifier,
                    "det_latency_ms": inspection.latency_ms,
                    "det_action": inspection.action,
                    "note": inspection.note,
                }
            )
        buffer.record(record)


def _record_synthetic(
    buffer: EventBuffer,
    *,
    session_id: int,
    raw: str,
    inspection: InspectionResult,
) -> None:
    """Log a synthetic s2c reply emitted by the proxy on c2s block.

    The synthetic event mirrors the parent c2s block's verdict so
    ``logs --verdict block`` shows BOTH rows; ``note='synthetic-block'``
    marks the row as proxy-emitted rather than from the real server.
    """
    parsed, kind = parse_frame(raw)
    record = EventRecord.from_parsed(
        session_id=session_id,
        direction="server_to_client",
        parsed=parsed,
        kind=kind,
        raw=raw,
    )
    record = record.model_copy(
        update={
            "det_verdict": inspection.verdict,
            "det_score": inspection.score,
            "det_rules": list(inspection.rules_hit) if inspection.rules_hit else None,
            "det_classifier": inspection.classifier,
            "det_latency_ms": inspection.latency_ms,
            "det_action": inspection.action,
            "note": "synthetic-block",
        }
    )
    buffer.record(record)


def _record_raw(
    buffer: EventBuffer,
    *,
    session_id: int,
    direction: Direction,
    raw: str,
    note: str,
) -> None:
    record = EventRecord(
        session_id=session_id,
        direction=direction,
        kind="raw",
        raw=raw,
        note=note,
    )
    buffer.record(record)


# --------------------------------------------------------------------------
# I/O adapters
# --------------------------------------------------------------------------


class _AsyncStreamReader:
    """Wraps :class:`asyncio.StreamReader` as a :class:`_LineReader`."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader

    async def readline(self) -> bytes:
        return await self._reader.readline()

    async def _readexactly(self, n: int) -> bytes:
        return await self._reader.readexactly(n)

    def close(self) -> None:  # readers don't need explicit close
        return


class _AsyncStreamWriter:
    """Wraps :class:`asyncio.StreamWriter` as a :class:`_LineWriter`."""

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self._writer = writer

    async def write_line(self, data: bytes) -> bool:
        try:
            self._writer.write(data)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            return False
        return True

    def close(self) -> None:
        if not self._writer.is_closing():
            self._writer.close()

    async def aclose(self) -> None:
        self.close()
        with suppress(ConnectionResetError, BrokenPipeError, Exception):
            await self._writer.wait_closed()

    def is_closing(self) -> bool:
        return self._writer.is_closing()


class _BlockingReader:
    """Fallback: blocking line reader on a worker thread.

    Plain ``io.BufferedReader.readline()`` is *unbounded* — an oversized
    frame would be slurped into memory in one shot, an OOM / DoS vector. We
    bound every read at ``limit`` bytes so this fallback honours the SAME
    contract :class:`_AsyncStreamReader` already enforces: a line over the
    limit is drained (read and discarded up to the next ``\n`` or EOF) and
    surfaced as an :class:`asyncio.LimitOverrunError`. (Note: the asyncio
    reader signals the same overflow as a ``ValueError`` instead; the
    handler in :func:`_pump` catches both exception types.) The drain runs
    synchronously inside the worker thread (natural for a blocking reader),
    leaving the stream positioned at the start of the next frame.

    A closed or invalid underlying stream is reported as a clean EOF
    (``b""``); this reader never lets a bare ``ValueError`` escape, so
    :func:`_pump`'s ``ValueError`` branch unambiguously means an async-reader
    overflow and a closed blocking stdin ends the pump instead of spinning.

    Boundary semantics (off-by-one): ``readline(limit)`` reads at most
    ``limit`` bytes, stopping early at the first ``\\n``. A line therefore
    *fits* when its newline-terminated form is at most ``limit`` bytes (i.e.
    at most ``limit - 1`` content bytes); the trailing ``\\n`` counts toward
    the budget. A line whose content reaches ``limit`` bytes before any
    ``\\n`` is oversized. The lone exception is a final, unterminated line
    *under* the limit (EOF before both the limit and a ``\\n``): like
    :meth:`asyncio.StreamReader.readline`, we return that partial tail intact.
    """

    # Drain the overflow in bounded steps so we never hold more than one
    # chunk past the limit in memory while discarding an oversized line.
    _DRAIN_CHUNK = 64 * 1024

    def __init__(self, fileobj: IO[bytes], *, limit: int) -> None:
        self._fileobj = fileobj
        self._limit = limit
        self._closed = False

    async def readline(self) -> bytes:
        if self._closed:
            return b""
        return await asyncio.to_thread(self._readline_bounded)

    def _readline_bounded(self) -> bytes:
        """Read one line capped at ``self._limit`` bytes (runs in a worker thread).

        ``io.BufferedReader.readline(size)`` stops at the first ``\\n`` OR
        after ``size`` bytes, whichever comes first, so a single
        ``readline(limit)`` tells us which happened:

        - empty result → clean EOF, return ``b""``;
        - underlying file closed under us (a ``ValueError`` surfaced as
          ``None`` by :meth:`_read_or_none`) → also a clean end-of-stream,
          return ``b""``;
        - ends in ``\\n`` → the whole line fit, return it (trailing ``\\n``
          included, matching readline semantics);
        - shorter than ``limit`` without a ``\\n`` → EOF reached before the
          limit, a final unterminated tail that still fits — return it;
        - exactly ``limit`` bytes without a ``\\n`` → oversized. Drain the
          rest of the line (next ``\\n`` or EOF) in bounded chunks, then raise
          :class:`asyncio.LimitOverrunError` so the stream is left at the
          start of the next frame.
        """
        chunk = self._read_or_none(self._limit)
        if not chunk:
            return b""  # clean stream end: EOF, or stdin closed under us
        if chunk.endswith(b"\n"):
            return chunk  # complete line within the limit
        if len(chunk) < self._limit:
            # EOF before both the limit and a newline: a final unterminated
            # line that fits. Return it as readline() does at EOF.
            return chunk
        # Limit hit with no newline → oversized. Drain and discard the rest
        # of the line synchronously, then raise.
        consumed = len(chunk)
        while True:
            extra = self._read_or_none(self._DRAIN_CHUNK)
            if extra is None:
                # Stream closed mid-drain: nothing left to discard and no
                # point raising into a dead stream — report a clean EOF.
                return b""
            if not extra:
                break  # genuine EOF before the oversized line terminated
            consumed += len(extra)
            if extra.endswith(b"\n"):
                break  # reached the end of the oversized line
        raise asyncio.LimitOverrunError(
            f"line exceeded {self._limit}-byte limit before a newline", consumed
        )

    def _read_or_none(self, size: int) -> bytes | None:
        """``self._fileobj.readline(size)``, or ``None`` if the file is closed.

        ``io.BufferedReader.readline`` raises ``ValueError`` ("readline of
        closed file") if stdin is closed under us mid-run. We surface that as
        ``None`` so the caller treats a closed stream as a clean end-of-stream
        rather than letting the bare ``ValueError`` escape — which would land
        in :func:`_pump`'s oversized branch and busy-loop. Over-limit lines on
        this path are signalled by :class:`asyncio.LimitOverrunError`, never by
        ``ValueError`` (we cap the read size ourselves), so swallowing
        ``ValueError`` here cannot hide a real overflow. We do NOT match on the
        exception message: any ``ValueError`` from the file read means the
        stream is unusable and is treated as end-of-stream.
        """
        try:
            return self._fileobj.readline(size)
        except ValueError:
            return None

    def close(self) -> None:
        self._closed = True


class _BlockingWriter:
    """Fallback: blocking line writer on a worker thread.

    We deliberately do **not** close the underlying file object on
    :meth:`close` — that would close real ``sys.stdout`` or ``sys.stderr``
    and break everything else in the process. We just flip a flag.
    """

    def __init__(self, fileobj: IO[bytes]) -> None:
        self._fileobj = fileobj
        self._closed = False
        self._lock = asyncio.Lock()

    async def write_line(self, data: bytes) -> bool:
        if self._closed:
            return False
        async with self._lock:
            try:
                await asyncio.to_thread(self._sync_write, data)
            except (ConnectionResetError, BrokenPipeError):
                self._closed = True
                return False
        return True

    def _sync_write(self, data: bytes) -> None:
        self._fileobj.write(data)
        self._fileobj.flush()

    def close(self) -> None:
        self._closed = True

    async def aclose(self) -> None:
        self._closed = True

    def is_closing(self) -> bool:
        return self._closed


async def _open_client_reader(limit: int) -> _LineReader:
    loop = asyncio.get_running_loop()
    try:
        reader = asyncio.StreamReader(limit=limit, loop=loop)
        protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
        return _AsyncStreamReader(reader)
    except (ValueError, OSError, NotImplementedError) as exc:
        logger.debug("falling back to blocking stdin reader: %r", exc)
        return _BlockingReader(sys.stdin.buffer, limit=limit)


async def _open_client_writer() -> _LineWriter:
    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.connect_write_pipe(
            lambda: asyncio.streams.FlowControlMixin(loop=loop),
            sys.stdout.buffer,
        )
        sw = asyncio.StreamWriter(transport, protocol, None, loop)
        return _AsyncStreamWriter(sw)
    except (ValueError, OSError, NotImplementedError) as exc:
        logger.debug("falling back to blocking stdout writer: %r", exc)
        return _BlockingWriter(sys.stdout.buffer)


def _install_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop_event.set)


async def _patch_session_with_server_pid(
    storage: Storage, session_id: int, server_pid: int | None
) -> None:
    if server_pid is None:
        return
    await storage.set_server_pid(session_id, server_pid)


async def _telemetry_loop(client: TelemetryClient, storage: Storage) -> None:
    """Side-car: print the opt-in banner once, then ship a payload after
    a 60 s warm-up, then once every 24 h until cancelled.

    Cadence per ADR-0005 §3. We split the wait into 60-second chunks so
    cancellation feels immediate even though the steady-state delay is
    24 h.
    """
    client.show_banner_once()

    initial_delay_s = 60.0
    daily_s = 24 * 60 * 60.0
    delay = initial_delay_s

    try:
        while True:
            elapsed = 0.0
            while elapsed < delay:
                step = min(60.0, delay - elapsed)
                await asyncio.sleep(step)
                elapsed += step
            try:
                payload = await client.build_payload(storage)
                await client.send(payload)
            except Exception as exc:
                logger.warning("telemetry: payload build/send raised %r", exc)
            delay = daily_s
    except asyncio.CancelledError:
        raise


async def _build_inspector(
    settings: Settings, storage: Storage
) -> tuple[Inspector | None, OllamaClassifier | None]:
    """Construct the Inspector + classifier pair (ADR-0004 §1).

    Returns ``(None, None)`` when ``settings.detector.enabled`` is False —
    the pump then keeps Week 1 behaviour. Otherwise the caller owns the
    classifier and must ``aclose`` it on shutdown.
    """
    det = settings.detector
    if not det.enabled:
        return None, None

    rules = RulesEngine.from_directory(det.rules_dir)
    policy = (
        Policy.from_file(det.policies_file) if det.policies_file is not None else default_policy()
    )

    classifier: OllamaClassifier | None = None
    if det.llm_enabled:
        classifier = OllamaClassifier(
            storage=storage,
            url=det.ollama_url,
            model=det.ollama_model,
            timeout_ms=det.timeout_ms,
            cache_ttl_s=det.cache_ttl_s,
            circuit_threshold=det.circuit_threshold,
            circuit_open_s=det.circuit_open_s,
        )

    inspector = Inspector(
        rules=rules,
        classifier=classifier,
        policy=policy,
        max_latency_ms=det.max_latency_ms,
        short_circuit_threshold=det.short_circuit_threshold,
    )
    logger.info(
        "detector: enabled (rules=%d, llm=%s, policy=%s)",
        len(rules),
        "on" if classifier is not None else "off",
        det.policies_file or "<built-in>",
    )
    return inspector, classifier
