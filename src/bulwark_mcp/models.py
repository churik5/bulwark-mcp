"""JSON-RPC 2.0 / MCP message models and parser.

We deliberately stay close to the JSON-RPC 2.0 spec rather than building a full
MCP type tree. The proxy needs to *route* and *log* — not to validate every MCP
method's params shape. Detector logic in milestone 2 will layer on top of this.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

JSONRPC_VERSION: Literal["2.0"] = "2.0"

JsonRpcId = int | str | None
"""JSON-RPC ids may be int, string, or null (the null case appears only in
error responses where the request was unparseable)."""


class _Frozen(BaseModel):
    """Base for parsed messages. Frozen so callers can hash / dedupe."""

    model_config = ConfigDict(frozen=True, extra="allow")


class MCPRequest(_Frozen):
    jsonrpc: Literal["2.0"] = JSONRPC_VERSION
    id: JsonRpcId
    method: str
    params: dict[str, Any] | list[Any] | None = None


class MCPNotification(_Frozen):
    """A request without an id — server must not reply."""

    jsonrpc: Literal["2.0"] = JSONRPC_VERSION
    method: str
    params: dict[str, Any] | list[Any] | None = None


class MCPErrorBody(_Frozen):
    code: int
    message: str
    data: Any | None = None


class MCPResponse(_Frozen):
    jsonrpc: Literal["2.0"] = JSONRPC_VERSION
    id: JsonRpcId
    result: Any | None = None
    error: MCPErrorBody | None = None


ParsedMessage = MCPRequest | MCPNotification | MCPResponse


def parse_frame(line: str) -> tuple[ParsedMessage | None, str]:
    """Parse one newline-delimited JSON-RPC frame.

    Returns (parsed, kind). On any parse error we still return (None, kind)
    where kind is "parse_error", so the caller can log the raw line.
    Batch frames (a JSON array) are returned as None with kind="batch" — the
    caller should pre-split via :func:`split_batch` before calling us.
    """
    line = line.strip()
    if not line:
        return None, "empty"
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, RecursionError):
        # A deeply nested array overflows json.loads with a RecursionError,
        # which is NOT a JSONDecodeError; without catching it here the error
        # would escape into the pump and crash it. Treat it like any other
        # malformed frame. Keep the handler trivial — the stack is near its
        # limit at this point.
        return None, "parse_error"

    if isinstance(payload, list):
        return None, "batch"
    if not isinstance(payload, dict):
        return None, "parse_error"

    return _from_dict(payload)


def split_batch(line: str) -> list[str]:
    """If the frame is a JSON-RPC batch, return its members as JSON strings.

    Returns ``[line]`` (single-element list with the original frame) for
    anything that isn't an array — including invalid JSON. The caller is
    expected to feed each element back through :func:`parse_frame`.
    """
    try:
        payload = json.loads(line.strip() or "null")
    except (json.JSONDecodeError, RecursionError):
        # A deeply nested array overflows json.loads with a RecursionError
        # (not a JSONDecodeError); treat it as a non-batch frame so the caller
        # forwards/logs it like any other unparseable line instead of letting
        # the error crash the pump. Nothing heavy here — the stack is near its
        # limit.
        return [line]
    if isinstance(payload, list):
        return [json.dumps(item, separators=(",", ":")) for item in payload]
    return [line]


def _from_dict(payload: dict[str, Any]) -> tuple[ParsedMessage | None, str]:
    has_method = "method" in payload
    has_result = "result" in payload
    has_error = "error" in payload
    has_id = "id" in payload

    try:
        if has_method and has_id:
            return MCPRequest.model_validate(payload), "request"
        if has_method and not has_id:
            return MCPNotification.model_validate(payload), "notification"
        if has_id and (has_result or has_error):
            kind = "error" if has_error else "response"
            return MCPResponse.model_validate(payload), kind
    except Exception:
        return None, "parse_error"

    return None, "parse_error"


DetectionVerdict = Literal["PASS", "WARN", "BLOCK"]
DetectionAction = Literal["allow", "warn", "block", "rewrite"]
ClassifierLabel = Literal["DATA", "INSTRUCTION"]


class EventRecord(BaseModel):
    """One row of the ``events`` table. Internal — not over the wire.

    The ``det_*`` fields are populated by the inspector (ADR-0004); they
    are all optional and default to ``None`` so a Week 1 caller (no
    detector) builds an event with the original shape.
    """

    model_config = ConfigDict(frozen=True)

    session_id: int
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    direction: Literal["client_to_server", "server_to_client"]
    kind: Literal["request", "response", "notification", "error", "raw", "parse_error"]
    msg_id: str | None = None
    method: str | None = None
    params_json: str | None = None
    result_json: str | None = None
    error_json: str | None = None
    raw: str
    note: str | None = None
    # ADR-0004 detection columns (schema v2). All NULL when the detector is off.
    det_verdict: DetectionVerdict | None = None
    det_score: float | None = None
    det_rules: list[str] | None = None
    det_classifier: ClassifierLabel | None = None
    det_latency_ms: int | None = None
    det_action: DetectionAction | None = None

    @classmethod
    def from_parsed(
        cls,
        *,
        session_id: int,
        direction: Literal["client_to_server", "server_to_client"],
        parsed: ParsedMessage | None,
        kind: str,
        raw: str,
    ) -> EventRecord:
        """Build a row from a parsed message + the original line.

        ``kind`` comes from :func:`parse_frame` and is normalised here against
        the schema CHECK constraint. Anything we don't recognise becomes "raw"
        rather than crashing the proxy.
        """
        normalised_kind = _normalise_kind(kind)

        if parsed is None:
            return cls(
                session_id=session_id,
                direction=direction,
                kind=normalised_kind,
                raw=raw,
            )

        msg_id = _stringify_id(getattr(parsed, "id", None))
        method = getattr(parsed, "method", None)
        params = getattr(parsed, "params", None)
        result = getattr(parsed, "result", None)
        error = getattr(parsed, "error", None)

        return cls(
            session_id=session_id,
            direction=direction,
            kind=normalised_kind,
            msg_id=msg_id,
            method=method,
            params_json=_dump_optional(params),
            result_json=_dump_optional(result),
            error_json=_dump_optional(
                error.model_dump(exclude_none=True) if error is not None else None
            ),
            raw=raw,
        )


def _normalise_kind(
    kind: str,
) -> Literal["request", "response", "notification", "error", "raw", "parse_error"]:
    if kind in ("request", "response", "notification", "error", "parse_error"):
        return kind  # type: ignore[return-value]
    return "raw"


def _stringify_id(value: JsonRpcId) -> str | None:
    """Normalise any JSON-RPC id to a string (the column is TEXT)."""
    if value is None:
        return None
    return str(value)


def _dump_optional(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)
