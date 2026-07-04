"""Tests for the JSON-RPC parser and EventRecord shaping."""

from __future__ import annotations

import json

import pytest

from bulwark_mcp.models import (
    EventRecord,
    MCPNotification,
    MCPRequest,
    MCPResponse,
    parse_frame,
    split_batch,
)


class TestParseFrame:
    def test_parses_request_with_int_id(self) -> None:
        line = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}'
        parsed, kind = parse_frame(line)
        assert kind == "request"
        assert isinstance(parsed, MCPRequest)
        assert parsed.id == 1
        assert parsed.method == "ping"
        assert parsed.params == {}

    def test_parses_request_with_string_id(self) -> None:
        line = '{"jsonrpc":"2.0","id":"abc","method":"tools/list"}'
        parsed, kind = parse_frame(line)
        assert kind == "request"
        assert isinstance(parsed, MCPRequest)
        assert parsed.id == "abc"

    def test_parses_notification(self) -> None:
        line = '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
        parsed, kind = parse_frame(line)
        assert kind == "notification"
        assert isinstance(parsed, MCPNotification)
        assert parsed.method == "notifications/initialized"

    def test_parses_success_response(self) -> None:
        line = '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
        parsed, kind = parse_frame(line)
        assert kind == "response"
        assert isinstance(parsed, MCPResponse)
        assert parsed.result == {"tools": []}
        assert parsed.error is None

    def test_parses_error_response(self) -> None:
        line = '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}'
        parsed, kind = parse_frame(line)
        assert kind == "error"
        assert isinstance(parsed, MCPResponse)
        assert parsed.error is not None
        assert parsed.error.code == -32601
        assert parsed.error.message == "method not found"

    def test_returns_parse_error_for_invalid_json(self) -> None:
        parsed, kind = parse_frame("not json {{{")
        assert parsed is None
        assert kind == "parse_error"

    def test_returns_empty_for_blank_line(self) -> None:
        parsed, kind = parse_frame("   \n")
        assert parsed is None
        assert kind == "empty"

    def test_returns_batch_for_arrays(self) -> None:
        parsed, kind = parse_frame('[{"jsonrpc":"2.0","id":1,"method":"a"}]')
        assert parsed is None
        assert kind == "batch"

    def test_returns_parse_error_for_non_object(self) -> None:
        # JSON-RPC requires an object (or batch); a bare number is invalid
        parsed, kind = parse_frame("42")
        assert parsed is None
        assert kind == "parse_error"

    def test_id_can_be_null_in_error_response(self) -> None:
        line = '{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}'
        parsed, kind = parse_frame(line)
        assert kind == "error"
        assert isinstance(parsed, MCPResponse)
        assert parsed.id is None

    def test_deeply_nested_json_is_parse_error_not_recursion_crash(self) -> None:
        # A deeply nested array (~40k, well under the 8 MiB line limit) overflows
        # json.loads with a RecursionError, which is NOT a JSONDecodeError. It
        # must degrade to a parse error rather than escaping and crashing the pump.
        line = "[" * 40000 + "]" * 40000
        parsed, kind = parse_frame(line)
        assert parsed is None
        assert kind == "parse_error"


class TestSplitBatch:
    def test_splits_a_two_element_batch(self) -> None:
        line = '[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]'
        members = split_batch(line)
        assert len(members) == 2
        for m in members:
            assert json.loads(m)["jsonrpc"] == "2.0"

    def test_returns_singleton_for_non_array(self) -> None:
        line = '{"jsonrpc":"2.0","id":1,"method":"a"}'
        assert split_batch(line) == [line]

    def test_returns_singleton_for_invalid_json(self) -> None:
        line = "garbage"
        assert split_batch(line) == [line]

    def test_deeply_nested_json_is_singleton_not_recursion_crash(self) -> None:
        # json.loads raises RecursionError (not JSONDecodeError) on a deeply
        # nested array; split_batch must treat it as a non-batch frame instead
        # of letting the error escape and crash the pump.
        line = "[" * 40000 + "]" * 40000
        assert split_batch(line) == [line]


class TestEventRecord:
    def test_from_parsed_request_serialises_params(self) -> None:
        parsed, kind = parse_frame('{"jsonrpc":"2.0","id":7,"method":"x","params":{"a":1}}')
        rec = EventRecord.from_parsed(
            session_id=1,
            direction="client_to_server",
            parsed=parsed,
            kind=kind,
            raw='{"jsonrpc":"2.0","id":7,"method":"x","params":{"a":1}}',
        )
        assert rec.kind == "request"
        assert rec.method == "x"
        assert rec.msg_id == "7"  # ids are stringified for the TEXT column
        assert rec.params_json is not None
        assert json.loads(rec.params_json) == {"a": 1}
        assert rec.result_json is None
        assert rec.error_json is None

    def test_from_parsed_handles_unrecognised_kind_as_raw(self) -> None:
        rec = EventRecord.from_parsed(
            session_id=1,
            direction="server_to_client",
            parsed=None,
            kind="some-future-kind",
            raw="weird",
        )
        assert rec.kind == "raw"
        assert rec.raw == "weird"

    def test_from_parsed_error_response(self) -> None:
        parsed, kind = parse_frame(
            '{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"boom","data":{"x":1}}}'
        )
        rec = EventRecord.from_parsed(
            session_id=1,
            direction="server_to_client",
            parsed=parsed,
            kind=kind,
            raw="raw",
        )
        assert rec.kind == "error"
        assert rec.error_json is not None
        decoded = json.loads(rec.error_json)
        assert decoded["code"] == -1
        assert decoded["message"] == "boom"

    def test_rejects_unknown_direction(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 — pydantic ValidationError, but we
            # don't want to import it just for this test
            EventRecord(
                session_id=1,
                direction="sideways",  # type: ignore[arg-type]
                kind="raw",
                raw="x",
            )
