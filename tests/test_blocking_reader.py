"""Unit tests for :class:`bulwark_mcp.proxy._BlockingReader`.

The blocking fallback reader (used on Windows / when stdin can't attach to an
asyncio ``StreamReader``) wraps a plain ``io.BufferedReader`` whose
``readline()`` is *unbounded*. These tests pin the bound: an oversized frame
must raise :class:`asyncio.LimitOverrunError` (the SAME exception the async
reader raises) AND leave the stream positioned at the next frame, so memory is
never exhausted and the protocol is never corrupted.

We drive the reader directly with an ``io.BytesIO`` — no subprocess needed —
and use a small ``limit`` (64 bytes) so oversized cases are cheap to build.
"""

from __future__ import annotations

import asyncio
import io

import pytest

from bulwark_mcp.proxy import _BlockingReader

LIMIT = 64


def _reader(payload: bytes, *, limit: int = LIMIT) -> _BlockingReader:
    return _BlockingReader(io.BytesIO(payload), limit=limit)


async def test_normal_line_under_limit_returned_with_newline() -> None:
    """A short line comes back verbatim, trailing ``\\n`` included."""
    reader = _reader(b"hello world\n")
    assert await reader.readline() == b"hello world\n"
    # Stream is exhausted afterwards.
    assert await reader.readline() == b""


async def test_multiple_lines_read_in_sequence() -> None:
    """Consecutive normal lines are each returned correctly, in order."""
    reader = _reader(b"one\ntwo\nthree\n")
    assert await reader.readline() == b"one\n"
    assert await reader.readline() == b"two\n"
    assert await reader.readline() == b"three\n"
    assert await reader.readline() == b""


async def test_line_exactly_at_limit_boundary_is_returned() -> None:
    """The largest line that fits is ``limit`` bytes *including* the newline.

    Off-by-one: ``limit - 1`` content bytes + ``\\n`` == ``limit`` bytes total
    is the maximum that ``readline(limit)`` can return while still seeing the
    newline within its budget, so it must come back intact.
    """
    line = b"a" * (LIMIT - 1) + b"\n"  # exactly LIMIT bytes
    assert len(line) == LIMIT
    reader = _reader(line + b"next\n")
    assert await reader.readline() == line
    # The boundary line did not consume into the following frame.
    assert await reader.readline() == b"next\n"


async def test_line_one_over_limit_is_oversized() -> None:
    """``limit`` content bytes + ``\\n`` (== ``limit + 1`` total) is oversized.

    This is the other side of the off-by-one in
    :func:`test_line_exactly_at_limit_boundary_is_returned`: one content byte
    more than the boundary trips the overrun.
    """
    line = b"a" * LIMIT + b"\n"  # LIMIT + 1 bytes total
    reader = _reader(line + b"after\n")
    with pytest.raises(asyncio.LimitOverrunError):
        await reader.readline()
    # Drain left the stream at the next frame.
    assert await reader.readline() == b"after\n"


async def test_oversized_line_raises_and_stream_left_at_next_line() -> None:
    """Core regression: an oversized line raises, then the NEXT line is intact.

    Proves the synchronous drain leaves the stream uncorrupted (positioned at
    the start of the following frame) and that we never buffer the whole
    oversized frame in memory.
    """
    oversized = b"X" * (LIMIT * 10) + b"\n"  # well over the limit
    follow = b'{"jsonrpc":"2.0","id":1}\n'
    reader = _reader(oversized + follow)

    with pytest.raises(asyncio.LimitOverrunError) as excinfo:
        await reader.readline()
    # ``consumed`` reflects the whole oversized line that was read and discarded.
    assert excinfo.value.consumed == len(oversized)

    # The following frame survives intact — protocol not corrupted.
    assert await reader.readline() == follow
    assert await reader.readline() == b""


async def test_oversized_line_drained_in_multiple_chunks() -> None:
    """OOM-prevention proof: a line far larger than ``_DRAIN_CHUNK`` is drained
    in bounded steps, never buffered whole, and the next frame is intact.

    The earlier oversized tests stay under ``_DRAIN_CHUNK`` (64 KiB), so the
    drain ``while`` loop runs only once and the multi-step ``consumed``
    accumulation — the exact mechanism that keeps memory bounded — goes
    unexercised. Here the oversized line spans several ``_DRAIN_CHUNK`` reads,
    forcing the loop to iterate and accumulate.
    """
    # ~3 KiB over three full 64 KiB drain steps → several loop iterations.
    oversized = b"Z" * (_BlockingReader._DRAIN_CHUNK * 3 + 3333) + b"\n"
    assert len(oversized) > _BlockingReader._DRAIN_CHUNK  # forces multi-step drain
    follow = b'{"jsonrpc":"2.0","id":7}\n'
    reader = _reader(oversized + follow)

    with pytest.raises(asyncio.LimitOverrunError) as excinfo:
        await reader.readline()
    # consumed accumulated correctly across every bounded drain step.
    assert excinfo.value.consumed == len(oversized)

    # Stream is positioned exactly at the next frame — no corruption, no OOM.
    assert await reader.readline() == follow
    assert await reader.readline() == b""


async def test_back_to_back_oversized_lines() -> None:
    """Two consecutive oversized lines each raise, and the trailing good frame
    still survives — drain→readline→drain sequencing keeps the stream aligned."""
    big = b"A" * (LIMIT * 5) + b"\n"
    follow = b"ok\n"
    reader = _reader(big + big + follow)

    for _ in range(2):
        with pytest.raises(asyncio.LimitOverrunError) as excinfo:
            await reader.readline()
        assert excinfo.value.consumed == len(big)

    assert await reader.readline() == follow
    assert await reader.readline() == b""


async def test_final_unterminated_line_exactly_at_limit_is_oversized() -> None:
    """Documented off-by-one: a final, newline-less line of EXACTLY ``limit``
    bytes at EOF is classified oversized, not returned as a tail.

    ``readline(limit)`` returns ``limit`` bytes with no ``\\n``, so we cannot
    distinguish it from a truly oversized frame without reading past the limit
    — which is precisely what we refuse to do. The strictly-under-limit tail
    (:func:`test_final_unterminated_line_under_limit_is_returned`) is the one
    that is delivered; reaching the limit trips the overrun. This documents
    that the blocking reader is one byte stricter than the async reader, which
    would return this input as a partial tail.
    """
    line = b"q" * LIMIT  # exactly LIMIT bytes, no newline, then EOF
    reader = _reader(line)

    with pytest.raises(asyncio.LimitOverrunError) as excinfo:
        await reader.readline()
    assert excinfo.value.consumed == LIMIT

    assert await reader.readline() == b""


async def test_oversized_line_without_trailing_newline_before_eof() -> None:
    """Oversized line that never terminates: raise, then a clean ``b""`` EOF."""
    oversized = b"Y" * (LIMIT * 4)  # over the limit, no trailing newline, EOF
    reader = _reader(oversized)

    with pytest.raises(asyncio.LimitOverrunError) as excinfo:
        await reader.readline()
    assert excinfo.value.consumed == len(oversized)

    # Drain ran to EOF; the next read is a clean stream end.
    assert await reader.readline() == b""


async def test_final_unterminated_line_under_limit_is_returned() -> None:
    """A short, newline-less final line (EOF before the limit) is returned.

    Mirrors :meth:`asyncio.StreamReader.readline`, which yields the partial
    tail at EOF rather than treating it as an error.
    """
    reader = _reader(b"no newline here")  # < LIMIT, no '\n', then EOF
    assert await reader.readline() == b"no newline here"
    assert await reader.readline() == b""


async def test_empty_stream_returns_eof() -> None:
    """An empty buffer reads as a clean EOF."""
    reader = _reader(b"")
    assert await reader.readline() == b""


async def test_readline_after_close_returns_eof() -> None:
    """``close()`` flips the flag so subsequent reads short-circuit to EOF."""
    reader = _reader(b"still buffered\n")
    reader.close()
    assert await reader.readline() == b""


class _CloseAfterFirstReadBytesIO(io.BytesIO):
    """A ``BytesIO`` that closes itself right after its first ``readline``.

    Simulates stdin being closed *mid-drain*: the first read serves the
    oversized chunk, the next read hits a genuinely closed file and raises the
    real ``ValueError`` that :class:`_BlockingReader` must absorb as EOF.
    """

    def readline(self, size: int | None = -1, /) -> bytes:
        data = super().readline(size)
        self.close()
        return data


async def test_closed_underlying_file_returns_eof_not_valueerror() -> None:
    """Core regression: stdin closed under us → ``readline`` returns ``b""``
    (clean EOF), never a bare ``ValueError`` — so :func:`_pump` ends instead of
    busy-looping on a repeated ``ValueError``.

    Distinct from :func:`test_readline_after_close_returns_eof`, which trips the
    reader's OWN ``close()`` flag before the file is ever touched. Here the
    reader is NOT close()-flagged; we close the UNDERLYING file so the bounded
    read actually executes and hits ``BufferedReader``'s closed-file
    ``ValueError``.
    """
    buf = io.BytesIO(b'{"jsonrpc":"2.0","id":1}\n')
    reader = _BlockingReader(buf, limit=LIMIT)
    buf.close()  # external close; the reader's own _closed flag stays False

    assert reader._closed is False
    assert await reader.readline() == b""
    # Idempotent: still a clean EOF on the next read — no raise, no spin.
    assert await reader.readline() == b""


async def test_underlying_file_closed_mid_drain_returns_eof() -> None:
    """An oversized line whose stream closes mid-drain returns ``b""`` rather
    than raising into a dead stream — and never leaks the ``ValueError``.

    The first read serves an over-limit chunk (no newline → the drain begins),
    then the file is closed and the drain read raises ``ValueError``, which the
    reader absorbs as a clean end-of-stream.
    """
    payload = b"X" * (LIMIT * 4)  # over the limit, no trailing newline
    reader = _BlockingReader(_CloseAfterFirstReadBytesIO(payload), limit=LIMIT)
    assert await reader.readline() == b""


async def test_oversized_on_open_file_still_raises() -> None:
    """Guard: swallowing closed-file ValueErrors did NOT swallow real overflow.

    On a STILL-OPEN file an over-limit line must still raise
    :class:`asyncio.LimitOverrunError` and leave the stream at the next frame.
    """
    reader = _reader(b"Z" * (LIMIT * 3) + b"\n" + b"next\n")
    with pytest.raises(asyncio.LimitOverrunError):
        await reader.readline()
    assert await reader.readline() == b"next\n"
