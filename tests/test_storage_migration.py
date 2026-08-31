"""Schema v1 → v2 migration tests (ADR-0004 §4).

A v1 database (the Week 1 ship) is constructed by hand here so we never
have to ship a binary fixture. The test then opens it through the live
:class:`Storage` and asserts that:

- the new ``det_*`` columns exist on ``events``;
- the partial index ``idx_events_verdict`` is in place;
- the ``classifier_cache`` table is created;
- the ``schema_version`` table records both ``1`` and ``2``;
- old rows still read fine and have ``NULL`` for the new columns.

The classifier-cache helpers (``lookup`` / ``upsert``) are also
exercised here because they live or die with the migration.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite
import pytest

from bulwark_mcp.models import EventRecord
from bulwark_mcp.storage import Storage

_V1_DDL = """
CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
INSERT INTO schema_version(version) VALUES (1);

CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    server_command  TEXT NOT NULL,
    client_pid      INTEGER,
    server_pid      INTEGER,
    exit_code       INTEGER
);

CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts           TEXT    NOT NULL,
    direction    TEXT    NOT NULL CHECK (direction IN ('client_to_server','server_to_client')),
    kind         TEXT    NOT NULL CHECK (
        kind IN ('request','response','notification','error','raw','parse_error')
    ),
    msg_id       TEXT,
    method       TEXT,
    params_json  TEXT,
    result_json  TEXT,
    error_json   TEXT,
    raw          TEXT    NOT NULL,
    note         TEXT
);
"""


async def _seed_v1_db(path: Path) -> int:
    """Build a Week-1-shaped database with one session and one event."""
    conn = await aiosqlite.connect(path)
    try:
        await conn.executescript(_V1_DDL)
        cur = await conn.execute(
            "INSERT INTO sessions (started_at, server_command) VALUES (?, ?)",
            ("2026-05-04T10:00:00+00:00", "cat"),
        )
        sid = cur.lastrowid
        assert sid is not None
        await conn.execute(
            "INSERT INTO events (session_id, ts, direction, kind, raw) VALUES (?, ?, ?, ?, ?)",
            (sid, "2026-05-04T10:00:01+00:00", "client_to_server", "request", "{}"),
        )
        await conn.commit()
        return int(sid)
    finally:
        await conn.close()


async def _columns(storage: Storage, table: str) -> set[str]:
    conn = storage._required_conn
    cur = await conn.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in await cur.fetchall()}


async def _index_names(storage: Storage, table: str) -> set[str]:
    conn = storage._required_conn
    cur = await conn.execute(f"PRAGMA index_list({table})")
    return {row["name"] for row in await cur.fetchall()}


async def _max_version(storage: Storage) -> int:
    conn = storage._required_conn
    cur = await conn.execute("SELECT MAX(version) AS v FROM schema_version")
    row = await cur.fetchone()
    return int(row["v"]) if row else 0


class TestMigrationFromV1:
    async def test_fresh_db_lands_on_v2(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            assert await _max_version(storage) == 2
            cols = await _columns(storage, "events")
            for new_col in (
                "det_verdict",
                "det_score",
                "det_rules",
                "det_classifier",
                "det_latency_ms",
                "det_action",
            ):
                assert new_col in cols
            indexes = await _index_names(storage, "events")
            assert "idx_events_verdict" in indexes

    async def test_upgrade_preserves_existing_rows(self, tmp_path: Path) -> None:
        db = tmp_path / "old.db"
        await _seed_v1_db(db)

        async with Storage(db) as storage:
            assert await _max_version(storage) == 2
            rows = await storage.latest_events(limit=10)
            assert len(rows) == 1
            row = rows[0]
            assert row["raw"] == "{}"
            # All v2 columns are NULL on a row inserted before migration.
            assert row["det_verdict"] is None
            assert row["det_score"] is None
            assert row["det_action"] is None

    async def test_upgrade_creates_classifier_cache(self, tmp_path: Path) -> None:
        db = tmp_path / "old.db"
        await _seed_v1_db(db)
        async with Storage(db) as storage:
            await storage.upsert_classifier_cache(
                content_hash="a" * 64, classifier="DATA", score=0.1
            )
            hit = await storage.lookup_classifier_cache(content_hash="a" * 64, ttl_s=3600)
        assert hit == ("DATA", 0.1)

    async def test_reopening_a_v2_db_is_idempotent(self, tmp_path: Path) -> None:
        db = tmp_path / "log.db"
        # Open & close three times. If the migration is not idempotent the
        # ALTER TABLE on the second open would raise "duplicate column".
        for _ in range(3):
            async with Storage(db) as storage:
                assert await _max_version(storage) == 2

    async def test_v2_db_records_both_versions_in_history(self, tmp_path: Path) -> None:
        db = tmp_path / "old.db"
        await _seed_v1_db(db)
        async with Storage(db) as storage:
            conn = storage._required_conn
            cur = await conn.execute("SELECT version FROM schema_version ORDER BY version")
            versions = [int(r["version"]) for r in await cur.fetchall()]
        assert versions == [1, 2]

    async def test_partial_migration_recovers_on_reopen(self, tmp_path: Path) -> None:
        """Simulate a crash after some ALTERs landed but before the version bump."""
        db = tmp_path / "old.db"
        await _seed_v1_db(db)
        # Manually apply two of the ALTERs but skip the version stamp.
        conn = await aiosqlite.connect(db)
        try:
            await conn.execute("ALTER TABLE events ADD COLUMN det_verdict TEXT")
            await conn.execute("ALTER TABLE events ADD COLUMN det_score REAL")
            await conn.commit()
        finally:
            await conn.close()
        # Now open through Storage. The v1->v2 migration must finish the job
        # (other ALTERs + index + classifier_cache) without choking on the
        # already-present columns.
        async with Storage(db) as storage:
            assert await _max_version(storage) == 2
            cols = await _columns(storage, "events")
            assert {
                "det_verdict",
                "det_score",
                "det_rules",
                "det_classifier",
                "det_latency_ms",
                "det_action",
            } <= cols


class TestClassifierCache:
    async def test_lookup_returns_none_for_unknown_hash(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            assert (
                await storage.lookup_classifier_cache(content_hash="nope" * 16, ttl_s=60)
            ) is None

    async def test_lookup_respects_ttl(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            await storage.upsert_classifier_cache(
                content_hash="b" * 64, classifier="INSTRUCTION", score=0.9
            )
            # Forge an old cached_at to simulate staleness.
            conn = storage._required_conn
            stale = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
            await conn.execute(
                "UPDATE classifier_cache SET cached_at = ? WHERE content_hash = ?",
                (stale, "b" * 64),
            )
            await conn.commit()
            assert (
                await storage.lookup_classifier_cache(content_hash="b" * 64, ttl_s=86400)
            ) is None

    async def test_upsert_replaces_existing(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            await storage.upsert_classifier_cache(
                content_hash="c" * 64, classifier="DATA", score=0.2
            )
            await storage.upsert_classifier_cache(
                content_hash="c" * 64, classifier="INSTRUCTION", score=0.95
            )
            hit = await storage.lookup_classifier_cache(content_hash="c" * 64, ttl_s=3600)
        assert hit == ("INSTRUCTION", 0.95)


class TestInsertWithVerdict:
    async def test_round_trip_with_detection_columns(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            ev = EventRecord(
                session_id=sid,
                direction="server_to_client",
                kind="response",
                raw="{}",
                method=None,
                msg_id="42",
                det_verdict="BLOCK",
                det_score=0.91,
                det_rules=["role_hijack.ignore_previous"],
                det_classifier="INSTRUCTION",
                det_latency_ms=123,
                det_action="block",
            )
            await storage.insert_events([ev])
            rows = await storage.latest_events(limit=10, verdict="BLOCK")

        assert len(rows) == 1
        row = rows[0]
        assert row["det_verdict"] == "BLOCK"
        assert row["det_score"] == pytest.approx(0.91)
        # det_rules is JSON-encoded at the storage layer.
        assert row["det_rules"] == '["role_hijack.ignore_previous"]'
        assert row["det_classifier"] == "INSTRUCTION"
        assert row["det_latency_ms"] == 123
        assert row["det_action"] == "block"

    async def test_verdict_filter_excludes_non_matches(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            await storage.insert_events(
                [
                    EventRecord(
                        session_id=sid,
                        direction="server_to_client",
                        kind="response",
                        raw="{}",
                        det_verdict="PASS",
                        det_score=0.0,
                        det_action="allow",
                    ),
                    EventRecord(
                        session_id=sid,
                        direction="server_to_client",
                        kind="response",
                        raw="{}",
                        det_verdict="BLOCK",
                        det_score=0.95,
                        det_action="block",
                    ),
                ]
            )
            blocked = await storage.latest_events(limit=10, verdict="BLOCK")
            passed = await storage.latest_events(limit=10, verdict="PASS")
        assert len(blocked) == 1
        assert len(passed) == 1
        assert blocked[0]["det_verdict"] == "BLOCK"
        assert passed[0]["det_verdict"] == "PASS"


class TestFailedMigrationDoesNotLeakConnection:
    """``open()`` must not strand the connection it just opened.

    ``Storage`` is documented "always open with ``async with``", and
    ``async with`` only calls ``__aexit__`` when ``__aenter__`` succeeded.
    So a migration that raises out of ``open()`` means ``close()`` never
    runs: without the guard in ``open()`` the connection stays live in
    ``_conn`` (its worker thread outliving the loop), and the early-return
    guard would later hand that dead handle back to the next ``open()``.
    """

    @staticmethod
    def _failing_migration(
        storage: Storage, exc: BaseException, captured: list[aiosqlite.Connection]
    ) -> Callable[[], Awaitable[None]]:
        """A ``_run_migrations`` stand-in that records the live conn, then raises."""

        async def _run() -> None:
            captured.append(storage._required_conn)
            raise exc

        return _run

    @staticmethod
    async def _drain(storage: Storage, captured: list[aiosqlite.Connection]) -> None:
        """Close whatever the code under test left open.

        A no-op on the passing path — both closes are idempotent — but on a
        regression it stops the leaked aiosqlite worker thread. That thread is
        non-daemon, so without this the assertions below would report the
        failure and then hang the interpreter at exit instead of exiting
        non-zero; a regression must fail red, not time out.
        """
        await storage.close()
        for conn in captured:
            await conn.close()

    async def test_failed_migration_closes_connection_and_clears_conn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        storage = Storage(tmp_path / "log.db")
        captured: list[aiosqlite.Connection] = []
        monkeypatch.setattr(
            storage,
            "_run_migrations",
            self._failing_migration(storage, RuntimeError("migration exploded"), captured),
        )

        try:
            with pytest.raises(RuntimeError, match="migration exploded"):
                async with storage:
                    pass  # pragma: no cover - __aenter__ raises first

            assert storage._conn is None
            # The connection opened by open() was really closed, not just dropped.
            assert len(captured) == 1
            with pytest.raises(ValueError, match=r"(?i)connection"):
                await captured[0].execute("SELECT 1")
        finally:
            await self._drain(storage, captured)

    async def test_reopen_after_crashed_migration_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "log.db"
        storage = Storage(db)
        captured: list[aiosqlite.Connection] = []
        monkeypatch.setattr(
            storage,
            "_run_migrations",
            self._failing_migration(storage, RuntimeError("migration exploded"), captured),
        )

        try:
            with pytest.raises(RuntimeError, match="migration exploded"):
                await storage.open()
            assert storage._conn is None

            # Same instance, real migrations this time: the early-return guard
            # must not strand it on the connection the crashed open() left behind.
            monkeypatch.undo()
            await storage.open()
            assert storage._conn is not None
            assert storage._conn is not captured[0]
            assert await _max_version(storage) == 2
            sid = await storage.start_session(server_command="cat")
            assert sid >= 1
        finally:
            await self._drain(storage, captured)

    async def test_cancelled_migration_closes_connection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        storage = Storage(tmp_path / "log.db")
        captured: list[aiosqlite.Connection] = []
        monkeypatch.setattr(
            storage,
            "_run_migrations",
            self._failing_migration(storage, asyncio.CancelledError(), captured),
        )

        try:
            with pytest.raises(asyncio.CancelledError):
                async with storage:
                    pass  # pragma: no cover - __aenter__ raises first

            assert storage._conn is None
            assert len(captured) == 1
            with pytest.raises(ValueError, match=r"(?i)connection"):
                await captured[0].execute("SELECT 1")
        finally:
            await self._drain(storage, captured)
