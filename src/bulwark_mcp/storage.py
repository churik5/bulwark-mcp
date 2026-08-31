"""Async SQLite storage for the audit log.

Two layers:

- :class:`Storage` — thin repository over :mod:`aiosqlite`. Knows DDL,
  parameterised inserts, and queries used by the viewer.
- :class:`EventBuffer` — high-level handle the proxy uses. Owns an
  ``asyncio.Queue`` and a single background writer task that flushes to
  :class:`Storage` in batches. The proxy calls :meth:`record` and never
  awaits a database write directly, so DB latency cannot back-pressure
  JSON-RPC traffic (ADR-0002).

Schema versioning
-----------------

``schema_version`` is a write-once log: every time we successfully reach
a new schema, we ``INSERT OR IGNORE`` a row with that version. The current
version is ``MAX(version)``. ADR-0004 lifts this to v2 by adding the
``det_*`` columns and a ``classifier_cache`` table.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Self

import aiosqlite

from .models import EventRecord

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

_PRAGMAS = (
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
    "PRAGMA foreign_keys = ON",
)

# Base DDL = a fresh v1 schema. Migrations below upgrade it to current.
_BASE_DDL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    server_command  TEXT NOT NULL,
    client_pid      INTEGER,
    server_pid      INTEGER,
    exit_code       INTEGER
);

CREATE TABLE IF NOT EXISTS events (
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

CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_method      ON events(method) WHERE method IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_kind        ON events(kind);
"""

# target_version -> ordered DDL to bring a DB from the previous version up.
# Statements are run sequentially in a transaction; ``ALTER TABLE ADD COLUMN``
# duplicates are tolerated to make re-open after a crashed migration safe.
_MIGRATIONS: dict[int, tuple[str, ...]] = {
    2: (
        "ALTER TABLE events ADD COLUMN det_verdict TEXT",
        "ALTER TABLE events ADD COLUMN det_score REAL",
        "ALTER TABLE events ADD COLUMN det_rules TEXT",
        "ALTER TABLE events ADD COLUMN det_classifier TEXT",
        "ALTER TABLE events ADD COLUMN det_latency_ms INTEGER",
        "ALTER TABLE events ADD COLUMN det_action TEXT",
        "CREATE INDEX IF NOT EXISTS idx_events_verdict "
        "ON events(det_verdict) WHERE det_verdict IS NOT NULL",
        """CREATE TABLE IF NOT EXISTS classifier_cache (
            content_hash  TEXT PRIMARY KEY,
            classifier    TEXT NOT NULL,
            score         REAL NOT NULL,
            cached_at     TEXT NOT NULL,
            backend       TEXT NOT NULL DEFAULT 'ollama'
        )""",
        "CREATE INDEX IF NOT EXISTS idx_classifier_cache_cached_at ON classifier_cache(cached_at)",
    ),
}


class Storage:
    """Repository for the audit log. Always open with ``async with``."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    async def __aenter__(self) -> Self:
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def open(self) -> None:
        if self._conn is not None:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(self._db_path)
        conn.row_factory = aiosqlite.Row
        for pragma in _PRAGMAS:
            await conn.execute(pragma)
        await conn.executescript(_BASE_DDL)
        # If schema_version is empty, this is a brand-new DB — record v1 so
        # the migration loop can climb from there. We never INSERT directly
        # at SCHEMA_VERSION here; migrations stamp their own target version.
        await conn.execute("INSERT OR IGNORE INTO schema_version(version) VALUES (1)")
        await conn.commit()
        self._conn = conn
        try:
            await self._run_migrations()
        except BaseException:
            # A failed — or cancelled — migration must not leak the connection
            # we just opened: ``open()`` raises out of ``__aenter__``, so
            # ``async with`` never calls ``__aexit__`` and ``close()`` would
            # never run. Clearing ``_conn`` also means a later ``open()`` on
            # this instance really re-opens instead of returning early on a
            # dead handle; migrations are written to be safe to retry. The
            # ``finally`` guarantees ``_conn`` is cleared even if ``close()``
            # is itself interrupted by a second ``CancelledError`` during a
            # real cancellation.
            try:
                await conn.close()
            finally:
                self._conn = None
            raise

    async def _current_schema_version(self) -> int:
        conn = self._required_conn
        cur = await conn.execute("SELECT MAX(version) AS v FROM schema_version")
        row = await cur.fetchone()
        if row is None or row["v"] is None:
            return 0
        return int(row["v"])

    async def _run_migrations(self) -> None:
        """Apply pending migrations from ``current+1`` up to ``SCHEMA_VERSION``.

        Each migration is wrapped in an explicit transaction so that a
        crash mid-way leaves ``schema_version`` un-bumped — the next open
        will retry from the same starting point. Within a migration, an
        ``ALTER TABLE ADD COLUMN`` whose column already exists (only
        possible after a partial earlier run) is tolerated, which keeps
        the procedure idempotent.
        """
        conn = self._required_conn
        for target in sorted(_MIGRATIONS):
            if target <= await self._current_schema_version():
                continue
            statements = _MIGRATIONS[target]
            logger.info("storage: migrating to schema v%d", target)
            # BEGIN IMMEDIATE acquires the writer lock up front so two
            # concurrently-launching proxies cannot both attempt the same
            # migration. Without it, the second writer races on the
            # ``INSERT INTO schema_version`` and may exit the loop early
            # while the first commit is still in flight.
            await conn.execute("BEGIN IMMEDIATE")
            try:
                for stmt in statements:
                    try:
                        await conn.execute(stmt)
                    except aiosqlite.OperationalError as exc:
                        msg = str(exc).lower()
                        if "duplicate column name" in msg:
                            continue
                        raise
                await conn.execute(
                    "INSERT OR IGNORE INTO schema_version(version) VALUES (?)",
                    (target,),
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def close(self) -> None:
        if self._conn is None:
            return
        await self._conn.close()
        self._conn = None

    @property
    def _required_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Storage is not open; call await Storage.open() first")
        return self._conn

    async def start_session(
        self,
        *,
        server_command: str,
        client_pid: int | None = None,
        server_pid: int | None = None,
    ) -> int:
        conn = self._required_conn
        cur = await conn.execute(
            """
            INSERT INTO sessions (started_at, server_command, client_pid, server_pid)
            VALUES (?, ?, ?, ?)
            """,
            (
                datetime.now(UTC).isoformat(),
                server_command,
                client_pid,
                server_pid,
            ),
        )
        await conn.commit()
        if cur.lastrowid is None:  # pragma: no cover — sqlite always returns an id here
            raise RuntimeError("SQLite did not return a session id")
        return int(cur.lastrowid)

    async def end_session(self, session_id: int, *, exit_code: int | None) -> None:
        conn = self._required_conn
        await conn.execute(
            "UPDATE sessions SET ended_at = ?, exit_code = ? WHERE id = ?",
            (datetime.now(UTC).isoformat(), exit_code, session_id),
        )
        await conn.commit()

    async def set_server_pid(self, session_id: int, server_pid: int) -> None:
        conn = self._required_conn
        await conn.execute(
            "UPDATE sessions SET server_pid = ? WHERE id = ?",
            (server_pid, session_id),
        )
        await conn.commit()

    async def insert_events(self, events: list[EventRecord]) -> None:
        if not events:
            return
        conn = self._required_conn
        await conn.executemany(
            """
            INSERT INTO events (
                session_id, ts, direction, kind, msg_id, method,
                params_json, result_json, error_json, raw, note,
                det_verdict, det_score, det_rules, det_classifier,
                det_latency_ms, det_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    e.session_id,
                    e.ts.isoformat(),
                    e.direction,
                    e.kind,
                    e.msg_id,
                    e.method,
                    e.params_json,
                    e.result_json,
                    e.error_json,
                    e.raw,
                    e.note,
                    e.det_verdict,
                    e.det_score,
                    json.dumps(e.det_rules) if e.det_rules is not None else None,
                    e.det_classifier,
                    e.det_latency_ms,
                    e.det_action,
                )
                for e in events
            ],
        )
        await conn.commit()

    async def latest_events(
        self,
        *,
        limit: int,
        since_id: int | None = None,
        verdict: str | None = None,
    ) -> list[aiosqlite.Row]:
        """Return the most recent ``limit`` events newer than ``since_id``.

        Used by ``logs --tail`` (since_id=None) and ``logs --follow``
        (since_id=last seen). The optional ``verdict`` filter restricts
        to rows whose ``det_verdict`` equals the given label — used by
        ``logs --verdict block`` (ADR-0004).
        """
        conn = self._required_conn
        if since_id is None:
            if verdict is None:
                cur = await conn.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            else:
                cur = await conn.execute(
                    "SELECT * FROM events WHERE det_verdict = ? ORDER BY id DESC LIMIT ?",
                    (verdict, limit),
                )
            rows = list(await cur.fetchall())
            return list(reversed(rows))

        if verdict is None:
            cur = await conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (since_id, limit),
            )
        else:
            cur = await conn.execute(
                "SELECT * FROM events WHERE id > ? AND det_verdict = ? ORDER BY id ASC LIMIT ?",
                (since_id, verdict, limit),
            )
        return list(await cur.fetchall())

    async def event_count(self) -> int:
        conn = self._required_conn
        cur = await conn.execute("SELECT COUNT(*) AS n FROM events")
        row = await cur.fetchone()
        return int(row["n"]) if row is not None else 0

    # ------------------------------------------------------------------
    # Classifier cache (ADR-0004 §4)
    # ------------------------------------------------------------------

    async def lookup_classifier_cache(
        self,
        *,
        content_hash: str,
        ttl_s: int,
    ) -> tuple[str, float] | None:
        """Return ``(classifier, score)`` if a fresh entry exists, else ``None``.

        An entry is "fresh" when ``cached_at`` is within ``ttl_s`` seconds
        of *now*. Stale entries are not deleted here — the v0.3 vacuum
        command will sweep them; for v0.2 they only waste a small amount
        of disk.
        """
        conn = self._required_conn
        cur = await conn.execute(
            "SELECT classifier, score, cached_at FROM classifier_cache WHERE content_hash = ?",
            (content_hash,),
        )
        row = await cur.fetchone()
        if row is None:
            return None
        cached_at = datetime.fromisoformat(row["cached_at"])
        age = (datetime.now(UTC) - cached_at).total_seconds()
        if age > ttl_s:
            return None
        return str(row["classifier"]), float(row["score"])

    async def upsert_classifier_cache(
        self,
        *,
        content_hash: str,
        classifier: str,
        score: float,
        backend: str = "ollama",
    ) -> None:
        conn = self._required_conn
        await conn.execute(
            "INSERT OR REPLACE INTO classifier_cache "
            "(content_hash, classifier, score, cached_at, backend) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                content_hash,
                classifier,
                score,
                datetime.now(UTC).isoformat(),
                backend,
            ),
        )
        await conn.commit()


class EventBuffer:
    """Background writer + bounded queue. Use as ``async with``.

    The proxy calls :meth:`record` from its hot path. We bound the queue
    (``maxsize=queue_max``) and *drop* events with a warning rather than
    block JSON-RPC traffic — see ADR-0002.
    """

    def __init__(
        self,
        storage: Storage,
        *,
        queue_max: int,
        batch_size: int,
        batch_interval_s: float,
    ) -> None:
        self._storage = storage
        self._batch_size = batch_size
        self._batch_interval_s = batch_interval_s
        self._queue: asyncio.Queue[EventRecord | None] = asyncio.Queue(maxsize=queue_max)
        self._writer_task: asyncio.Task[None] | None = None
        self._dropped = 0

    @property
    def dropped(self) -> int:
        return self._dropped

    async def __aenter__(self) -> Self:
        self._writer_task = asyncio.create_task(self._run(), name="bulwark-mcp-writer")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.shutdown()

    def record(self, event: EventRecord) -> None:
        """Non-blocking enqueue. Drops on overflow rather than back-pressuring."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._dropped += 1
            if self._dropped == 1 or self._dropped % 100 == 0:
                logger.warning(
                    "event queue full — dropped %d events so far; raise queue_max",
                    self._dropped,
                )

    async def shutdown(self, *, timeout_s: float = 5.0) -> None:
        if self._writer_task is None:
            return
        if self._writer_task.done():
            self._writer_task = None
            return
        await self._queue.put(None)
        try:
            await asyncio.wait_for(self._writer_task, timeout=timeout_s)
        except TimeoutError:
            logger.warning("writer task did not drain in %.1fs; cancelling", timeout_s)
            self._writer_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await self._writer_task
        except asyncio.CancelledError:  # pragma: no cover
            logger.debug("shutdown was itself cancelled while awaiting writer")
        self._writer_task = None

    async def _run(self) -> None:
        batch: list[EventRecord] = []
        try:
            while True:
                stopping = False
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=self._batch_interval_s)
                except TimeoutError:
                    item = None  # flush whatever we have
                else:
                    if item is None:
                        stopping = True
                    else:
                        batch.append(item)
                        while len(batch) < self._batch_size:
                            try:
                                more = self._queue.get_nowait()
                            except asyncio.QueueEmpty:
                                break
                            if more is None:
                                stopping = True
                                break
                            batch.append(more)

                if batch:
                    try:
                        await self._storage.insert_events(batch)
                    except Exception:
                        logger.exception("failed to flush %d events; dropping", len(batch))
                    batch = []

                if stopping:
                    return
        except asyncio.CancelledError:  # pragma: no cover
            if batch:
                try:
                    await self._storage.insert_events(batch)
                except Exception:
                    logger.exception("failed to flush on cancel")
            raise


async def stream_events(
    storage: Storage,
    *,
    poll_interval_s: float = 0.25,
    initial_tail: int = 20,
) -> AsyncIterator[aiosqlite.Row]:
    """Yield events as they appear. Used by ``logs --follow``.

    Yields the last ``initial_tail`` rows up front (so the user sees recent
    context) and then polls for new rows by id.
    """
    seed = await storage.latest_events(limit=initial_tail)
    cursor = int(seed[-1]["id"]) if seed else 0
    for row in seed:
        yield row
    while True:
        await asyncio.sleep(poll_interval_s)
        rows = await storage.latest_events(limit=500, since_id=cursor)
        for row in rows:
            cursor = int(row["id"])
            yield row
