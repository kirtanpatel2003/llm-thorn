"""Per-session conversation state tracking, backed by SQLite.

Sessions are how Thorn sees *trajectories* instead of isolated messages.
The context layer (Layer 3) reads the accumulated risk score and event
history from here to catch multi-turn attacks that look benign one message
at a time.

Sessions expire on TTL or when they exceed ``max_turns`` (both configured in
the policy ``defaults`` section). Expired sessions start fresh: the trust a
user builds up cannot be carried past the window, and neither can suspicion
be held forever.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    last_active  TEXT NOT NULL,
    turn_count   INTEGER NOT NULL DEFAULT 0,
    risk_score   REAL NOT NULL DEFAULT 0.0,
    terminated   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS session_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    turn        INTEGER NOT NULL,
    timestamp   TEXT NOT NULL,
    event       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON session_events (session_id);
"""


@dataclass
class SessionContext:
    """A read-only snapshot of one session's state, passed to layers.

    Layers receive this via the ``session`` parameter of ``inspect_input`` /
    ``inspect_output``. It is a snapshot: mutating it does not write back to
    the store. State changes go through :class:`SessionStore`.
    """

    session_id: str
    created_at: datetime
    last_active: datetime
    turn_count: int
    risk_score: float
    terminated: bool
    events: list[dict] = field(default_factory=list)

    @property
    def recent_events(self) -> list[dict]:
        """The last 10 recorded events, oldest first."""
        return self.events[-10:]


class SessionStore:
    """SQLite-backed store for per-session conversation state.

    Reads must stay under 10ms — this store is on the hot path of Layer 3.
    Keep queries indexed and avoid joins on the read path.

    Example::

        store = SessionStore("./llm-thorn.db", ttl_seconds=3600, max_turns=50)
        ctx = store.get_or_create("session-1")
        store.record_turn("session-1", risk_delta=2.5, event={"kind": "probe"})
    """

    def __init__(
        self,
        db_path: str | Path,
        ttl_seconds: int = 3600,
        max_turns: int = 50,
    ) -> None:
        """Open (or create) the session database.

        Args:
            db_path: SQLite file path. May be shared with the audit log.
            ttl_seconds: Idle seconds after which a session is reset.
            max_turns: Turn count after which a session is reset.
        """
        self._db_path = str(db_path)
        self.ttl_seconds = ttl_seconds
        self.max_turns = max_turns
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read path (hot — keep fast)
    # ------------------------------------------------------------------

    def get_or_create(self, session_id: str) -> SessionContext:
        """Fetch a session snapshot, creating or resetting it as needed.

        A session is reset (state wiped, fresh start) when it has exceeded
        the TTL or the max turn count.
        """
        now = datetime.now(UTC)
        with self._lock:
            row = self._conn.execute(
                "SELECT created_at, last_active, turn_count, risk_score, terminated "
                "FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()

            if row is not None:
                created_at = datetime.fromisoformat(row[0])
                last_active = datetime.fromisoformat(row[1])
                expired = (now - last_active) > timedelta(seconds=self.ttl_seconds)
                over_turns = row[2] >= self.max_turns
                if expired or over_turns:
                    self._reset(session_id, now)
                    row = None

            if row is None:
                self._conn.execute(
                    "INSERT OR REPLACE INTO sessions "
                    "(session_id, created_at, last_active, turn_count, risk_score, terminated) "
                    "VALUES (?, ?, ?, 0, 0.0, 0)",
                    (session_id, now.isoformat(), now.isoformat()),
                )
                self._conn.commit()
                return SessionContext(
                    session_id=session_id,
                    created_at=now,
                    last_active=now,
                    turn_count=0,
                    risk_score=0.0,
                    terminated=False,
                    events=[],
                )

            events = [
                json.loads(e)
                for (e,) in self._conn.execute(
                    "SELECT event FROM session_events WHERE session_id = ? "
                    "ORDER BY id DESC LIMIT 25",
                    (session_id,),
                ).fetchall()
            ][::-1]

        return SessionContext(
            session_id=session_id,
            created_at=created_at,
            last_active=last_active,
            turn_count=row[2],
            risk_score=row[3],
            terminated=bool(row[4]),
            events=events,
        )

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def record_turn(
        self,
        session_id: str,
        risk_delta: float = 0.0,
        event: dict | None = None,
    ) -> None:
        """Record one conversation turn against a session.

        Increments the turn count, adds ``risk_delta`` to the accumulated
        risk score (floored at 0), and optionally appends an event for the
        context layer's trajectory analysis.
        """
        now = datetime.now(UTC)
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET turn_count = turn_count + 1, "
                "risk_score = MAX(0.0, risk_score + ?), last_active = ? "
                "WHERE session_id = ?",
                (risk_delta, now.isoformat(), session_id),
            )
            if event is not None:
                (turn,) = self._conn.execute(
                    "SELECT turn_count FROM sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
                self._conn.execute(
                    "INSERT INTO session_events (session_id, turn, timestamp, event) "
                    "VALUES (?, ?, ?, ?)",
                    (session_id, turn, now.isoformat(), json.dumps(event)),
                )
            self._conn.commit()

    def terminate(self, session_id: str) -> None:
        """Mark a session terminated. Further requests on it are blocked."""
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET terminated = 1 WHERE session_id = ?",
                (session_id,),
            )
            self._conn.commit()

    def close(self) -> None:
        """Close the underlying database connection."""
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _reset(self, session_id: str, now: datetime) -> None:
        """Wipe a session's state and events (caller holds the lock)."""
        self._conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        self._conn.execute("DELETE FROM session_events WHERE session_id = ?", (session_id,))
        self._conn.commit()
