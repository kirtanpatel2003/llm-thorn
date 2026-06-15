"""Hash-chained, tamper-evident audit log backed by SQLite.

Every intercepted request writes exactly one entry before the response is
returned to the client. Entries form a hash chain: each entry stores
``sha256(previous_chain_hash + canonical_entry_content)``. Deleting or
modifying any entry breaks the chain, and :meth:`AuditLog.verify` detects it.

This is what makes Thorn viable in regulated industries: compliance teams can
demonstrate log integrity to auditors with ``llm-thorn audit verify``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from llm_thorn.core.models import (
    AuditEntry,
    LayerVerdict,
    PolicyDecision,
    sha256_hex,
)

#: Chain hash seed for the first entry in a fresh database.
GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id        TEXT NOT NULL UNIQUE,
    timestamp       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    request_hash    TEXT NOT NULL,
    response_hash   TEXT,
    verdicts        TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    chain_hash      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);
"""


@dataclass
class VerificationResult:
    """Outcome of an audit chain integrity check."""

    intact: bool
    entries_checked: int
    first_broken_entry: str | None = None
    detail: str = ""


class AuditLog:
    """Append-only, hash-chained audit log.

    Thread-safe: a single instance may be shared across the proxy worker
    and CLI. Writes are serialized with an internal lock and each append is
    committed immediately — an unlogged response is a compliance failure,
    so durability beats batching here.

    Example::

        log = AuditLog("./llm-thorn.db")
        entry = log.append(
            session_id="abc",
            request_hash="...",
            response_hash=None,
            verdicts=[...],
            policy_decision=decision,
        )
        assert log.verify().intact
    """

    def __init__(self, db_path: str | Path) -> None:
        """Open (or create) the audit database at ``db_path``."""
        self._db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def append(
        self,
        session_id: str,
        request_hash: str,
        response_hash: str | None,
        verdicts: list[LayerVerdict],
        policy_decision: PolicyDecision,
        entry_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEntry:
        """Append one entry to the chain and return it.

        The entry's ``chain_hash`` is computed as
        ``sha256(previous_chain_hash + canonical_content)`` where the previous
        hash is :data:`GENESIS_HASH` for the first entry.
        """
        entry = AuditEntry(
            entry_id=entry_id or str(uuid.uuid4()),
            timestamp=timestamp or datetime.now(UTC),
            session_id=session_id,
            request_hash=request_hash,
            response_hash=response_hash,
            verdicts=verdicts,
            policy_decision=policy_decision,
            chain_hash="",
        )
        with self._lock:
            previous = self._last_chain_hash()
            entry.chain_hash = sha256_hex(previous + entry.content_for_hashing())
            self._conn.execute(
                "INSERT INTO audit_log "
                "(entry_id, timestamp, session_id, request_hash, response_hash, "
                " verdicts, policy_decision, chain_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.entry_id,
                    entry.timestamp.isoformat(),
                    entry.session_id,
                    entry.request_hash,
                    entry.response_hash,
                    json.dumps([v.to_dict() for v in entry.verdicts]),
                    json.dumps(entry.policy_decision.to_dict()),
                    entry.chain_hash,
                ),
            )
            self._conn.commit()
        return entry

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> VerificationResult:
        """Walk the full chain and recompute every hash.

        Returns a :class:`VerificationResult` whose ``intact`` flag is False
        if any entry has been modified, deleted, or reordered.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT entry_id, timestamp, session_id, request_hash, response_hash, "
                "verdicts, policy_decision, chain_hash FROM audit_log ORDER BY seq"
            ).fetchall()

        previous = GENESIS_HASH
        for index, row in enumerate(rows):
            entry = _row_to_entry(row)
            expected = sha256_hex(previous + entry.content_for_hashing())
            if expected != entry.chain_hash:
                return VerificationResult(
                    intact=False,
                    entries_checked=index + 1,
                    first_broken_entry=entry.entry_id,
                    detail=(
                        f"chain broken at entry {entry.entry_id} "
                        f"(position {index + 1} of {len(rows)}): "
                        f"stored hash does not match recomputed hash"
                    ),
                )
            previous = entry.chain_hash

        return VerificationResult(
            intact=True,
            entries_checked=len(rows),
            detail=f"all {len(rows)} entries verified",
        )

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def entries(
        self,
        session_id: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        """Fetch entries, newest first, optionally filtered."""
        query = (
            "SELECT entry_id, timestamp, session_id, request_hash, response_hash, "
            "verdicts, policy_decision, chain_hash FROM audit_log"
        )
        clauses: list[str] = []
        params: list[str] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY seq DESC"
        if limit is not None:
            query += f" LIMIT {int(limit)}"

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [_row_to_entry(row) for row in rows]

    def entries_last(self, window: timedelta) -> list[AuditEntry]:
        """Fetch entries from the trailing time window, newest first."""
        return self.entries(since=datetime.now(UTC) - window)

    def count(self) -> int:
        """Total number of entries in the log."""
        with self._lock:
            (n,) = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        return int(n)

    def close(self) -> None:
        """Close the underlying database connection."""
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _last_chain_hash(self) -> str:
        row = self._conn.execute(
            "SELECT chain_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_HASH


def _row_to_entry(row: tuple) -> AuditEntry:
    """Rehydrate an :class:`AuditEntry` from a database row."""
    (
        entry_id,
        timestamp,
        session_id,
        request_hash,
        response_hash,
        verdicts_json,
        decision_json,
        chain_hash,
    ) = row
    verdicts = [LayerVerdict(**v) for v in json.loads(verdicts_json)]
    decision_dict = json.loads(decision_json)
    decision = PolicyDecision(
        action=decision_dict["action"],
        triggered_by=decision_dict["triggered_by"],
        verdicts=[LayerVerdict(**v) for v in decision_dict["verdicts"]],
        session_id=decision_dict["session_id"],
        timestamp=datetime.fromisoformat(decision_dict["timestamp"]),
        audit_entry_id=decision_dict["audit_entry_id"],
    )
    return AuditEntry(
        entry_id=entry_id,
        timestamp=datetime.fromisoformat(timestamp),
        session_id=session_id,
        request_hash=request_hash,
        response_hash=response_hash,
        verdicts=verdicts,
        policy_decision=decision,
        chain_hash=chain_hash,
    )
