"""Unit tests for the hash-chained audit log. Tamper evidence is the product."""

from __future__ import annotations

import sqlite3
import time
from datetime import UTC, datetime, timedelta

from llm_thorn.core.audit import AuditLog
from llm_thorn.core.models import LayerVerdict, PolicyDecision, Verdict


def _decision(session_id: str = "s1") -> PolicyDecision:
    return PolicyDecision(
        action="allow",
        triggered_by=[],
        verdicts=[],
        session_id=session_id,
        timestamp=datetime.now(UTC),
        audit_entry_id="d-1",
    )


def _verdicts() -> list[LayerVerdict]:
    return [
        LayerVerdict(
            layer="heuristic",
            verdict=Verdict.BENIGN,
            confidence=0.95,
            reason="no signatures matched",
        )
    ]


def _append(log: AuditLog, session_id: str = "s1", n: int = 1) -> None:
    for i in range(n):
        log.append(
            session_id=session_id,
            request_hash=f"req-hash-{i}",
            response_hash=f"resp-hash-{i}",
            verdicts=_verdicts(),
            policy_decision=_decision(session_id),
        )


class TestEntryQueries:
    def test_session_window_and_limit_combine(self, db_path: str) -> None:
        """`report` relies on entries() filtering by session AND window before
        applying the limit — not slicing first and dropping matches."""
        log = AuditLog(db_path)
        _append(log, session_id="noise", n=5)
        _append(log, session_id="target", n=3)
        rows = log.entries(
            session_id="target",
            since=datetime.now(UTC) - timedelta(hours=24),
            limit=2,
        )
        assert len(rows) == 2
        assert all(e.session_id == "target" for e in rows)
        log.close()


class TestChainIntegrity:
    def test_empty_log_verifies(self, db_path: str) -> None:
        log = AuditLog(db_path)
        result = log.verify()
        assert result.intact
        assert result.entries_checked == 0
        log.close()

    def test_intact_chain_verifies(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, n=20)
        result = log.verify()
        assert result.intact
        assert result.entries_checked == 20
        log.close()

    def test_modified_entry_breaks_chain(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, n=10)
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE audit_log SET request_hash = 'forged' WHERE seq = 5")
        conn.commit()
        conn.close()
        result = log.verify()
        assert not result.intact
        assert result.first_broken_entry is not None
        assert "chain broken" in result.detail
        log.close()

    def test_deleted_entry_breaks_chain(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, n=10)
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM audit_log WHERE seq = 3")
        conn.commit()
        conn.close()
        assert not log.verify().intact
        log.close()

    def test_deleting_last_entry_is_undetectable_but_documented(self, db_path: str) -> None:
        """Truncation from the tail is the known limit of pure hash chains.

        Detecting it requires anchoring the head hash externally — documented
        in docs/architecture.md. This test pins the behavior so a future fix
        is a deliberate change.
        """
        log = AuditLog(db_path)
        _append(log, n=5)
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM audit_log WHERE seq = 5")
        conn.commit()
        conn.close()
        assert log.verify().intact  # remaining prefix is still a valid chain
        log.close()

    def test_reordered_entries_break_chain(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, n=4)
        conn = sqlite3.connect(db_path)
        # Swap the chain hashes of entries 2 and 3 to simulate reordering.
        h2 = conn.execute("SELECT chain_hash FROM audit_log WHERE seq = 2").fetchone()[0]
        h3 = conn.execute("SELECT chain_hash FROM audit_log WHERE seq = 3").fetchone()[0]
        conn.execute("UPDATE audit_log SET chain_hash = ? WHERE seq = 2", (h3,))
        conn.execute("UPDATE audit_log SET chain_hash = ? WHERE seq = 3", (h2,))
        conn.commit()
        conn.close()
        assert not log.verify().intact
        log.close()


class TestEntryStorage:
    def test_blocked_request_has_null_response_hash(self, db_path: str) -> None:
        log = AuditLog(db_path)
        log.append(
            session_id="s1",
            request_hash="req",
            response_hash=None,  # blocked before forwarding
            verdicts=_verdicts(),
            policy_decision=_decision(),
        )
        entry = log.entries()[0]
        assert entry.response_hash is None
        assert log.verify().intact
        log.close()

    def test_entries_rehydrate_fully(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log)
        entry = log.entries()[0]
        assert entry.verdicts[0].layer == "heuristic"
        assert entry.verdicts[0].verdict == Verdict.BENIGN
        assert entry.policy_decision.action == "allow"
        assert entry.chain_hash
        log.close()

    def test_filter_by_session(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, session_id="aaa", n=3)
        _append(log, session_id="bbb", n=2)
        assert len(log.entries(session_id="aaa")) == 3
        assert len(log.entries(session_id="bbb")) == 2
        log.close()

    def test_filter_by_time_window(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, n=3)
        assert len(log.entries_last(timedelta(hours=1))) == 3
        assert len(log.entries_last(timedelta(seconds=0))) == 0
        log.close()

    def test_limit_and_order(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, n=10)
        entries = log.entries(limit=4)
        assert len(entries) == 4
        timestamps = [e.timestamp for e in entries]
        assert timestamps == sorted(timestamps, reverse=True)  # newest first
        log.close()

    def test_count(self, db_path: str) -> None:
        log = AuditLog(db_path)
        _append(log, n=7)
        assert log.count() == 7
        log.close()


def test_write_performance_budget(db_path: str) -> None:
    """Audit write budget: < 5ms per entry."""
    log = AuditLog(db_path)
    _append(log)  # warm-up
    iterations = 50
    start = time.perf_counter()
    _append(log, n=iterations)
    average = (time.perf_counter() - start) / iterations
    log.close()
    assert average < 0.005, f"audit write averaged {average * 1000:.2f}ms (budget 5ms)"
