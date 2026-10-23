import sqlite3
from pathlib import Path

import pytest

from audit import log_event, verify_chain, GENESIS


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript((Path(__file__).parent / "schema.sql").read_text())
    return conn


def test_empty_log_is_valid(db):
    assert verify_chain(db) == (True, None)


def test_first_row_links_to_genesis(db):
    log_event(db, 1, "upload", 1, "allowed")
    row = db.execute("SELECT prev_hash FROM audit_log").fetchone()
    assert row["prev_hash"] == GENESIS


def test_denied_attempts_are_recorded(db):
    log_event(db, 4, "download", 1, "denied", "no grant")
    row = db.execute("SELECT outcome FROM audit_log").fetchone()
    assert row["outcome"] == "denied"


def test_update_is_blocked_by_trigger(db):
    log_event(db, 1, "upload", 1, "allowed")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE audit_log SET actor_id = 99")


def test_delete_is_blocked_by_trigger(db):
    log_event(db, 1, "upload", 1, "allowed")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM audit_log")


def test_tampering_is_detected_even_if_trigger_is_dropped(db):
    log_event(db, 1, "upload", 1, "allowed")
    log_event(db, 4, "download", 1, "allowed")
    log_event(db, 1, "delete", 1, "allowed")
    assert verify_chain(db) == (True, None)

    db.execute("DROP TRIGGER audit_no_update")
    db.execute("UPDATE audit_log SET actor_id = 99 WHERE id = 2")
    db.commit()

    ok, bad_id = verify_chain(db)
    assert ok is False
    assert bad_id == 2