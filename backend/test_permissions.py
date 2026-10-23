import sqlite3
from pathlib import Path

from permissions import authorize


def make_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript((Path(__file__).parent / "schema.sql").read_text())
    for name, role in [("admin", "admin"), ("owner1", "owner"),
                       ("owner2", "owner"), ("viewer1", "viewer")]:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, 'x', ?)",
            (name, role),
        )
    db.execute(
        "INSERT INTO documents (owner_id, name, stored_name, size_bytes, content_type) "
        "VALUES (2, 'a.pdf', 'abc', 1, 'application/pdf')"
    )
    db.commit()
    return db


def get_user(db, name):
    return db.execute(
        "SELECT id, username, role FROM users WHERE username = ?", (name,)
    ).fetchone()


def get_doc(db):
    return db.execute("SELECT * FROM documents WHERE id = 1").fetchone()


def test_owner_can_do_everything():
    db = make_db()
    assert authorize(get_user(db, "owner1"), get_doc(db), "delete", db)


def test_other_owner_cannot_read():
    db = make_db()
    assert not authorize(get_user(db, "owner2"), get_doc(db), "read", db)


def test_viewer_without_grant_cannot_download():
    db = make_db()
    assert not authorize(get_user(db, "viewer1"), get_doc(db), "download", db)


def test_read_grant_allows_read_but_not_edit():
    db = make_db()
    db.execute("INSERT INTO grants VALUES (1, 4, 'read', 2, CURRENT_TIMESTAMP)")
    viewer, doc = get_user(db, "viewer1"), get_doc(db)
    assert authorize(viewer, doc, "read", db)
    assert not authorize(viewer, doc, "edit", db)


def test_revoke_works_immediately():
    db = make_db()
    db.execute("INSERT INTO grants VALUES (1, 4, 'read', 2, CURRENT_TIMESTAMP)")
    viewer, doc = get_user(db, "viewer1"), get_doc(db)
    assert authorize(viewer, doc, "read", db)
    db.execute("DELETE FROM grants WHERE document_id = 1 AND user_id = 4")
    assert not authorize(viewer, doc, "read", db)


def test_admin_cannot_read_content_but_can_view_meta():
    db = make_db()
    admin, doc = get_user(db, "admin"), get_doc(db)
    assert not authorize(admin, doc, "download", db)
    assert authorize(admin, doc, "view_meta", db)


def test_unknown_action_is_denied():
    db = make_db()
    assert not authorize(get_user(db, "owner1"), get_doc(db), "hack", db)