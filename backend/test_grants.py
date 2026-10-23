import io
import os
import tempfile

# setdefault: if test_api.py already set these in this run, keep them
_tmp = tempfile.mkdtemp()
os.environ.setdefault("TRUSTVAULT_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("TRUSTVAULT_STORAGE", os.path.join(_tmp, "files"))

import pytest
from werkzeug.security import generate_password_hash

from app import app
from db import get_db, init_db

PDF = b"%PDF-1.4 test content"


@pytest.fixture(autouse=True)
def fresh_db():
    path = os.environ["TRUSTVAULT_DB"]
    if os.path.exists(path):
        os.remove(path)
    init_db()
    db = get_db()
    for name, role in [("admin", "admin"), ("owner1", "owner"),
                       ("owner2", "owner"), ("viewer1", "viewer")]:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (name, generate_password_hash("pw"), role),
        )
    db.commit()
    db.close()


def login(name):
    c = app.test_client()
    assert c.post("/login", json={"username": name, "password": "pw"}).status_code == 200
    return c


def upload(c, name="a.pdf", data=PDF):
    return c.post("/documents", data={"file": (io.BytesIO(data), name)},
                  content_type="multipart/form-data")


def grant(c, doc_id, username, permission="read"):
    return c.post(f"/documents/{doc_id}/grants",
                  json={"username": username, "permission": permission})


def audit_rows(action):
    db = get_db()
    rows = db.execute("SELECT * FROM audit_log WHERE action = ?", (action,)).fetchall()
    db.close()
    return rows


def test_grant_read_lets_viewer_download():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    viewer = login("viewer1")
    assert viewer.get(f"/documents/{doc_id}/download").status_code == 404
    assert grant(owner, doc_id, "viewer1").status_code == 201
    assert viewer.get(f"/documents/{doc_id}/download").status_code == 200


def test_revoke_takes_effect_immediately():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    grant(owner, doc_id, "viewer1")
    viewer = login("viewer1")
    assert viewer.get(f"/documents/{doc_id}/download").status_code == 200
    r = owner.delete(f"/documents/{doc_id}/grants/viewer1")
    assert r.status_code == 200
    # same logged-in session, same moment: access is gone
    assert viewer.get(f"/documents/{doc_id}/download").status_code == 404


def test_other_owner_cannot_grant():
    doc_id = upload(login("owner1")).get_json()["id"]
    assert grant(login("owner2"), doc_id, "viewer1").status_code == 404
    assert login("viewer1").get(f"/documents/{doc_id}/download").status_code == 404


def test_grantee_cannot_share_onwards():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    grant(owner, doc_id, "viewer1", "edit")
    assert grant(login("viewer1"), doc_id, "owner2").status_code == 404
    assert login("owner2").get(f"/documents/{doc_id}/download").status_code == 404


def test_other_owner_cannot_revoke():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    grant(owner, doc_id, "viewer1")
    r = login("owner2").delete(f"/documents/{doc_id}/grants/viewer1")
    assert r.status_code == 404
    assert login("viewer1").get(f"/documents/{doc_id}/download").status_code == 200


def test_invalid_permission_is_rejected():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    assert grant(owner, doc_id, "viewer1", "admin").status_code == 400


def test_cannot_grant_file_access_to_admin():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    assert grant(owner, doc_id, "admin").status_code == 400
    assert login("admin").get(f"/documents/{doc_id}/download").status_code == 404


def test_grant_and_revoke_are_audited():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    grant(owner, doc_id, "viewer1")
    owner.delete(f"/documents/{doc_id}/grants/viewer1")
    assert [r["outcome"] for r in audit_rows("grant")] == ["allowed"]
    assert [r["outcome"] for r in audit_rows("revoke")] == ["allowed"]


def test_denied_grant_attempt_is_audited():
    doc_id = upload(login("owner1")).get_json()["id"]
    grant(login("owner2"), doc_id, "viewer1")
    rows = audit_rows("grant")
    assert len(rows) == 1
    assert rows[0]["outcome"] == "denied"
    assert rows[0]["actor_id"] == 3


def test_grantee_cannot_delete_document():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    grant(owner, doc_id, "viewer1", "edit")
    assert login("viewer1").delete(f"/documents/{doc_id}").status_code == 404
    assert owner.get(f"/documents/{doc_id}/download").status_code == 200


def test_deleted_document_is_unreachable_for_everyone():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    grant(owner, doc_id, "viewer1")
    assert owner.delete(f"/documents/{doc_id}").status_code == 200
    assert owner.get(f"/documents/{doc_id}/download").status_code == 404
    assert login("viewer1").get(f"/documents/{doc_id}/download").status_code == 404
    assert [r["outcome"] for r in audit_rows("delete")] == ["allowed"]


def test_list_follows_grants():
    owner = login("owner1")
    doc_id = upload(owner).get_json()["id"]
    viewer = login("viewer1")
    assert viewer.get("/documents").get_json() == []
    grant(owner, doc_id, "viewer1")
    assert len(viewer.get("/documents").get_json()) == 1
    owner.delete(f"/documents/{doc_id}/grants/viewer1")
    assert viewer.get("/documents").get_json() == []