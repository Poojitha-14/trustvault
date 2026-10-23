import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.setdefault("TRUSTVAULT_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("TRUSTVAULT_STORAGE", os.path.join(_tmp, "files"))

import io
import pytest
from werkzeug.security import generate_password_hash

from app import app
from db import get_db, init_db


@pytest.fixture(autouse=True)
def fresh_db():
    path = os.environ["TRUSTVAULT_DB"]
    if os.path.exists(path):
        os.remove(path)
    init_db()
    db = get_db()
    for name, role in [("admin", "admin"), ("owner1", "owner"),
                       ("owner2", "owner"), ("viewer1", "viewer")]:
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   (name, generate_password_hash("pw"), role))
    db.commit()
    db.close()


def login(name):
    c = app.test_client()
    assert c.post("/login", json={"username": name, "password": "pw"}).status_code == 200
    return c


def upload(c, name="a.pdf"):
    return c.post("/documents", data={"file": (io.BytesIO(b"%PDF-1.4 x"), name)},
                  content_type="multipart/form-data")


def test_non_admin_cannot_see_audit():
    assert login("owner1").get("/admin/audit").status_code == 404
    assert login("viewer1").get("/admin/audit").status_code == 404
    assert app.test_client().get("/admin/audit").status_code == 401


def test_admin_sees_activity_and_denied_attempts():
    doc_id = upload(login("owner1")).get_json()["id"]
    login("owner2").get(f"/documents/{doc_id}/download")
    data = login("admin").get("/admin/audit").get_json()
    assert data["chain_ok"] is True
    assert any(e["outcome"] == "denied" for e in data["events"])


def test_search_does_not_leak_other_users_documents():
    upload(login("owner1"), "secret_salary.pdf")
    assert login("owner2").get("/search?q=salary").get_json() == []
    assert len(login("owner1").get("/search?q=salary").get_json()) == 1