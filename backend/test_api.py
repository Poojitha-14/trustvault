import io
import os
import tempfile

# Must be set BEFORE importing app/db, so tests never touch the real data
_tmp = tempfile.mkdtemp()
os.environ["TRUSTVAULT_DB"] = os.path.join(_tmp, "test.db")
os.environ["TRUSTVAULT_STORAGE"] = os.path.join(_tmp, "files")

import pytest
from werkzeug.security import generate_password_hash

from app import app
from audit import verify_chain
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
    r = c.post("/login", json={"username": name, "password": "pw"})
    assert r.status_code == 200
    return c


def upload(c, name="a.pdf", data=PDF):
    return c.post("/documents", data={"file": (io.BytesIO(data), name)},
                  content_type="multipart/form-data")


def test_owner_can_upload_and_download_own_file():
    c = login("owner1")
    doc_id = upload(c).get_json()["id"]
    r = c.get(f"/documents/{doc_id}/download")
    assert r.status_code == 200
    assert r.data == PDF


def test_other_owner_cannot_download():
    doc_id = upload(login("owner1")).get_json()["id"]
    assert login("owner2").get(f"/documents/{doc_id}/download").status_code == 404


def test_viewer_without_grant_cannot_download():
    doc_id = upload(login("owner1")).get_json()["id"]
    assert login("viewer1").get(f"/documents/{doc_id}/download").status_code == 404


def test_anonymous_cannot_download():
    doc_id = upload(login("owner1")).get_json()["id"]
    assert app.test_client().get(f"/documents/{doc_id}/download").status_code == 401


def test_admin_cannot_download_file_content():
    doc_id = upload(login("owner1")).get_json()["id"]
    assert login("admin").get(f"/documents/{doc_id}/download").status_code == 404


def test_list_hides_other_users_documents():
    upload(login("owner1"))
    assert login("owner2").get("/documents").get_json() == []
    assert len(login("owner1").get("/documents").get_json()) == 1


def test_denied_download_is_audited():
    doc_id = upload(login("owner1")).get_json()["id"]
    login("owner2").get(f"/documents/{doc_id}/download")
    db = get_db()
    row = db.execute(
        "SELECT outcome FROM audit_log WHERE action = 'download' AND actor_id = 3"
    ).fetchone()
    db.close()
    assert row["outcome"] == "denied"


def test_fake_pdf_is_rejected():
    r = upload(login("owner1"), "evil.pdf", b"this is not a pdf")
    assert r.status_code == 400


def test_disallowed_extension_is_rejected():
    assert upload(login("owner1"), "run.exe", b"MZ....").status_code == 400


def test_path_traversal_filename_is_neutralised():
    r = upload(login("owner1"), "../../x.pdf")
    assert r.status_code == 201
    assert r.get_json()["name"] == "x.pdf"


def test_viewer_cannot_upload():
    assert upload(login("viewer1")).status_code == 403


def test_audit_chain_is_valid_after_activity():
    c = login("owner1")
    doc_id = upload(c).get_json()["id"]
    c.get(f"/documents/{doc_id}/download")
    login("owner2").get(f"/documents/{doc_id}/download")
    db = get_db()
    ok, _ = verify_chain(db)
    db.close()
    assert ok