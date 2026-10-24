import os
import uuid
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session, g
from werkzeug.security import check_password_hash

from audit import log_event, verify_chain
from db import get_db
from permissions import authorize

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("RENDER") is not None
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

STORAGE = Path(os.environ.get("TRUSTVAULT_STORAGE", Path(__file__).parent / "storage"))
STORAGE.mkdir(parents=True, exist_ok=True)

# extension -> (content type we serve, required first bytes)
ALLOWED = {
    "pdf": ("application/pdf", b"%PDF-"),
    "png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    "jpg": ("image/jpeg", b"\xff\xd8\xff"),
    "txt": ("text/plain", None),
}


def clean_name(raw):
    name = os.path.basename(str(raw).replace("\\", "/"))
    name = "".join(c for c in name if c.isprintable() and c not in "<>\"'`")
    return name[:100]


def access_level(user, doc, db):
    """Ask authorize(): what is the highest thing this user can do here?"""
    for action, label in (("share", "owner"), ("edit", "edit"),
                          ("download", "read"), ("view_meta", "metadata only")):
        if authorize(user, doc, action, db):
            return label
    return "none"


@app.errorhandler(413)
def too_large(e):
    return jsonify(error="file too large (max 5 MB)"), 413


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        db = get_db()
        g.user = db.execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        db.close()


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return jsonify(error="login required"), 401
        return view(*args, **kwargs)
    return wrapper


@app.get("/")
def index():
    return send_from_directory(Path(__file__).parent / "static", "index.html")


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    db = get_db()
    user = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify(error="invalid username or password"), 401

    session.clear()
    session["user_id"] = user["id"]
    return jsonify(status="logged in")


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(status="logged out")


@app.get("/me")
@login_required
def me():
    return jsonify(id=g.user["id"], username=g.user["username"], role=g.user["role"])


@app.post("/documents")
@login_required
def upload():
    db = get_db()
    try:
        if g.user["role"] != "owner":
            log_event(db, g.user["id"], "upload", None, "denied", "role not allowed")
            return jsonify(error="forbidden"), 403

        file = request.files.get("file")
        if file is None or not file.filename:
            return jsonify(error="no file"), 400

        name = clean_name(file.filename)
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext not in ALLOWED:
            log_event(db, g.user["id"], "upload", None, "denied", "type not allowed: " + ext)
            return jsonify(error="file type not allowed"), 400

        content_type, magic = ALLOWED[ext]
        data = file.read()
        if not data:
            return jsonify(error="empty file"), 400
        if magic and not data.startswith(magic):
            log_event(db, g.user["id"], "upload", None, "denied", "content does not match ." + ext)
            return jsonify(error="file content does not match its type"), 400
        if ext == "txt":
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                return jsonify(error="text file must be UTF-8"), 400

        stored_name = uuid.uuid4().hex
        (STORAGE / stored_name).write_bytes(data)
        category = clean_name(request.form.get("category", ""))[:50] or None

        cur = db.execute(
            "INSERT INTO documents (owner_id, name, category, stored_name, size_bytes, content_type) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (g.user["id"], name, category, stored_name, len(data), content_type),
        )
        doc_id = cur.lastrowid
        db.commit()
        log_event(db, g.user["id"], "upload", doc_id, "allowed", name)
        return jsonify(id=doc_id, name=name), 201
    finally:
        db.close()


@app.get("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    db = get_db()
    try:
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not authorize(g.user, doc, "download", db):
            log_event(db, g.user["id"], "download", doc_id, "denied", "not authorised or not found")
            return jsonify(error="not found"), 404

        log_event(db, g.user["id"], "download", doc_id, "allowed", doc["name"])
        resp = send_from_directory(
            STORAGE, doc["stored_name"],
            as_attachment=True, download_name=doc["name"], mimetype=doc["content_type"],
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp
    finally:
        db.close()


@app.get("/documents")
@login_required
def list_documents():
    db = get_db()
    try:
        q = request.args.get("q", "")
        rows = db.execute(
            "SELECT d.id, d.owner_id, d.name, d.category, d.size_bytes, d.deleted_at, "
            "d.created_at, u.username AS owner "
            "FROM documents d JOIN users u ON u.id = d.owner_id "
            "WHERE d.name LIKE ? ORDER BY d.id DESC",
            ("%" + q + "%",),
        ).fetchall()
        visible = [
            {"id": r["id"], "name": r["name"], "category": r["category"],
             "owner": r["owner"], "size_bytes": r["size_bytes"], "created_at": r["created_at"]}
            for r in rows if authorize(g.user, r, "view_meta", db)
        ]
        return jsonify(visible)
    finally:
        db.close()


@app.get("/search")
@login_required
def search_documents():
    db = get_db()
    try:
        q = request.args.get("q", "")
        owner = request.args.get("owner", "")
        category = request.args.get("category", "")
        date_from = request.args.get("from", "")
        date_to = request.args.get("to", "")
        sql = (
            "SELECT d.id, d.owner_id, d.name, d.category, d.size_bytes, d.deleted_at, "
            "d.created_at, u.username AS owner FROM documents d "
            "JOIN users u ON u.id = d.owner_id "
            "WHERE d.name LIKE ? AND u.username LIKE ? AND IFNULL(d.category, '') LIKE ?"
        )
        params = ["%" + q + "%", "%" + owner + "%", "%" + category + "%"]
        if date_from:
            sql += " AND date(d.created_at) >= date(?)"
            params.append(date_from)
        if date_to:
            sql += " AND date(d.created_at) <= date(?)"
            params.append(date_to)
        rows = db.execute(sql + " ORDER BY d.id DESC", params).fetchall()
        return jsonify([
            {"id": r["id"], "name": r["name"], "category": r["category"],
             "owner": r["owner"], "size_bytes": r["size_bytes"],
             "created_at": r["created_at"],
             "access": access_level(g.user, r, db)}
            for r in rows if authorize(g.user, r, "view_meta", db)
        ])
    finally:
        db.close()


@app.post("/documents/<int:doc_id>/grants")
@login_required
def grant_access(doc_id):
    db = get_db()
    try:
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not authorize(g.user, doc, "share", db):
            log_event(db, g.user["id"], "grant", doc_id, "denied", "not authorised or not found")
            return jsonify(error="not found"), 404

        data = request.get_json(silent=True) or {}
        username = str(data.get("username", ""))
        permission = str(data.get("permission", ""))
        if permission not in ("read", "edit"):
            return jsonify(error="permission must be 'read' or 'edit'"), 400

        target = db.execute(
            "SELECT id, role FROM users WHERE username = ?", (username,)
        ).fetchone()
        if target is None:
            return jsonify(error="user not found"), 404
        if target["id"] == doc["owner_id"]:
            return jsonify(error="owner already has full access"), 400
        if target["role"] == "admin":
            return jsonify(error="cannot grant file access to an admin"), 400

        db.execute(
            "INSERT INTO grants (document_id, user_id, permission, granted_by) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(document_id, user_id) DO UPDATE SET "
            "permission = excluded.permission, granted_by = excluded.granted_by, "
            "granted_at = CURRENT_TIMESTAMP",
            (doc_id, target["id"], permission, g.user["id"]),
        )
        db.commit()
        log_event(db, g.user["id"], "grant", doc_id, "allowed", username + ":" + permission)
        return jsonify(status="granted", username=username, permission=permission), 201
    finally:
        db.close()


@app.get("/documents/<int:doc_id>/grants")
@login_required
def list_grants(doc_id):
    db = get_db()
    try:
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not authorize(g.user, doc, "share", db):
            return jsonify(error="not found"), 404
        rows = db.execute(
            "SELECT u.username, gr.permission, gr.granted_at "
            "FROM grants gr JOIN users u ON u.id = gr.user_id "
            "WHERE gr.document_id = ? ORDER BY u.username",
            (doc_id,),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        db.close()


@app.delete("/documents/<int:doc_id>/grants/<username>")
@login_required
def revoke_access(doc_id, username):
    db = get_db()
    try:
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not authorize(g.user, doc, "share", db):
            log_event(db, g.user["id"], "revoke", doc_id, "denied", "not authorised or not found")
            return jsonify(error="not found"), 404

        cur = db.execute(
            "DELETE FROM grants WHERE document_id = ? AND user_id = "
            "(SELECT id FROM users WHERE username = ?)",
            (doc_id, username),
        )
        db.commit()
        if cur.rowcount == 0:
            return jsonify(error="no such grant"), 404
        log_event(db, g.user["id"], "revoke", doc_id, "allowed", username)
        return jsonify(status="revoked", username=username)
    finally:
        db.close()


@app.delete("/documents/<int:doc_id>")
@login_required
def delete_document(doc_id):
    db = get_db()
    try:
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not authorize(g.user, doc, "delete", db):
            log_event(db, g.user["id"], "delete", doc_id, "denied", "not authorised or not found")
            return jsonify(error="not found"), 404

        db.execute(
            "UPDATE documents SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (doc_id,)
        )
        db.commit()
        log_event(db, g.user["id"], "delete", doc_id, "allowed", doc["name"])
        return jsonify(status="deleted")
    finally:
        db.close()


@app.get("/admin/audit")
@login_required
def admin_audit():
    db = get_db()
    try:
        if g.user["role"] != "admin":
            log_event(db, g.user["id"], "admin_audit", None, "denied", "not admin")
            return jsonify(error="not found"), 404
        action = request.args.get("action", "")
        outcome = request.args.get("outcome", "")
        rows = db.execute(
            "SELECT id, at, actor_id, action, document_id, outcome, detail FROM audit_log "
            "WHERE action LIKE ? AND outcome LIKE ? ORDER BY id DESC LIMIT 200",
            ("%" + action + "%", "%" + outcome + "%"),
        ).fetchall()
        ok, bad = verify_chain(db)
        return jsonify(chain_ok=ok, first_bad_row=bad, events=[dict(r) for r in rows])
    finally:
        db.close()


if __name__ == "__main__":
    app.run(port=5000)