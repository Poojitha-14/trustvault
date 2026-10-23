import hashlib
import json
from datetime import datetime, timezone

GENESIS = "0" * 64


def _fingerprint(prev_hash, at, actor_id, action, document_id, outcome, detail):
    payload = json.dumps(
        [prev_hash, at, actor_id, action, document_id, outcome, detail],
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(db, actor_id, action, document_id, outcome, detail=""):
    """Append one row to the audit log. Always commits, even for denied attempts."""
    detail = str(detail)[:500]
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    last = db.execute(
        "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = last["hash"] if last else GENESIS
    at = datetime.now(timezone.utc).isoformat()
    new_hash = _fingerprint(prev_hash, at, actor_id, action, document_id, outcome, detail)
    db.execute(
        "INSERT INTO audit_log (at, actor_id, action, document_id, outcome, detail, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (at, actor_id, action, document_id, outcome, detail, prev_hash, new_hash),
    )
    db.commit()


def verify_chain(db):
    """Return (True, None) if the chain is intact, else (False, id_of_first_bad_row)."""
    expected_prev = GENESIS
    for row in db.execute("SELECT * FROM audit_log ORDER BY id"):
        if row["prev_hash"] != expected_prev:
            return False, row["id"]
        recomputed = _fingerprint(
            row["prev_hash"], row["at"], row["actor_id"], row["action"],
            row["document_id"], row["outcome"], row["detail"],
        )
        if recomputed != row["hash"]:
            return False, row["id"]
        expected_prev = row["hash"]
    return True, None