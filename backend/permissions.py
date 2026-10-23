OWNER_ACTIONS = {"read", "download", "edit", "delete", "share", "view_meta"}
GRANT_ACTIONS = {
    "read": {"read", "download", "view_meta"},
    "edit": {"read", "download", "edit", "view_meta"},
}
ADMIN_ACTIONS = {"view_meta"}


def authorize(user, doc, action, db):
    """Return True only if `user` may do `action` on `doc`. Default is deny."""
    if user is None or doc is None:
        return False

    if doc["deleted_at"] is not None:
        return user["role"] == "admin" and action in ADMIN_ACTIONS

    if doc["owner_id"] == user["id"]:
        return action in OWNER_ACTIONS

    grant = db.execute(
        "SELECT permission FROM grants WHERE document_id = ? AND user_id = ?",
        (doc["id"], user["id"]),
    ).fetchone()
    if grant is not None and action in GRANT_ACTIONS.get(grant["permission"], set()):
        return True

    if user["role"] == "admin":
        return action in ADMIN_ACTIONS

    return False