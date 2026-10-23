# THREATS.md

Ways this system could be broken, what I did, and what I accepted.

## Audit log: tail truncation

**Threat:** Someone with direct access to the database file drops the
`audit_no_delete` trigger and deletes the most recent audit rows. The
remaining rows still form a valid hash chain, so `verify_chain` reports
the log as intact.

**What I did:**
- `audit_log` has triggers that abort any UPDATE or DELETE.
- Each row stores the hash of the previous row, so editing a row, or
  deleting a row in the middle, is detected by `verify_chain`
  (tested in `test_audit.py`).

**What I knowingly accepted:** Deleting the last N rows is NOT detected.
A hash chain alone cannot prove how many rows should exist. A fix would be
to store the latest hash somewhere the database owner cannot write to
(a separate service, or periodic anchoring), but I did not build this
because of the time limit. This attack needs write access to the database
file, which is already a full compromise of the server.

**Test:** None for this case. I am listing it as an open weakness.

## 1. Reading another user's document by changing the ID (IDOR)
**What I did:** Every document route calls `authorize(user, doc, action, db)`. Default is deny. A missing document and a forbidden document both return 404, so IDs cannot be probed.
**Tests:** `test_other_owner_cannot_download`, `test_viewer_without_grant_cannot_download`, `test_anonymous_cannot_download`.

## 2. Access removed but still works (revocation)
**What I did:** Grants are read from the database on every request. Nothing is cached and permissions are not stored in the cookie, only `user_id`. Revoking deletes the grant row.
**Tests:** `test_revoke_takes_effect_immediately`, `test_list_follows_grants`.

## 3. Grantee shares onwards or deletes (privilege escalation)
**What I did:** `share` and `delete` belong to the owner only. An `edit` grant does not include them.
**Tests:** `test_grantee_cannot_share_onwards`, `test_grantee_cannot_delete_document`.

## 4. Path traversal and dangerous filenames
**What I did:** Files are stored under random UUID names, never the user's name. Display names go through `clean_name` (strips paths and `<>"'`).
**Tests:** `test_path_traversal_filename_is_neutralised`.

## 5. Malicious or fake uploads
**What I did:** Extension allow-list (pdf, png, jpg, txt), magic-byte check, 5 MB limit, downloads sent as attachment with `nosniff`.
**Tests:** `test_fake_pdf_is_rejected`, `test_disallowed_extension_is_rejected`.

## 6. Search and list leaking names of others' documents
**What I did:** Every result row is passed through `authorize(..., "view_meta")` before it is returned.
**Tests:** `test_list_hides_other_users_documents`, `test_search_does_not_leak_other_users_documents`.

## 7. Deleted documents still reachable
**What I did:** Soft delete. `authorize` denies everything on a deleted document except admin metadata.
**Tests:** `test_deleted_document_is_unreachable_for_everyone`.

## 8. Admin reading file contents
**What I did:** Admin can only `view_meta`. Admin cannot be granted file access.
**Tests:** `test_admin_cannot_download_file_content`, `test_cannot_grant_file_access_to_admin`.

## 9. Quietly altering the audit trail
**What I did:** Triggers abort UPDATE and DELETE on `audit_log`. Each row stores the hash of the previous row, so edits or middle deletions are detected by `verify_chain`, shown to the admin as `chain_ok`. Denied attempts are logged too.
**Tests:** `test_tampering_is_detected_even_if_trigger_is_dropped`, `test_denied_download_is_audited`.

## 10. SQL injection
**What I did:** All queries use `?` placeholders, including search.

## 11. Role escalation through the session cookie
**What I did:** The cookie stores only `user_id`. Role is read from the database on every request. Cookie is HttpOnly, SameSite=Lax, and Secure on Render.

## Knowingly accepted (not fixed)
- **Tail truncation of the audit log** (see entry above): not detected. Needs an external anchor for the latest hash.
- **No login rate limiting:** brute force is possible. I did not add it for lack of time.
- **No CSRF tokens:** I rely on SameSite=Lax and JSON-only write endpoints.
- **No session expiry or password change:** demo scope.
- **Render free tier:** disk is temporary. Database and files reset on restart or redeploy, and demo users are re-seeded.
- **`SECRET_KEY` falls back to a dev default if the env var is missing.** On Render it is set. A production system should refuse to start without it.
- **Edit permission exists in the model but there is no endpoint that edits file contents.** Only read, download, share, delete are reachable.
- **Audit does not record list or search calls**, only uploads, downloads, grants, revokes, deletes, and denied admin access.
- **No automatic test for the SQL injection or the admin-only audit route beyond the three admin tests.**