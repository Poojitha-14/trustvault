# TrustVault

Document sharing API where access is decided per document, on the server, every time, and every action (including refused ones) goes into a hash-chained audit log.

**Live:** https://trustvault-poojitha.onrender.com (free tier: first request after idle can take ~1 minute. Data resets on restart.)

## Demo accounts
| Username | Password | Role |
|---|---|---|
| admin | Admin#2026demo | admin |
| owner1 | Owner1#2026demo | owner |
| owner2 | Owner2#2026demo | owner |
| viewer1 | Viewer1#2026demo | viewer |

## Permission model
- **Owner** (the user who uploaded): read, download, edit, delete, share.
- **Grant `read`:** read, download. **Grant `edit`:** same plus edit (no edit endpoint exists yet).
- **Admin:** metadata and audit only. Cannot read file contents and cannot be granted access.
- Everyone else: denied. Denied and missing documents both return 404.
- One function decides everything: `authorize()` in `backend/permissions.py`.

## API (JSON, session cookie)
| Endpoint | Who |
|---|---|
| POST /login, POST /logout | anyone |
| GET /health, GET / | anyone |
| GET /me | logged in |
| POST /documents | role `owner` |
| GET /documents, GET /search | logged in, results filtered by `authorize` |
| GET /documents/<id>/download | owner or grantee |
| POST/GET /documents/<id>/grants | document owner |
| DELETE /documents/<id>/grants/<username> | document owner |
| DELETE /documents/<id> | document owner |
| GET /admin/audit | admin |

## Run locally