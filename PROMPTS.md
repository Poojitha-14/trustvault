# PROMPTS.md

I used Claude (claude.ai) as a step-by-step guide for this project. Claude explained each step, I applied it myself, and I ran each test myself. Below are the places where the AI was wrong and what happened. All entries are dated 23 Oct 2026 unless stated.

## Context I reused
- I pasted the problem statement and instructions into the chat first and asked for a plan.
- Standing instruction I gave: explain each step in simple words, tell me what to learn, and give me full files instead of fragments.
- Checks I ran on everything the AI gave me: run `pytest -v`, then remove one authorisation check on purpose and confirm tests fail.

## 23 Oct 2026, Entry 1 (authentication / access control)
**Asked:** Explain the login step and how revocation works.
**Produced:** An explanation saying "we put the role in the cookie".
**Wrong:** That sentence was wrong for my code. The cookie only holds `user_id`, and `load_user` reads the role from the database on every request. Putting the role in the cookie would mean a role change or deletion would not take effect immediately. I said the explanation did not make sense to me and the AI corrected it.
**Fixed:** No code change needed (the code was right). I checked `load_user` in `backend/app.py` myself. THREATS.md entry 11 now states the correct design. (commit: <hash of "Add login, logout, session auth and seed users">)

## 23 Oct 2026, Entry 2 (audit trail)
**Asked:** Build an audit log nobody can quietly edit.
**Produced:** Append-only triggers plus a hash chain (`verify_chain`).
**Wrong:** The AI did not mention up front that deleting the last rows (tail truncation) is not detected, because the remaining rows still form a valid chain. It only told me after I asked what a part of the code meant.
**Fixed:** I did not build a fix (it needs an external anchor for the latest hash). I wrote it in THREATS.md as "knowingly accepted" and listed it in the README. (commit: <hash of "Add hash-chained audit log...">)

## 23 Oct 2026, Entry 3 (tests)
**Asked:** Tests for upload/download, grants and admin routes.
**Produced:** `test_api.py` created its own temp database path, while `test_grants.py` and `test_admin.py` used `setdefault`. `db.py` reads the path once at import.
**Wrong:** Running all tests together gave 14 passed and 26 errors (`UNIQUE constraint failed` first, then `database is locked`, and the run took 144 seconds). The cause was in the tests, not in `app.py` or `permissions.py`.
**Fixed:** Added `backend/conftest.py` so all test files share one database path, and removed the duplicate setup from `test_api.py`. Result: 40 passed. (commit: <hash of "Fix shared test database with conftest">)

## 23 Oct 2026, Entry 4 (deployment)
**Asked:** Deploy to Render.
**Produced:** Start command `python seed.py && gunicorn app:app`.
**Wrong:** `seed.py` was not in my repository (the AI gave me the code earlier but never checked that the file existed). Render build succeeded, then the start failed with `can't open file .../backend/seed.py`.
**Fixed:** Created `backend/seed.py`, ran it locally, pushed, and the redeploy went live. (commit: <hash of "Add seed script for demo users">)

## 23 Oct 2026, Entry 5 (how the AI gave code)
**Asked:** Add the upload/download routes.
**Produced:** Code as several small patches ("add this at the top, paste that before the last lines").
**Wrong:** I could not tell where each patch belonged. I told the AI this made it harder for me to learn.
**Fixed:** I asked for full files. After that, `db.py` and `app.py` were replaced as whole files. (commit: <hash of "Add upload, download and list routes...">)

## 23 Oct 2026, Entry 6 (honesty of the record)
**Asked:** Whether the date in my first PROMPTS.md entry should be changed.
**Produced:** The AI confidently said the date "21 Oct" was wrong and told me to change it to 23 Oct.
**Wrong:** The AI guessed. The planning conversation really happened on 21 Oct. I pushed back, and the AI agreed that a date in this file must be the real date of the work, not a guess.
**Fixed:** I did not change the date. Rule I follow now: every date in this file is the real date. (commit: <hash of "Add PROMPTS.md and THREATS.md placeholders">)