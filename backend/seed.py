from werkzeug.security import generate_password_hash

from db import get_db, init_db

USERS = [
    ("admin", "Admin#2026demo", "admin"),
    ("owner1", "Owner1#2026demo", "owner"),
    ("owner2", "Owner2#2026demo", "owner"),
    ("viewer1", "Viewer1#2026demo", "viewer"),
]

init_db()
db = get_db()
for username, password, role in USERS:
    db.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), role),
    )
db.commit()
db.close()
print("Seeded users")