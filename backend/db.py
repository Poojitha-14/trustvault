import os
import sqlite3
from pathlib import Path

BASE = Path(__file__).parent
DB_PATH = Path(os.environ.get("TRUSTVAULT_DB", BASE / "trustvault.db"))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript((BASE / "schema.sql").read_text())
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database ready:", DB_PATH)