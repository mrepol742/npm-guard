import sqlite3
from pathlib import Path

DB_PATH = Path("npmguard.db")

# initialize the database and create the scanned_files table if it doesn't exist
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scanned_files (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE,
            sha256 TEXT,
            risk_score INTEGER,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()

# check if a file with the given path and SHA256 hash already exists in the database
def file_exists(path, sha256):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM scanned_files WHERE path=? AND sha256=?",
        (path, sha256)
    )

    result = cur.fetchone()
    conn.close()

    return result is not None

# insert or update a scan result for a file in the database
def insert_scan(path, sha256, risk_score):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT OR REPLACE INTO scanned_files
        (path, sha256, risk_score)
        VALUES (?, ?, ?)
        """,
        (path, sha256, risk_score)
    )

    conn.commit()
    conn.close()
