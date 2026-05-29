import sqlite3
from pathlib import Path

DB_PATH = Path("npmguard.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scanned_files (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE,
            sha256 TEXT,
            risk_score INTEGER,
            findings TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY,
            total INTEGER,
            suspicious INTEGER,
            quarantined INTEGER,
            duration_sec REAL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

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

def insert_scan(path, sha256, risk_score, findings=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR REPLACE INTO scanned_files
        (path, sha256, risk_score, findings)
        VALUES (?, ?, ?, ?)
        """,
        (path, sha256, risk_score, findings)
    )
    conn.commit()
    conn.close()

def record_scan_run(total, suspicious, quarantined, duration_sec):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scan_runs (total, suspicious, quarantined, duration_sec) VALUES (?, ?, ?, ?)",
        (total, suspicious, quarantined, duration_sec)
    )
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) FROM scanned_files").fetchone()[0]
    vulnerable = cur.execute("SELECT COUNT(*) FROM scanned_files WHERE risk_score >= 50").fetchone()[0]
    clean = cur.execute("SELECT COUNT(*) FROM scanned_files WHERE risk_score < 50").fetchone()[0]
    avg_score = cur.execute("SELECT COALESCE(AVG(risk_score), 0) FROM scanned_files").fetchone()[0]
    max_score = cur.execute("SELECT COALESCE(MAX(risk_score), 0) FROM scanned_files").fetchone()[0]
    last_scan = cur.execute("SELECT scanned_at FROM scan_runs ORDER BY id DESC LIMIT 1").fetchone()

    cur.execute("""
        SELECT path, risk_score, scanned_at FROM scanned_files
        WHERE risk_score >= 50 ORDER BY risk_score DESC LIMIT 10
    """)
    top_vulns = [(Path(r[0]).name, r[1], r[2]) for r in cur.fetchall()]

    cur.execute("SELECT COUNT(*), COALESCE(SUM(suspicious), 0), COALESCE(SUM(total), 0) FROM scan_runs")
    run_stats = cur.fetchone()

    conn.close()

    return {
        "total_scanned": total,
        "vulnerable": vulnerable,
        "clean": clean,
        "avg_score": round(avg_score, 1),
        "max_score": max_score,
        "last_scan_at": last_scan[0] if last_scan else "never",
        "total_runs": run_stats[0] if run_stats else 0,
        "total_suspicious_across_runs": run_stats[1] if run_stats else 0,
        "total_packages_across_runs": run_stats[2] if run_stats else 0,
        "top_vulnerable": top_vulns,
    }

def clear_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM scanned_files")
    cur.execute("DELETE FROM scan_runs")
    conn.commit()
    conn.close()
