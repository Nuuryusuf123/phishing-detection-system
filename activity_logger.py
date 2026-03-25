import sqlite3
from datetime import datetime
from pathlib import Path

DB = Path("data/app.db")

def log_activity(username, action, details=""):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            action TEXT,
            details TEXT
        )
    """)

    cur.execute(
        "INSERT INTO activity_logs (timestamp, username, action, details) VALUES (?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, action, details)
    )

    conn.commit()
    conn.close()