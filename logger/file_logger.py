# logger/file_logger.py
import sqlite3
import os
from datetime import datetime
from inotify_simple import INotify, flags

DB_PATH = os.path.join(os.path.dirname(__file__), "activity_logs.db")
WATCH_DIR = "/home"  # можно указать конкретную директорию

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            file_path TEXT,
            action TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_user():
    return os.getenv("USER") or "unknown"

def log_file_access():
    init_db()
    inotify = INotify()
    watch_flags = flags.MODIFY | flags.OPEN | flags.CLOSE_WRITE
    wd = inotify.add_watch(WATCH_DIR, watch_flags)

    print(f"Watching {WATCH_DIR}...")

    while True:
        for event in inotify.read():
            username = get_user()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            filepath = os.path.join(WATCH_DIR, event.name)
            actions = ",".join(str(flag).split('.')[-1] for flag in flags.from_mask(event.mask))

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                INSERT INTO file_logs (timestamp, username, file_path, action)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, username, filepath, actions))
            conn.commit()
            conn.close()

if __name__ == "__main__":
    log_file_access()
