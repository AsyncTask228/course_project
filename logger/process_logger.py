# logger/process_logger.py
import sqlite3
import subprocess
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "activity_logs.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS process_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            pid INTEGER,
            command TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_user():
    return subprocess.getoutput("whoami") or "Unknown"

def log_processes():
    init_db()
    username = get_user()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Получаем список активных процессов пользователя
    processes = subprocess.getoutput(f"ps -u {username} -o pid=,cmd=").splitlines()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for line in processes:
        try:
            pid, command = line.strip().split(maxsplit=1)
            c.execute('''
                INSERT INTO process_logs (timestamp, username, pid, command)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, username, int(pid), command))
        except ValueError:
            continue

    conn.commit()
    conn.close()

if __name__ == "__main__":
    log_processes()
