# logger/session_tracker.py
import sqlite3
import subprocess
from datetime import datetime
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "activity_logs.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            login_time TEXT,
            logout_time TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_active_users():
    output = subprocess.getoutput("who")
    return set(line.split()[0] for line in output.splitlines())

def track_sessions():
    init_db()
    active_sessions = {}

    while True:
        current_users = get_active_users()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Новые входы
        for user in current_users:
            if user not in active_sessions:
                active_sessions[user] = timestamp
                print(f"[+] Login: {user} at {timestamp}")

        # Завершённые сессии
        finished = [user for user in active_sessions if user not in current_users]
        for user in finished:
            login_time = active_sessions.pop(user)
            logout_time = timestamp
            print(f"[-] Logout: {user} at {logout_time}")

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                INSERT INTO sessions (username, login_time, logout_time)
                VALUES (?, ?, ?)
            ''', (user, login_time, logout_time))
            conn.commit()
            conn.close()

        time.sleep(5)

if __name__ == "__main__":
    track_sessions()
