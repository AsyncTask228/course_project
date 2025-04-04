# logger/db_logger.py
import sqlite3
import subprocess
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "activity_logs.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Таблица для логов аутентификации
    c.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            ip_address TEXT,
            mac_address TEXT
        )
    ''')

    conn.commit()
    conn.close()

def get_mac():
    try:
        output = subprocess.getoutput("ip link show | grep 'link/ether'")
        return output.split()[1] if output else "MAC не найден"
    except Exception:
        return "Ошибка"

def get_user():
    try:
        return subprocess.getoutput("whoami") or "Unknown"
    except Exception:
        return "Unknown"

def log_auth():
    init_db()
    username = get_user()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = subprocess.getoutput("hostname -I").split()[0]
    mac = get_mac()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO auth_logs (timestamp, username, ip_address, mac_address)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, username, ip, mac))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    log_auth()
