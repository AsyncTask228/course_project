import sqlite3
import threading
import queue
import os

# Универсальный путь до БД
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "activity_logs.db")
log_queue = queue.Queue()

# Таблицы и допустимые поля
TABLE_FIELDS = {
    "file_logs": ["timestamp", "username", "file_path", "opened", "closed", "action", "details"],
    "auth_logs": ["timestamp", "username", "ip_address", "mac_address"],
    "process_logs": ["timestamp", "username", "pid", "command"],
    "network_logs": ["timestamp", "username", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "process_name", "src_location", "dst_location"],
    "sessions": ["username", "login_time", "logout_time"],
    "device_logs": ["timestamp", "device_name", "device_type", "device_id", "status", "details"]
}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, username TEXT, ip_address TEXT, mac_address TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS process_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, username TEXT, pid INTEGER, command TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS file_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, username TEXT, file_path TEXT, opened TEXT, closed TEXT, action TEXT, details TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS network_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, username TEXT,
        src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT,
        protocol TEXT, process_name TEXT, src_location TEXT, dst_location TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, login_time TEXT, logout_time TEXT
    )''')
    c.execute(''' CREATE TABLE IF NOT EXISTS device_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_name TEXT,
            device_type TEXT,
            device_id TEXT,
            status TEXT,
            details TEXT
    )''')
    conn.commit()
    conn.close()

def log(table, data):
    """Универсальный логер — добавляет данные в очередь"""
    if table not in TABLE_FIELDS:
        print(f"[ERROR] Неизвестная таблица: {table}")
        return

    log_queue.put((table, data))
    print(f"[QUEUE] → table: {table} → data: {data}")

def db_worker():
    """Фоновый поток, пишущий из очереди в базу"""
    while True:
        table, data = log_queue.get()
        try:
            fields = TABLE_FIELDS[table]
            values = [data.get(field) for field in fields]

            placeholders = ", ".join("?" for _ in fields)
            query = f"INSERT INTO {table} ({', '.join(fields)}) VALUES ({placeholders})"

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(query, values)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB ERROR] {e} — table={table}, data={data}")
        finally:
            log_queue.task_done()

def start_worker():
    threading.Thread(target=db_worker, daemon=True).start()