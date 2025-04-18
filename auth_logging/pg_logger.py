import psycopg2
from psycopg2 import sql
from datetime import datetime

# Настройки подключения
DB_CONFIG = {
    "dbname": "login_events",
    "user": "auth_logger",
    "password": "your_secure_password",  # замени
    "host": "localhost",
    "port": "5432"
}

# ✅ Логирование локальной авторизации
def log_to_postgres(data):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        insert_query = sql.SQL("""
            INSERT INTO auth_logs (timestamp, username, ip_address, mac_address)
            VALUES (%s, %s, %s, %s)
        """)

        cur.execute(insert_query, (
            data["timestamp"],
            data["username"],
            data["ip_address"],
            data["mac_address"]
        ))

        conn.commit()
        cur.close()
        conn.close()

        print("[PG] Данные успешно записаны в auth_logs")

    except Exception as e:
        print(f"[PG ERROR] Ошибка при логировании в auth_logs: {e}")

# ✅ Логирование SSH
def log_remote_connection(data):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        insert_query = sql.SQL("""
            INSERT INTO remote_connections (timestamp, username, ip_address, port, method, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """)

        cur.execute(insert_query, (
            data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            data.get("username"),
            data.get("ip_address"),
            data.get("port"),
            data.get("method", "ssh"),
            data.get("status")
        ))

        conn.commit()
        cur.close()
        conn.close()

        print("[PG] Записано в remote_connections:", data)

    except Exception as e:
        print(f"[PG ERROR] Ошибка при логировании в remote_connections: {e}")

# Логирование GUI/локальных сессий
def log_session_to_postgres(data):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        insert_query = sql.SQL("""
            INSERT INTO sessions (username, login_time, logout_time, terminal, remote_host)
            VALUES (%s, %s, %s, %s, %s)
        """)

        cur.execute(insert_query, (
            data.get("username"),
            data.get("login_time"),
            data.get("logout_time"),
            data.get("terminal"),
            data.get("remote_host")
        ))

        conn.commit()
        cur.close()
        conn.close()

        print("[PG] Записано в sessions:", data)

    except Exception as e:
        print(f"[PG ERROR] Ошибка при логировании в sessions: {e}")