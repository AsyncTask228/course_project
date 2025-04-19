import psycopg2
from datetime import datetime, timedelta
from collections import defaultdict

DB_CONFIG = {
    "dbname": "login_events",
    "user": "auth_logger",
    "password": "your_secure_password",
    "host": "localhost",
    "port": 5432
}

FAILED_THRESHOLD = 5
ABORTED_THRESHOLD = 3
KNOWN_USERS = ["asynctask", "admin", "root"]


def run():
    alerts = []
    failed_attempts = defaultdict(list)
    aborted_attempts = defaultdict(list)
    known_ips_by_user = defaultdict(set)

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, username, ip_address, port, status
            FROM remote_connections
            WHERE method = 'ssh'
            ORDER BY timestamp ASC
        """)
        rows = cursor.fetchall()

        for ts, username, ip, port, status in rows:
            ts_dt = ts if isinstance(ts, datetime) else datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            risk = 0
            messages = []

            if username not in KNOWN_USERS:
                messages.append(f"Попытка входа с неизвестным пользователем: {username}")
                risk += 3

            if status == "success" and ip not in known_ips_by_user[username]:
                messages.append(f"Новый IP-адрес {ip} у пользователя {username}")
                known_ips_by_user[username].add(ip)
                risk += 2

            if status == "failed":
                failed_attempts[ip].append(ts_dt)
                recent = [t for t in failed_attempts[ip] if t > ts_dt - timedelta(minutes=10)]
                if len(recent) >= FAILED_THRESHOLD:
                    messages.append(f"{len(recent)} неудачных попыток SSH с IP {ip} за 10 минут")
                    risk += 3

            if status == "aborted":
                aborted_attempts[ip].append(ts_dt)
                recent = [t for t in aborted_attempts[ip] if t > ts_dt - timedelta(minutes=10)]
                if len(recent) >= ABORTED_THRESHOLD:
                    messages.append(f"{len(recent)} соединений aborted с IP {ip} за 10 минут")
                    risk += 2

            if status in ("failed", "aborted", "disconnected"):
                count = sum(1 for t in failed_attempts[ip] if t > ts_dt - timedelta(minutes=5))
                if count >= 10:
                    messages.append(f"Массовые подключения с IP {ip} (brute-force?)")
                    risk += 4

            if messages:
                alerts.append({
                    "type": "ssh",
                    "username": username,
                    "timestamp": ts_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "ip_address": ip,
                    "severity": classify_risk(risk),
                    "risk_score": risk,
                    "message": " | ".join(messages)
                })

        cursor.close()
        conn.close()

    except Exception as e:
        alerts.append({
            "type": "ssh",
            "message": f"[ERROR] Анализ ssh логов не удался: {e}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "risk_score": 10,
            "username": "system"
        })

    return alerts


def classify_risk(score):
    if score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"
