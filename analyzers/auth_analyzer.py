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

TRUSTED_IPS = ["192.168.", "127.0.0.1", "::1"]
LOGINS_PER_DAY_THRESHOLD = 5

def is_night_time(ts):
    return ts.hour < 6 or ts.hour >= 23

def run():
    alerts = []
    known_mac_by_user = defaultdict(set)
    known_ip_by_user = defaultdict(set)
    mac_to_users = defaultdict(set)
    daily_login_counts = defaultdict(lambda: defaultdict(int))  # user -> date -> count
    login_warned_users = set()  # (user, date)

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT timestamp, username, ip_address, mac_address FROM auth_logs ORDER BY timestamp ASC")
        rows = cursor.fetchall()

        for ts, username, ip, mac in rows:
            ts_dt = ts if isinstance(ts, datetime) else datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            date_only = ts_dt.date()
            risk = 0
            messages = []

            # 1. Вход ночью
            if is_night_time(ts_dt):
                messages.append(f"Ночной вход в {ts_dt.strftime('%H:%M')}")
                risk += 2

            # 2. Внешний IP
            if not any(ip.startswith(prefix) for prefix in TRUSTED_IPS):
                messages.append(f"Подключение с внешнего IP {ip}")
                risk += 3

            # 3. Новый IP (если уже были какие-то IP)
            if known_ip_by_user[username] and ip not in known_ip_by_user[username]:
                messages.append(f"Новый IP для {username}: {ip}")
                risk += 2

            # 4. Новый MAC (если уже были какие-то MAC)
            if known_mac_by_user[username] and mac not in known_mac_by_user[username]:
                messages.append(f"Новый MAC для {username}: {mac}")
                risk += 2

            # 5. Один MAC у нескольких пользователей
            if username not in mac_to_users[mac] and len(mac_to_users[mac]) > 0:
                others = ", ".join(u for u in mac_to_users[mac] if u != username)
                messages.append(f"MAC {mac} используется также пользователями: {others}")
                risk += 3

            # 6. Слишком много логинов в день
            daily_login_counts[username][date_only] += 1
            count = daily_login_counts[username][date_only]
            if count > LOGINS_PER_DAY_THRESHOLD and (username, date_only) not in login_warned_users:
                messages.append(f"{count} логинов за день для {username}")
                risk += 2
                login_warned_users.add((username, date_only))

            # Обновление известной информации
            known_ip_by_user[username].add(ip)
            known_mac_by_user[username].add(mac)
            mac_to_users[mac].add(username)

            if messages:
                alerts.append({
                    "type": "auth",
                    "username": username,
                    "timestamp": ts_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": classify_risk(risk),
                    "risk_score": risk,
                    "message": " | ".join(messages)
                })

        cursor.close()
        conn.close()

    except Exception as e:
        alerts.append({
            "type": "auth",
            "message": f"[ERROR] Анализ auth_logs не удался: {e}",
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
