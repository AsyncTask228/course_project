# analyzers/session_analyzer.py

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

SHORT_SESSION_THRESHOLD = 10         # сек
LONG_SESSION_THRESHOLD = 8 * 3600    # 8 часов
SESSION_BURST_THRESHOLD = 5          # 5 входов за 1 час

def run():
    alerts = []
    user_sessions = defaultdict(list)

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("SELECT username, login_time, logout_time FROM sessions ORDER BY login_time ASC")
        rows = cursor.fetchall()

        for username, login, logout in rows:
            if not login:
                continue

            login_dt = login if isinstance(login, datetime) else datetime.strptime(login, "%Y-%m-%d %H:%M:%S")

            # 1. Нет logout — возможно, аварийное завершение
            if not logout:
                alerts.append({
                    "type": "session",
                    "username": username,
                    "timestamp": login_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "high",
                    "risk_score": 7,
                    "message": f"Сессия без logout у пользователя {username}"
                })
                continue

            logout_dt = logout if isinstance(logout, datetime) else datetime.strptime(logout, "%Y-%m-%d %H:%M:%S")
            duration = (logout_dt - login_dt).total_seconds()

            # 2. Очень короткая сессия
            if duration < SHORT_SESSION_THRESHOLD:
                alerts.append({
                    "type": "session",
                    "username": username,
                    "timestamp": login_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "medium",
                    "risk_score": 4,
                    "message": f"Очень короткая сессия ({int(duration)} сек)"
                })

            # 3. Очень длинная сессия
            elif duration > LONG_SESSION_THRESHOLD:
                alerts.append({
                    "type": "session",
                    "username": username,
                    "timestamp": login_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "high",
                    "risk_score": 6,
                    "message": f"Слишком долгая сессия ({int(duration / 3600)} часов)"
                })

            # 4. Вход в нерабочее время
            hour = login_dt.hour
            if hour < 6 or hour >= 23:
                alerts.append({
                    "type": "session",
                    "username": username,
                    "timestamp": login_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "medium",
                    "risk_score": 3,
                    "message": f"Вход вне рабочего времени: {hour}:00"
                })

            # 5. Сохраняем для подсчёта частоты входов
            user_sessions[username].append(login_dt)

        # 6. Много сессий за короткое время
        for user, logins in user_sessions.items():
            logins.sort()
            for i in range(len(logins)):
                count = 1
                for j in range(i + 1, len(logins)):
                    if (logins[j] - logins[i]) <= timedelta(hours=1):
                        count += 1
                if count >= SESSION_BURST_THRESHOLD:
                    alerts.append({
                        "type": "session",
                        "username": user,
                        "timestamp": logins[i].strftime("%Y-%m-%d %H:%M:%S"),
                        "severity": "medium",
                        "risk_score": 5,
                        "message": f"{count} сессий у пользователя {user} за 1 час"
                    })
                    break  # один флаг на всплеск хватит

        cursor.close()
        conn.close()

    except Exception as e:
        alerts.append({
            "type": "session",
            "username": "system",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "risk_score": 10,
            "message": f"[ERROR] Анализ session_logs не удался: {e}"
        })

    return alerts
