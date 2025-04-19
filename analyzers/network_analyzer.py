import sqlite3
from datetime import datetime
import ipaddress
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logger", "activity_logs.db")

SUSPICIOUS_PORTS = set(range(0, 20)) | {21, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389}
TRUSTED_PORTS = {80, 443, 22}
SUSPICIOUS_COUNTRIES = {"CN", "KP", "IR", "SY"}  # можно дополнить

# Имитация функции получения страны по IP (в реале можно через geoip2 или ipinfo)
def get_country_for_ip(ip):
    try:
        if ipaddress.ip_address(ip).is_private or ip.startswith("127."):
            return "Local"
        if ip.startswith("66.151."):
            return "US"  # пример
        return "Unknown"
    except:
        return "Unknown"

def is_night_time(ts):
    hour = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").hour
    return hour < 7 or hour >= 23

def run():
    alerts = []

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, username, src_ip, dst_ip, dst_port, protocol, process_name, dst_location
            FROM network_logs
            ORDER BY timestamp ASC
        """)
        rows = cursor.fetchall()

        for ts, username, src_ip, dst_ip, dst_port, proto, proc_name, country in rows:
            risk = 0
            messages = []

            # 1. Подозрительный порт
            try:
                port = int(dst_port)
                if port not in TRUSTED_PORTS and port in SUSPICIOUS_PORTS:
                    messages.append(f"Подключение на подозрительный порт {port}")
                    risk += 3
            except:
                continue

            # 2. Подключение в подозрительную страну
            country = country or get_country_for_ip(dst_ip)
            if country in SUSPICIOUS_COUNTRIES:
                messages.append(f"Подключение в подозрительную страну: {country}")
                risk += 2

            # 3. Ночное время
            if is_night_time(ts):
                messages.append(f"Подключение в ночное время: {ts.split()[1]}")
                risk += 2

            if messages:
                alerts.append({
                    "type": "network",
                    "username": username,
                    "timestamp": ts,
                    "severity": classify_risk(risk),
                    "risk_score": risk,
                    "message": " | ".join(messages) + f" (процесс: {proc_name or 'Unknown'})"
                })

        cursor.close()
        conn.close()

    except Exception as e:
        alerts.append({
            "type": "network",
            "message": f"[ERROR] Анализ network_logs не удался: {e}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "risk_score": 10,
            "username": "system"
        })

    return alerts

def classify_risk(score):
    if score >= 6:
        return "high"
    elif score >= 3:
        return "medium"
    else:
        return "low"
