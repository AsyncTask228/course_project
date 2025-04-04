# analyzer/anomaly_detector.py
import sqlite3
from datetime import datetime, timedelta
import os
from collections import Counter, defaultdict

DB_PATH = os.path.join(os.path.dirname(__file__), "../logger/activity_logs.db")

def fetch_table(query, params=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(query, params or [])
    rows = cursor.fetchall()
    conn.close()
    return rows

def analyze_auth_activity():
    rows = fetch_table("SELECT timestamp, username, ip_address, mac_address FROM auth_logs")
    user_logins = defaultdict(list)

    for timestamp, username, ip, mac in rows:
        dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        user_logins[username].append((dt, ip, mac))

    for user, records in user_logins.items():
        ips = {ip for _, ip, _ in records}
        macs = {mac for _, _, mac in records}
        hours = [dt.hour for dt, _, _ in records]
        late_hours = [h for h in hours if h < 6 or h > 22]

        print(f"\n🔍 Пользователь: {user}")
        print(f"• Всего входов: {len(records)}")
        print(f"• Уникальных IP: {len(ips)}, MAC: {len(macs)}")
        if late_hours:
            print(f"⚠️ Входы в нетипичное время: {late_hours}")
        if len(ips) > 3:
            print(f"⚠️ Подозрительно много IP-адресов")

def analyze_sessions():
    rows = fetch_table("SELECT username, login_time, logout_time FROM sessions")
    session_durations = defaultdict(list)

    for user, start, end in rows:
        if not end:
            continue
        dt_start = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        dt_end = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
        duration = (dt_end - dt_start).total_seconds() / 60
        session_durations[user].append(duration)

    for user, durations in session_durations.items():
        avg = sum(durations) / len(durations)
        print(f"\n⏳ Сессии пользователя {user}:")
        print(f"• Средняя длительность: {avg:.1f} мин")
        if any(d > avg * 2 for d in durations):
            print(f"⚠️ Есть подозрительно длинные сессии")

def analyze_process_repetition():
    rows = fetch_table("SELECT username, command FROM process_logs")
    user_cmds = defaultdict(list)

    for user, cmd in rows:
        user_cmds[user].append(cmd.split()[0])  # имя команды

    for user, cmds in user_cmds.items():
        counter = Counter(cmds)
        frequent = [cmd for cmd, count in counter.items() if count > 20]
        if frequent:
            print(f"\n🔁 Частые команды у {user}: {frequent}")
            print("⚠️ Возможна автоматизация или скрипт")

def analyze_geo_activity():
    rows = fetch_table("SELECT username, remote_ip, location FROM network_logs")
    user_geo = defaultdict(list)

    for username, ip, location in rows:
        user_geo[username].append(location)

    for user, locations in user_geo.items():
        location_counts = Counter(locations)
        print(f"\n🌍 Геолокация сетевых подключений: {user}")
        print(f"• Страны: {dict(location_counts)}")

        uncommon = [loc for loc in location_counts if loc not in ("RU", "BY", "UA", "Unknown")]
        if uncommon:
            print(f"⚠️ Подозрительные страны: {uncommon}")

def run_all():
    print("=== АНАЛИЗ АКТИВНОСТИ ПОЛЬЗОВАТЕЛЕЙ ===")
    analyze_auth_activity()
    analyze_sessions()
    analyze_process_repetition()
    analyze_geo_activity()
    print("\n✅ Анализ завершён.")

if __name__ == "__main__":
    run_all()
