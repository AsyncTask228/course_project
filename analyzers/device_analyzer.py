# analyzers/device_analyzer.py

import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logger", "activity_logs.db")

UNKNOWN_DEVICES = set()
FREQUENT_EVENT_THRESHOLD = 4  # 4 события за 60 сек
NIGHT_HOURS = range(0, 5)

def run():
    alerts = []
    device_events = defaultdict(list)  # device_id → [timestamps]
    known_devices = set()

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, device_name, device_type, device_id, status, details
            FROM device_logs
            ORDER BY timestamp ASC
        """)
        rows = cursor.fetchall()

        for ts, name, dtype, devid, status, details in rows:
            if isinstance(ts, datetime):
                ts_dt = ts
            else:
                ts_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

            risk = 0
            messages = []

            # 1. Частые подключения/отключения
            device_events[devid] = [t for t in device_events[devid] if t > ts_dt - timedelta(seconds=60)]
            device_events[devid].append(ts_dt)
            if len(device_events[devid]) >= FREQUENT_EVENT_THRESHOLD:
                messages.append(f"{len(device_events[devid])} событий за минуту для {devid}")
                risk += 3

            # 2. Вставка ночью
            if ts_dt.hour in NIGHT_HOURS and status == "connected":
                messages.append(f"Подключение устройства ночью ({ts_dt.hour}:00)")
                risk += 2

            # 3. Неизвестное устройство
            key = (name, devid)
            if status == "connected" and key not in known_devices:
                known_devices.add(key)
                if len(known_devices) > 3:  # первые 3 не тревожим
                    messages.append(f"Новое USB-устройство: {name} ({devid})")
                    risk += 4

            if messages:
                alerts.append({
                    "type": "device",
                    "username": "system",  # или можно сохранить владельца, если будешь расширять
                    "timestamp": ts,
                    "severity": classify_risk(risk),
                    "risk_score": risk,
                    "message": " | ".join(messages)
                })

        cursor.close()
        conn.close()

    except Exception as e:
        alerts.append({
            "type": "device",
            "username": "system",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "risk_score": 10,
            "message": f"[ERROR] Анализ device_logs не удался: {e}"
        })

    return alerts


def classify_risk(score):
    if score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"
