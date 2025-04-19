# analyzers/file_analyzer.py

import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logger", "activity_logs.db")

DELETE_BURST_THRESHOLD = 10  # 10 удалений за 60 секунд
MOVE_BURST_THRESHOLD = 8
LONG_ACCESS = 8 * 3600  # 8 часов
SHORT_ACCESS = 1        # менее 1 секунды
NIGHT_HOURS = range(0, 5)

def run():
    alerts = []
    deletes = defaultdict(list)
    moves = defaultdict(list)
    access_paths = defaultdict(set)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, username, file_path, opened, closed, action, details
            FROM file_logs
            ORDER BY timestamp ASC
        """)
        rows = cursor.fetchall()

        for ts, user, path, opened, closed, action, details in rows:
            if isinstance(ts, datetime):
                ts_dt = ts
            else:
                ts_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

            risk = 0
            messages = []

            # 1. Удаления / перемещения
            if action == "deleted":
                deletes[user].append(ts_dt)
                recent = [t for t in deletes[user] if t > ts_dt - timedelta(seconds=60)]
                if len(recent) >= DELETE_BURST_THRESHOLD:
                    messages.append(f"{len(recent)} удалений за 60 секунд")
                    risk += 4

            elif action == "moved":
                moves[user].append(ts_dt)
                recent = [t for t in moves[user] if t > ts_dt - timedelta(seconds=60)]
                if len(recent) >= MOVE_BURST_THRESHOLD:
                    messages.append(f"{len(recent)} перемещений за 60 секунд")
                    risk += 2

            # 2. Время доступа
            if opened and closed:
                opened_dt = datetime.strptime(opened, "%Y-%m-%d %H:%M:%S")
                closed_dt = datetime.strptime(closed, "%Y-%m-%d %H:%M:%S")
                duration = (closed_dt - opened_dt).total_seconds()

                if duration < SHORT_ACCESS:
                    messages.append(f"Очень короткий доступ к файлу ({duration:.3f}s)")
                    risk += 2
                elif duration > LONG_ACCESS:
                    messages.append(f"Очень долгий доступ к файлу ({duration / 3600:.1f} ч.)")
                    risk += 3

            # 3. Ночная активность
            if ts_dt.hour in NIGHT_HOURS:
                if action in ("deleted", "moved", "accessed"):
                    messages.append(f"Операция с файлом ночью ({ts_dt.hour}:00)")
                    risk += 1

            # 4. Новый доступ к пути
            folder = str(Path(path).parent)
            if folder not in access_paths[user]:
                access_paths[user].add(folder)
                if len(access_paths[user]) > 5:
                    messages.append(f"Новый путь доступа к файлам: {folder}")
                    risk += 2

            if messages:
                alerts.append({
                    "type": "file",
                    "username": user,
                    "timestamp": ts,
                    "severity": classify_risk(risk),
                    "risk_score": risk,
                    "message": " | ".join(messages)
                })

        cursor.close()
        conn.close()

    except Exception as e:
        alerts.append({
            "type": "file",
            "username": "system",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "risk_score": 10,
            "message": f"[ERROR] Анализ file_logs не удался: {e}"
        })

    return alerts


def classify_risk(score):
    if score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"
