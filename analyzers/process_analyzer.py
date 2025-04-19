# analyzers/process_analyzer.py
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logger", "activity_logs.db")
REPEATED_COMMAND_THRESHOLD = 3

SUSPICIOUS_KEYWORDS = [
    "rm -rf", "wget", "curl", "nc ", "ncat", "netcat", "nmap",
    "bash -i", "mkfs", "dd if=", "chmod 777", "useradd", "passwd",
    "scp ", "ftp ", "telnet", "chattr", "python -c", "perl -e",
    "base64 -d", "killall", "pkill", "reboot", "shutdown"
]

SAFE_PROCESSES = [
    "zsh", "/usr/bin/zsh", "/usr/share/code/", "Telegram", "yandex_browser",
    "at-spi-bus-launcher", "code", "firefox", "chrome", "libexec"
]


def is_suspicious(command):
    cmd_lower = command.lower()
    if any(proc in cmd_lower for proc in SAFE_PROCESSES):
        return False
    return any(keyword in cmd_lower for keyword in SUSPICIOUS_KEYWORDS)


def run():
    alerts = []
    command_timestamps = defaultdict(list)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, username, pid, command
            FROM process_logs
            ORDER BY timestamp ASC
        """)
        rows = cursor.fetchall()

        for ts, username, pid, command in rows:
            ts_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            key = (username, command)
            command_timestamps[key].append(ts_dt)

            command_timestamps[key] = [t for t in command_timestamps[key] if t > ts_dt - timedelta(seconds=5)]

            if len(command_timestamps[key]) >= REPEATED_COMMAND_THRESHOLD:
                if not any(proc in command.lower() for proc in SAFE_PROCESSES):
                    alerts.append({
                        "type": "process",
                        "username": username,
                        "timestamp": ts,
                        "severity": "medium",
                        "risk_score": 4,
                        "message": f"{len(command_timestamps[key])} повторов команды за 5 сек: {command}"
                    })
                command_timestamps[key] = []

            if is_suspicious(command):
                alerts.append({
                    "type": "process",
                    "username": username,
                    "timestamp": ts,
                    "severity": "high",
                    "risk_score": 6,
                    "message": f"Обнаружена подозрительная команда: {command}"
                })

        cursor.close()
        conn.close()

    except Exception as e:
        alerts.append({
            "type": "process",
            "username": "system",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "risk_score": 10,
            "message": f"[ERROR] Анализ process_logs не удался: {e}"
        })

    return alerts
