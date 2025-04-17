# logger/session_tracker.py

import subprocess
from datetime import datetime
import time
from logger import collector

def get_active_sessions():
    output = subprocess.getoutput("who")
    sessions = {}

    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            username = parts[0]
            terminal = parts[1]
            login_time_str = f"{parts[2]} {parts[3]}"
            remote_host = parts[4] if parts[4].startswith('(') else None
            if remote_host:
                remote_host = remote_host.strip("()")

            # Генерируем уникальный идентификатор сессии
            session_id = f"{username}_{terminal}_{remote_host or 'local'}"

            sessions[session_id] = {
                "username": username,
                "terminal": terminal,
                "login_time": login_time_str,
                "remote_host": remote_host
            }

    return sessions

def track_sessions():
    active_sessions = {}

    while True:
        current_sessions = get_active_sessions()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Новые подключения
        for session_id, data in current_sessions.items():
            if session_id not in active_sessions:
                active_sessions[session_id] = {
                    "username": data["username"],
                    "terminal": data["terminal"],
                    "login_time": now_str,
                    "remote_host": data["remote_host"]
                }

        # Отключения
        finished_sessions = [sid for sid in active_sessions if sid not in current_sessions]
        for session_id in finished_sessions:
            session = active_sessions.pop(session_id)
            collector.log("sessions", {
                "username": session["username"],
                "login_time": session["login_time"],
                "logout_time": now_str,
                "terminal": session["terminal"],
                "remote_host": session["remote_host"]
            })

        time.sleep(5)