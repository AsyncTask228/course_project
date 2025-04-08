# logger/session_tracker.py
import subprocess
from datetime import datetime
import time
from logger import collector

def get_active_users():
    output = subprocess.getoutput("who")
    return set(line.split()[0] for line in output.splitlines())

def track_sessions():
    active_sessions = {}

    while True:
        current_users = get_active_users()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for user in current_users:
            if user not in active_sessions:
                active_sessions[user] = timestamp

        finished = [u for u in active_sessions if u not in current_users]
        for user in finished:
            login_time = active_sessions.pop(user)
            logout_time = timestamp

            collector.log("sessions", {
                "username": user,
                "login_time": login_time,
                "logout_time": logout_time
            })

        time.sleep(5)