import subprocess
import re
from datetime import datetime
from auth_logging.pg_logger import log_session_to_postgres

# Словарь активных GUI-сессий (по session ID)
active_sessions = {}

def parse_gui_log(line):
    login_match = re.search(r"New session (\d+) of user (\w+)", line)
    logout_match = re.search(r"Session (\d+) logged out", line)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if login_match:
        session_id = login_match.group(1)
        username = login_match.group(2)
        active_sessions[session_id] = {
            "username": username,
            "login_time": timestamp
        }
        print(f"[GUI LOGIN] session {session_id}, user: {username}")
    
    elif logout_match:
        session_id = logout_match.group(1)
        if session_id in active_sessions:
            session = active_sessions.pop(session_id)
            username = session["username"]
            login_time = session["login_time"]
            logout_time = timestamp

            print(f"[GUI LOGOUT] session {session_id}, user: {username}")

            # Логируем в БД
            log_session_to_postgres({
                "username": username,
                "login_time": login_time,
                "logout_time": logout_time,
                "terminal": f"gui:{session_id}",
                "remote_host": None
            })

def track_gui_sessions():
    print("[GUI TRACKER] Старт отслеживания GUI-сессий через auth.log...")
    process = subprocess.Popen(["tail", "-n", "0", "-F", "/var/log/auth.log"], stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        parse_gui_log(line.strip())

if __name__ == "__main__":
    track_gui_sessions()
