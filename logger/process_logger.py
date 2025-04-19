import os
import time
import subprocess
from datetime import datetime
from logger import collector

HISTORY_PATH = os.path.expanduser("~/.bash_history")
last_line = ""

IGNORE_PATTERNS = ["ps", "python", "tail", "grep", "ss -tunp", "sh", "zsh", "bash"]

def get_user():
    try:
        return os.getlogin()
    except:
        return subprocess.getoutput("whoami") or "Unknown"

def log_processes(interval=3):
    global last_line
    print("[PROCESS LOGGER] Запущен.")

    while True:
        try:
            with open(HISTORY_PATH, "r") as f:
                lines = f.read().splitlines()
                if lines:
                    current = lines[-1]
                    if current != last_line and not any(ign in current for ign in IGNORE_PATTERNS):
                        last_line = current
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        username = get_user()

                        collector.log("process_logs", {
                            "timestamp": timestamp,
                            "username": username,
                            "pid": -1,
                            "command": current
                        })

        except Exception as e:
            print(f"[PROCESS LOGGER] Ошибка: {e}")

        time.sleep(interval)

if __name__ == "__main__":
    log_processes()
