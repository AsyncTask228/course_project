# logger/process_logger.py
import subprocess
from datetime import datetime
import time
from logger import collector

def get_user():
    return subprocess.getoutput("whoami") or "Unknown"

def log_processes():
    username = get_user()

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        processes = subprocess.getoutput(f"ps -u {username} -o pid=,cmd=").splitlines()

        for line in processes:
            try:
                pid, command = line.strip().split(maxsplit=1)
                collector.log("process_logs", {
                    "timestamp": timestamp,
                    "username": username,
                    "pid": int(pid),
                    "command": command
                })
            except ValueError:
                continue

        time.sleep(5)
