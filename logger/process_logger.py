import subprocess
from datetime import datetime
import time
from logger import collector


# Процессы, которые игнорируем (наши собственные)
IGNORE_PATTERNS = [
    "ps -u", "tail -n", "python", "sh -c", "ss -tunp", "tracker-extract"
]


# Сет для фильтрации повторных процессов
seen = set()

def get_user():
    return subprocess.getoutput("whoami") or "Unknown"

def log_processes(interval=5):
    print("[PROCESS LOGGER] Запущен.")
    global seen

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = get_user()
        processes = subprocess.getoutput(f"ps -u {username} -o pid=,cmd=").splitlines()

        current_seen = set()

        for line in processes:
            try:
                pid, command = line.strip().split(maxsplit=1)
                pid = int(pid)
                key = (pid, command)

                if key in seen:
                    continue

                # Пропускаем "наши" процессы
                if any(ign in command for ign in IGNORE_PATTERNS):
                    continue

                seen.add(key)

                collector.log("process_logs", {
                    "timestamp": timestamp,
                    "username": username,
                    "pid": pid,
                    "command": command
                })

            except ValueError:
                continue

        # Очищаем старые записи, чтобы не накапливались
        seen = seen & current_seen

        time.sleep(interval)