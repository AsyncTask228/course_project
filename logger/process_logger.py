import os
import time
import psutil
from datetime import datetime
from logger import collector

HISTORY_PATHS = [
    os.path.expanduser("~/.bash_history"),
    os.path.expanduser("~/.zsh_history")
]

IGNORE_PATTERNS = ["ps", "python", "tail", "grep", "sh", "zsh", "bash", "top", "history", "clear"]
last_commands = {}

def get_user():
    try:
        return os.getlogin()
    except:
        return os.getenv("USER") or "unknown"

def read_shell_history():
    history_entries = []
    for path in HISTORY_PATHS:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.read().splitlines()
                    if lines:
                        history_entries.append(lines[-1])
            except Exception:
                continue
    return history_entries

def log_user_commands():
    history = read_shell_history()
    for command in history:
        command = command.strip()
        if not command or any(pat in command for pat in IGNORE_PATTERNS):
            continue
        if command in last_commands:
            continue
        last_commands[command] = True
        collector.log("process_logs", {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": get_user(),
            "pid": -1,
            "command": command
        })
        print(f"[SHELL CMD] {command}")

def log_processes():
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
        try:
            cmd = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else proc.info['name']
            if not cmd or any(pat in cmd for pat in IGNORE_PATTERNS):
                continue
            collector.log("process_logs", {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "username": proc.info['username'] or "unknown",
                "pid": proc.info['pid'],
                "command": cmd
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def log_all(interval=5):
    print("[PROCESS LOGGER] Работаю: shell + psutil")
    while True:
        log_user_commands()
        log_processes()
        time.sleep(interval)