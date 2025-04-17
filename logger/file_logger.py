import os
import time
from datetime import datetime
from pathlib import Path
from inotify_simple import INotify, flags
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemMovedEvent
from logger import collector

WATCH_DIR = "/home/asynctask"
TRASH_DIR = os.path.expanduser("~/.local/share/Trash/files")

IGNORED_DIRS = [".cache", ".config", ".local", ".vscode", "__pycache__", "courses work", ".ssh"]
IGNORED_EXT = (".tmp", ".swp", ".lock", ".part", ".db-wal", ".db-shm")
IGNORED_PREFIX = ("~", ".goutputstream", ".Trash", ".")

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".svg", ".bmp", ".webp")

open_files = {}
lock_file_map = {}
recent_actions = {}

IGNORED_PATH_CONTAINS = [
    ".mozilla", ".thunderbird", ".config", ".cache",
    ".local", ".var", "snap", "libreoffice/share", ".vscode",
    "firefox", "key4.db", "cert9.db", "places.sqlite", ".sqlite",
    ".db-wal", ".db-shm", ".lock", "tmp"
]

def get_user():
    return os.getenv("USER") or "unknown"

def is_ignored(path: str) -> bool:
    try:
        abs_path = Path(path).resolve()
        rel_path = abs_path.relative_to(Path(WATCH_DIR).resolve())
    except Exception:
        return True

    for part in rel_path.parts:
        if part in IGNORED_DIRS or any(pattern in str(abs_path) for pattern in IGNORED_PATH_CONTAINS):
            return True

    filename = abs_path.name
    return (
        filename.endswith(IGNORED_EXT)
        or filename.startswith(IGNORED_PREFIX)
    )

def is_image(path: str) -> bool:
    return Path(path).suffix.lower() in IMAGE_EXT

def is_lock_file(path: str) -> bool:
    name = Path(path).name
    return name.startswith(".~lock.") and name.endswith("#")

def get_original_from_lock(path: str) -> str | None:
    name = Path(path).name
    if not is_lock_file(path):
        return None
    real_name = name.replace(".~lock.", "").rstrip("#")
    return str(Path(path).parent / real_name)

def log_to_db(file_path, opened_time, closed_time):
    duration = (closed_time - opened_time).total_seconds()
    if duration < 0.001:
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    collector.log("file_logs", {
        "timestamp": timestamp,
        "username": get_user(),
        "file_path": file_path,
        "opened": opened_time.strftime("%Y-%m-%d %H:%M:%S"),
        "closed": closed_time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "accessed",
        "details": f"duration: {duration:.6f}s"
    })
    print(f"[LOGGED] accessed — {file_path}")

def log_action(file_path, action, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    collector.log("file_logs", {
        "timestamp": timestamp,
        "username": get_user(),
        "file_path": file_path,
        "opened": None,
        "closed": None,
        "action": action,
        "details": details
    })
    print(f"[LOGGED] {action.upper()} — {file_path}")

# inotify: OPEN / CLOSE
def monitor_inotify():
    print("🧠 inotify: отслеживание OPEN/CLOSE")
    inotify = INotify()
    watch_flags = flags.OPEN | flags.CLOSE_WRITE | flags.CLOSE_NOWRITE
    wd_map = {}

    for root, dirs, _ in os.walk(WATCH_DIR):
        if any(part in Path(root).parts for part in IGNORED_DIRS):
            continue
        wd = inotify.add_watch(root, watch_flags)
        wd_map[wd] = root

    while True:
        for event in inotify.read(timeout=1000):
            wd_path = wd_map.get(event.wd)
            if not wd_path or not event.name:
                continue

            file_path = os.path.join(wd_path, event.name)
            if os.path.isdir(file_path) or is_ignored(file_path):
                continue

            # LibreOffice: если файл отслеживается через .lock — игнор
            if file_path in lock_file_map:
                continue

            # Если lock-файл существует — отслеживаем его отдельно
            lock_path = os.path.join(os.path.dirname(file_path), f".~lock.{Path(file_path).name}#")
            if os.path.exists(lock_path):
                lock_file_map[file_path] = datetime.now()
                continue

            # Условие для игнорирования дублированных открытий
            if file_path in recent_actions:
                if (datetime.now() - recent_actions[file_path]).total_seconds() < 1:
                    continue

            now = datetime.now()
            mask = flags.from_mask(event.mask)

            if flags.OPEN in mask:
                if is_image(file_path):
                    continue
                open_files[file_path] = now
            elif flags.CLOSE_WRITE in mask or flags.CLOSE_NOWRITE in mask:
                opened_time = open_files.pop(file_path, None)
                if opened_time:
                    log_to_db(file_path, opened_time, now)

        time.sleep(0.05)

# Watchdog: created / deleted / moved + lock-обработка
class FileLoggerHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or is_ignored(event.src_path):
            return

        if is_lock_file(event.src_path):
            original = get_original_from_lock(event.src_path)
            if original and not is_ignored(original):
                lock_file_map[original] = datetime.now()
                print(f"[LOCK CREATED] → {original}")
            return

        recent_actions[event.src_path] = datetime.now()
        log_action(event.src_path, "created")

    def on_deleted(self, event):
        if event.is_directory or is_ignored(event.src_path):
            return

        if is_lock_file(event.src_path):
            original = get_original_from_lock(event.src_path)
            if original and original in lock_file_map:
                opened = lock_file_map.pop(original)
                closed = datetime.now()
                log_to_db(original, opened, closed)
                print(f"[LOCK REMOVED] → {original}")
            return

        log_action(event.src_path, "deleted")

    def on_moved(self, event: FileSystemMovedEvent):
        if event.is_directory or is_ignored(event.src_path) or is_ignored(event.dest_path):
            return
        details = f"{event.src_path} → {event.dest_path}"
        log_action(event.dest_path, "moved", details=details)

    def check_stale_locks(self):
        to_remove = []
        for file_path, opened_time in lock_file_map.items():
            lock_path = os.path.join(os.path.dirname(file_path), f".~lock.{Path(file_path).name}#")
            if not os.path.exists(lock_path):
                log_to_db(file_path, opened_time, datetime.now())
                print(f"[LOCK GC] Удалён вручную: {file_path}")
                to_remove.append(file_path)
        for p in to_remove:
            lock_file_map.pop(p, None)

# Trash логика (отдельно)
class TrashHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        real_name = Path(event.src_path).name
        log_action(event.src_path, "deleted", f"Moved to Trash: {real_name}")

def log_file_access():
    # Основной observer
    observer = Observer()
    handler = FileLoggerHandler()
    observer.schedule(handler, path=WATCH_DIR, recursive=True)

    # Trash observer
    trash_observer = Observer()
    trash_observer.schedule(TrashHandler(), path=TRASH_DIR, recursive=True)

    observer.start()
    trash_observer.start()

    import threading
    threading.Thread(target=monitor_inotify, daemon=True).start()

    print(f"📁 Мониторинг {WATCH_DIR} запущен (inotify + lock + watchdog + trash)")

    try:
        while True:
            time.sleep(1)
            handler.check_stale_locks()  # 👈 проверка "забытых" lock-файлов
    except KeyboardInterrupt:
        observer.stop()
        trash_observer.stop()

    observer.join()
    trash_observer.join()