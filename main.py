import threading
import time
from logger import (
    collector,
    process_logger,
    network_logger,
    device_logger
)
from logger.file_logger import log_file_access
from auth_logging import auth_logger, session_tracker, ssh_logger, gui_session_tracker


if __name__ == "__main__":
    # Инициализация базы данных и запуск фонового воркера
    collector.init_db()
    collector.start_worker()

    # Логируем факт входа
    auth_logger.log_auth()

    # Список потоков
    threads = [
        # threading.Thread(target=process_logger.log_processes, daemon=True),
        # threading.Thread(target=network_logger.log_network_connections, daemon=True),
        # threading.Thread(target=session_tracker.track_sessions, daemon=True),
        threading.Thread(target=log_file_access, daemon=True),
        threading.Thread(target=device_logger.monitor_devices, daemon=True),
        # threading.Thread(target=gui_session_tracker.track_gui_sessions, daemon=True), 
        # threading.Thread(target=ssh_logger.track_ssh_connections, daemon=True)
    ]

    for t in threads:
        t.start()

    print("✅ Все логгеры запущены. Нажмите Ctrl+C для выхода.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Выход из программы.")