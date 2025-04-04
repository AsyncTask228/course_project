from logger import (
    db_logger,
    process_logger,
    file_logger,
    network_logger,
    session_tracker
)
import threading

if __name__ == "__main__":
    # Запускаем логгер авторизации (однократно)
    db_logger.log_auth()

    # Потоки для логгеров, которые работают в фоне
    threads = [
        threading.Thread(target=process_logger.log_processes, daemon=True),
        threading.Thread(target=file_logger.log_file_access, daemon=True),
        threading.Thread(target=network_logger.log_network_connections, daemon=True),
        threading.Thread(target=session_tracker.track_sessions, daemon=True)
    ]

    for t in threads:
        t.start()

    print("Все логгеры запущены. Нажмите Ctrl+C для выхода.")
    try:
        while True:
            pass  # поддерживаем основной поток активным
    except KeyboardInterrupt:
        print("\nВыход из программы.")
