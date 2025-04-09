import pyudev
from datetime import datetime
from logger import collector
import threading

# Кэш последних событий (для фильтрации дубликатов)
last_logged = {}

# Таймаут между одинаковыми событиями (в секундах)
DUPLICATE_TIMEOUT = 2


def get_device_info(device):
    """Получает подробную информацию об устройстве"""
    device_name = device.get("ID_MODEL") or device.get("DEVNAME") or "Unknown"
    device_type = device.get("ID_TYPE") or device.device_type or "block"
    device_id = device.get("DEVNAME") or device.get("DEVPATH") or "unknown"
    vendor = device.get("ID_VENDOR") or "None"
    serial = device.get("ID_SERIAL_SHORT") or "None"
    return device_name, device_type, device_id, f"Vendor={vendor} | Serial={serial}"


def should_log(device_id, status):
    """Фильтрация дубликатов"""
    key = (device_id, status)
    now = datetime.now()
    if key in last_logged:
        delta = (now - last_logged[key]).total_seconds()
        if delta < DUPLICATE_TIMEOUT:
            return False
    last_logged[key] = now
    return True


def log_device_event(action, device):
    device_name, device_type, device_id, details = get_device_info(device)

    # Пропускаем фантомные/внутренние интерфейсы или неизвестные устройства
    if (
        device_name == "Unknown"
        or device_id == "unknown"
        or device_type in ["usb_interface", "usb_endpoint", "usb"]
    ):
        return

    if not should_log(device_id, action):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    collector.log("device_logs", {
        "timestamp": timestamp,
        "device_name": device_name,
        "device_type": device_type,
        "device_id": device_id,
        "status": action,
        "details": details
    })


def monitor_devices():
    """Запуск слежения за USB-устройствами"""
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')

    print("🖥️  USB-мониторинг запущен...")

    for device in iter(monitor.poll, None):
        if device.action == "add":
            log_device_event("connected", device)
        elif device.action == "remove":
            log_device_event("disconnected", device)