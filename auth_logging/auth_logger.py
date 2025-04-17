import subprocess
from datetime import datetime
from logger import collector  # локальный логгер
from auth_logging.pg_logger import log_to_postgres  # PostgreSQL логгер

def get_mac():
    try:
        route_output = subprocess.getoutput("ip route get 8.8.8.8")
        iface = ""
        for part in route_output.split():
            if part == "dev":
                iface = route_output.split()[route_output.split().index("dev") + 1]
                break

        if iface:
            link_output = subprocess.getoutput(f"ip link show {iface}")
            for line in link_output.splitlines():
                if "link/ether" in line:
                    return line.strip().split()[1]
        return "MAC не найден"
    except Exception as e:
        return f"Ошибка: {e}"

def get_user():
    return subprocess.getoutput("whoami") or "Unknown"

def log_auth():
    username = get_user()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = subprocess.getoutput("hostname -I").split()[0]
    mac = get_mac()

    data = {
        "timestamp": timestamp,
        "username": username,
        "ip_address": ip,
        "mac_address": mac
    }

    # Логирование в удалённую базу (PostgreSQL)
    log_to_postgres(data)