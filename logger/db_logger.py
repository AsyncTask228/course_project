# logger/db_logger.py
import subprocess
from datetime import datetime
from logger import collector

def get_mac():
    try:
        output = subprocess.getoutput("ip link show | grep 'link/ether'")
        return output.split()[1] if output else "MAC не найден"
    except:
        return "Ошибка"

def get_user():
    return subprocess.getoutput("whoami") or "Unknown"

def log_auth():
    username = get_user()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = subprocess.getoutput("hostname -I").split()[0]
    mac = get_mac()

    collector.log("auth_logs", {
        "timestamp": timestamp,
        "username": username,
        "ip_address": ip,
        "mac_address": mac
    })