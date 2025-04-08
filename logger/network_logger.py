# logger/network_logger.py
import subprocess
from datetime import datetime
import re
import time
import requests
import ipaddress
from logger import collector

def get_user():
    return subprocess.getoutput("whoami") or "Unknown"

def get_location(ip):
    try:
        if ipaddress.ip_address(ip).is_private or ip.startswith("127.") or ip == "0.0.0.0":
            return "Local"
        resp = requests.get(f"https://ipinfo.io/{ip}/country", timeout=2)
        return resp.text.strip()
    except:
        return "Unknown"

def parse_ss_output():
    output = subprocess.getoutput("ss -tunp")
    lines = output.splitlines()
    connections = []

    for line in lines[1:]:  # пропускаем заголовок
        try:
            parts = re.split(r'\s+', line)
            proto = parts[0]
            src = parts[4]
            dst = parts[5]
            users_field = parts[-1] if "users:" in parts[-1] else None

            if ":" not in src or ":" not in dst:
                continue

            # IPv6
            if src.startswith('['):
                src_ip, src_port = re.findall(r"\[([^\]]+)\]:(\d+)", src)[0]
                dst_ip, dst_port = re.findall(r"\[([^\]]+)\]:(\d+)", dst)[0]
            else:
                src_ip, src_port = src.rsplit(':', 1)
                dst_ip, dst_port = dst.rsplit(':', 1)

            proc_name = "Unknown"
            if users_field:
                match = re.search(r'"([^"]+)"', users_field)
                if match:
                    proc_name = match.group(1)

            connections.append({
                "protocol": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "process_name": proc_name
            })
        except Exception as e:
            continue

    return connections

def log_network_connections():
    username = get_user()

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        connections = parse_ss_output()

        for conn in connections:
            src_loc = get_location(conn["src_ip"])
            dst_loc = get_location(conn["dst_ip"])

            collector.log("network_logs", {
                "timestamp": timestamp,
                "username": username,
                "src_ip": conn["src_ip"],
                "src_port": conn["src_port"],
                "dst_ip": conn["dst_ip"],
                "dst_port": conn["dst_port"],
                "protocol": conn["protocol"],
                "process_name": conn["process_name"],
                "src_location": src_loc,
                "dst_location": dst_loc
            })

        time.sleep(5)


if __name__ == "__main__":
    log_network_connections()