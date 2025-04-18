import subprocess
import re
import time
import requests
import ipaddress
import psutil
from datetime import datetime
from logger import collector

seen_connections = set()
ip_cache = {}

def get_location(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        if ipaddress.ip_address(ip).is_private or ip.startswith("127.") or ip == "0.0.0.0":
            ip_cache[ip] = "Local"
        else:
            resp = requests.get(f"https://ipinfo.io/{ip}/country", timeout=2)
            ip_cache[ip] = resp.text.strip()
    except:
        ip_cache[ip] = "Unknown"
    return ip_cache[ip]

def parse_ss_output():
    output = subprocess.getoutput("ss -tunp")
    lines = output.splitlines()
    connections = []

    for line in lines[1:]:
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

            if dst_ip in ["127.0.0.1", "::1", "0.0.0.0"]:
                continue

            proc_name = "Unknown"
            username = "Unknown"
            pid_match = re.search(r"pid=(\d+)", users_field) if users_field else None

            if pid_match:
                pid = int(pid_match.group(1))
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                    username = proc.username()
                except:
                    pass

            connections.append({
                "protocol": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "process_name": proc_name,
                "username": username
            })

        except (ValueError, IndexError):
            continue

    return connections

def log_network_connections():
    print("[NETWORK LOGGER] Запущен.")
    global seen_connections

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        connections = parse_ss_output()

        for conn in connections:
            key = (conn["src_ip"], conn["src_port"], conn["dst_ip"], conn["dst_port"], conn["process_name"])
            if key in seen_connections:
                continue
            seen_connections.add(key)

            src_loc = get_location(conn["src_ip"])
            dst_loc = get_location(conn["dst_ip"])

            collector.log("network_logs", {
                "timestamp": timestamp,
                "username": conn["username"],
                "src_ip": conn["src_ip"],
                "src_port": conn["src_port"],
                "dst_ip": conn["dst_ip"],
                "dst_port": conn["dst_port"],
                "protocol": conn["protocol"],
                "process_name": conn["process_name"],
                "src_location": src_loc,
                "dst_location": dst_loc
            })

        # Чтобы не рос бесконечно
        if len(seen_connections) > 10000:
            seen_connections.clear()

        time.sleep(5)