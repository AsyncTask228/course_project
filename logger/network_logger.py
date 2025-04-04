# logger/network_logger.py
import sqlite3
import subprocess
from datetime import datetime
import os
import time
import requests
import re

DB_PATH = os.path.join(os.path.dirname(__file__), "activity_logs.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS network_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            remote_ip TEXT,
            remote_port TEXT,
            protocol TEXT,
            process_name TEXT,
            location TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_user():
    return subprocess.getoutput("whoami")

def get_country_from_ip(ip):
    try:
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
            local = parts[4]
            remote = parts[5]
            process_info = parts[-1] if "users:" in parts[-1] else None

            if remote == "*" or remote == "0.0.0.0:*":
                continue  # неинформативное

            # Парсим IP и порт
            if "[" in remote:  # IPv6
                match = re.search(r"\[([^\]]+)\]:(\d+)", remote)
                if not match:
                    continue
                ip, port = match.groups()
            else:  # IPv4
                if ':' not in remote:
                    continue
                ip, port = remote.rsplit(':', 1)

            process_name = "Unknown"
            if process_info:
                match = re.search(r'\"([^\"]+)\"', process_info)
                if match:
                    process_name = match.group(1)

            connections.append((proto, ip, port, process_name))

        except Exception as e:
            continue

    return connections

def log_network_connections():
    init_db()
    username = get_user()

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        connections = parse_ss_output()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        for proto, ip, port, proc in connections:
            country = get_country_from_ip(ip)
            c.execute('''
                INSERT INTO network_logs (timestamp, username, remote_ip, remote_port, protocol, process_name, location)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, username, ip, port, proto, proc, country))

        conn.commit()
        conn.close()
        time.sleep(5)

if __name__ == "__main__":
    log_network_connections()