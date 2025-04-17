import re
import subprocess
from datetime import datetime
from auth_logging.pg_logger import log_remote_connection


def parse_ssh_log(line):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    accepted = re.search(r"(sshd|sshd-session)\[\d+\]: Accepted .* for (\w+) from ([\d.:a-fA-F]+) port (\d+)", line)
    failed = re.search(r"(sshd|sshd-session)\[\d+\]: Failed .* for (\w+) from ([\d.:a-fA-F]+) port (\d+)", line)
    aborted = re.search(r"(sshd|sshd-session)\[\d+\]: Connection closed.*? (\w+) ([\d.:a-fA-F]+) port (\d+)", line)
    disconnected = re.search(r"(sshd|sshd-session)\[\d+\]: Disconnected from user (\w+) ([\d.:a-fA-F]+) port (\d+)", line)

    if accepted:
        return {
            "timestamp": timestamp,
            "username": accepted.group(2),
            "ip_address": accepted.group(3),
            "port": int(accepted.group(4)),
            "status": "success",
            "method": "ssh"
        }
    elif failed:
        return {
            "timestamp": timestamp,
            "username": failed.group(2),
            "ip_address": failed.group(3),
            "port": int(failed.group(4)),
            "status": "failed",
            "method": "ssh"
        }
    elif aborted:
        return {
            "timestamp": timestamp,
            "username": aborted.group(2),
            "ip_address": aborted.group(3),
            "port": int(aborted.group(4)),
            "status": "aborted",
            "method": "ssh"
        }
    elif disconnected:
        return {
            "timestamp": timestamp,
            "username": disconnected.group(2),
            "ip_address": disconnected.group(3),
            "port": int(disconnected.group(4)),
            "status": "disconnected",
            "method": "ssh"
        }

    return None


# Чтение лога в реальном времени
def track_ssh_connections():
    print("[SSH TRACKER] Старт отслеживания SSH подключений...")
    process = subprocess.Popen(["tail", "-n", "0", "-F", "/var/log/auth.log"], stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        data = parse_ssh_log(line)
        if data:
            print(f"[SSH EVENT] {data}")
            log_remote_connection(data)

if __name__ == "__main__":
    track_ssh_connections()
