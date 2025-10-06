import re
import requests 
from datetime import datetime, timedelta

#AUTH_LOG_PATH = "/var/log/auth.log"
AUTH_LOG_PATH = "/var/log/test_auth.log"
ALERT_LOG_PATH = "logs/alerts.log"

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5

# New regex for your ISO timestamp logs

failed_pattern = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}) .* Failed password for .* from (\d+\.\d+\.\d+\.\d+)'
)

root_pattern = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}) .* Accepted password for root from (\d+\.\d+\.\d+\.\d+)'
)

def parse_failed_logins(log_lines):
    failed_attempts = {}
    now = datetime.now().astimezone()
    time_window_start = now - timedelta(minutes=TIME_WINDOW_MINUTES)

    for line in log_lines:
        match = failed_pattern.search(line)
        if match:
            timestamp_str, ip = match.groups()
            timestamp = datetime.fromisoformat(timestamp_str)
            if timestamp >= time_window_start:
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return failed_attempts

def parse_root_logins(log_lines):
    root_logins = []
    for line in log_lines:
        match = root_pattern.search(line)
        if match:
            timestamp_str, ip = match.groups()
            timestamp = datetime.fromisoformat(timestamp_str)
            root_logins.append((timestamp, ip))
    return root_logins

def alert(message):
    print(f"{message}")
    with open(ALERT_LOG_PATH, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

    # Send to Discord too
    send_discord_alert(f"🚨 {message}")

#def alert(message):
#    print(f"[ALERT] {message}")
 #   with open(ALERT_LOG_PATH, "a") as f:
  #      f.write(f"{datetime.now()} - {message}\n")

def main():
    blacklisted_ips = load_blacklisted_ips()

    with open(AUTH_LOG_PATH, "r") as f:
        log_lines = f.readlines()

    failed_attempts = parse_failed_logins(log_lines)
    for ip, count in failed_attempts.items():
        if ip in blacklisted_ips:
            alert(f"[CRITICAL] Blacklisted IP {ip} attempted {count} failed SSH logins!")
        elif count >= FAILED_LOGIN_THRESHOLD:
            alert(f"SSH brute-force detected from IP {ip} with {count} failed login attempts in last {TIME_WINDOW_MINUTES} minutes")

    root_logins = parse_root_logins(log_lines)
    for ts, ip in root_logins:
        if ip in blacklisted_ips:
            alert(f"[CRITICAL] Blacklisted IP {ip} successfully logged in as root at {ts}")
        else:
            alert(f"Successful root login detected from IP {ip} at {ts}")


def send_discord_alert(message, webhook_url="https://discord.com/api/webhooks/1424468980541685922/aMiY08rJWgVTCKqBfQFDP3HRYayBXM8YuRaRuLcvGG99QYaZc5KUJpv_AW1hRtsvIFt7"):
    payload = {
        "content": message
    }
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 204:
            print(f"[!] Failed to send Discord alert: {response.status_code} {response.text}")
    except Exception as e:
        print(f"[!] Exception sending Discord alert: {e}")


def load_blacklisted_ips(filepath="config/blacklist_ips.txt"):
    try:
        with open(filepath, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()


if __name__ == "__main__":
    main()

