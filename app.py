from flask import Flask, render_template, jsonify
import os
import re

app = Flask(__name__)

# ======= Helper function to read and parse alerts ========
def read_alerts():
    alerts = []
    log_path = "logs/alerts.log"
    if not os.path.exists(log_path):
        return alerts

    with open(log_path, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            severity_match = re.search(r"\[(.*?)\]", line)
           # ip_match = re.search(r"from IP (\d+\.\d+\.\d+\.\d+)", line)
            ip_match = re.search(r"(?:from|Blacklisted) IP (\d+\.\d+\.\d+\.\d+)", line)

            severity = severity_match.group(1) if severity_match else "INFO"
            ip = ip_match.group(1) if ip_match else "Unknown"
            alerts.append({"raw": line, "severity": severity, "ip": ip})
    return alerts

# ========= Main dashboard route =========
@app.route("/")
def index():
    alerts = read_alerts()
    return render_template("index.html", alerts=alerts)

# ========= API endpoint for AJAX polling =========
@app.route("/alerts_data", methods=["GET"])
def alerts_data():
    alerts = read_alerts()
    return jsonify(alerts)

@app.route("/run_test")
def run_test():
    import subprocess
    subprocess.Popen(["python3", "log_monitor.py", "--test"])
    return "Triggered"

@app.route("/clear_alerts")
def clear_alerts():
    open("logs/alerts.log", "w").close()
    return "Cleared"


if __name__ == "__main__":
    app.run(debug=True)
