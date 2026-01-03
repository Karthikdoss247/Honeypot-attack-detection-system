import socket
import threading
import time
import os
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt

# ================= CONFIG =================
HOST = "0.0.0.0"
PORT = 2222

BLOCK_THRESHOLD = 5
MEDIUM_THRESHOLD = 3

LOG_FILE = "honeypot.log"
INCIDENT_REPORT = "incident_report.txt"
IDS_ALERTS = "ids_alerts.txt"
GRAPH_FILE = "attack_graph.png"

FILE_TRAP_DIR = "file_trap"   # Feature 5

# ============== DATA ======================
attempt_counter = defaultdict(int)
severity_map = {}
geo_map = {}

# ============== GEO-IP (FEATURE 4) =======
def geo_lookup(ip):
    if ip.startswith("192.168"):
        return "Local Network"
    elif ip.startswith("10."):
        return "Private Network"
    else:
        return "Unknown"

# ============== LOGGING ===================
def log_attack(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def export_ids_alert(msg):
    with open(IDS_ALERTS, "a") as f:
        f.write(msg + "\n")

# ============== SEVERITY ==================
def classify_severity(ip):
    count = attempt_counter[ip]
    if count >= BLOCK_THRESHOLD:
        sev = "HIGH"
    elif count >= MEDIUM_THRESHOLD:
        sev = "MEDIUM"
    else:
        sev = "LOW"
    severity_map[ip] = sev
    return sev

# ============== INCIDENT REPORT ===========
def write_incident_report():
    with open(INCIDENT_REPORT, "w") as f:
        f.write("HONEYPOT INCIDENT REPORT\n")
        f.write("========================\n\n")
        for ip in severity_map:
            f.write(f"IP Address : {ip}\n")
            f.write(f"Country    : {geo_map.get(ip,'Unknown')}\n")
            f.write(f"Attempts   : {attempt_counter[ip]}\n")
            f.write(f"Severity   : {severity_map[ip]}\n")
            f.write("----------------------------\n")

# ============== GRAPH (FEATURE 1) =========
def generate_graph():
    if not attempt_counter:
        return
    plt.bar(attempt_counter.keys(), attempt_counter.values())
    plt.title("Honeypot Attack Attempts per IP")
    plt.xlabel("IP Address")
    plt.ylabel("Attempts")
    plt.tight_layout()
    plt.savefig(GRAPH_FILE)
    plt.close()

# ============== FAKE COMMANDS (FEATURE 2) =
def fake_command_response(cmd):
    fake_fs = {
        "ls": "bin  etc  home  var\n",
        "whoami": "root\n",
        "pwd": "/root\n"
    }
    return fake_fs.get(cmd, "command not found\n")

# ============== FILE TRAP (FEATURE 5) =====
def setup_file_trap():
    if not os.path.exists(FILE_TRAP_DIR):
        os.makedirs(FILE_TRAP_DIR)
        with open(os.path.join(FILE_TRAP_DIR, "important.doc"), "w") as f:
            f.write("Sensitive File\n")

def monitor_file_trap():
    baseline = {
        f: os.path.getmtime(os.path.join(FILE_TRAP_DIR, f))
        for f in os.listdir(FILE_TRAP_DIR)
    }

    while True:
        time.sleep(3)
        for f in os.listdir(FILE_TRAP_DIR):
            path = os.path.join(FILE_TRAP_DIR, f)
            if os.path.getmtime(path) != baseline.get(f):
                alert = "[ALERT] FILE TAMPERING DETECTED (Possible Ransomware)"
                print(alert)
                log_attack(alert)
                export_ids_alert(alert)
                baseline[f] = os.path.getmtime(path)

# ============== CLIENT HANDLER ============
def handle_client(conn, addr):
    ip, port = addr
    attempt_counter[ip] += 1

    geo_map[ip] = geo_lookup(ip)
    severity = classify_severity(ip)

    base_log = f"{datetime.now()} | {ip}:{port} | Attempt {attempt_counter[ip]} | Severity={severity}"
    log_attack(base_log)

    if severity == "HIGH":
        export_ids_alert(f"[IDS ALERT] {base_log}")

    try:
        conn.sendall(b"Welcome to Secure Server v1.2\n")
        conn.sendall(b"Username: ")
        user = conn.recv(1024).decode(errors="ignore").strip()

        conn.sendall(b"Password: ")
        pwd = conn.recv(1024).decode(errors="ignore").strip()

        log_attack(f"{datetime.now()} | LOGIN FAIL | IP={ip} USER={user} PASS={pwd}")
        conn.sendall(b"Login failed\n")

        # Fake shell
        conn.sendall(b"$ ")
        cmd = conn.recv(1024).decode(errors="ignore").strip()
        conn.sendall(fake_command_response(cmd).encode())

        log_attack(f"{datetime.now()} | CMD | IP={ip} CMD={cmd}")

        if severity == "HIGH":
            conn.sendall(b"\n[!] Too many attempts detected. Logged.\n")
            time.sleep(3)

    except Exception as e:
        log_attack(f"Error: {e}")

    finally:
        write_incident_report()
        generate_graph()
        conn.close()

# ============== SERVER ====================
def start_honeypot():
    setup_file_trap()
    threading.Thread(target=monitor_file_trap, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] Honeypot running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# ============== RUN =======================
start_honeypot()
