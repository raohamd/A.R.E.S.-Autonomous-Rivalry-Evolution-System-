import psutil
import time
import csv
import os
from datetime import datetime

# --- CONFIGURATION ---
THREAT_SIGNATURES = {
    "nmap": "substring",
    "hydra": "substring",
    "wireshark": "substring",
    "su": "exact"  # STRICT MODE: Only kills if name is EXACTLY 'su'
}

LOG_FILE = "sentinel_forensic_log.csv"

# Create Log File if missing
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        csv.writer(f).writerow(["TIMESTAMP", "TARGET", "PID", "ACTION", "STATUS"])

def scan_and_neutralize():
    print("[-] AI Analyst: MONITORING KERNEL...")
    
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                p_info = proc.info
                p_name = p_info['name'].lower() if p_info['name'] else ""
                p_cmd = " ".join(p_info['cmdline']).lower() if p_info['cmdline'] else ""
                
                # --- CRITICAL SAFETY CHECK: IGNORE SELF & DASHBOARD ---
                if "ai_analyst" in p_cmd or "dashboard" in p_cmd or "streamlit" in p_cmd:
                    continue
                if "code" in p_name or "chrome" in p_name: # Don't kill VS Code or Chrome
                    continue

                is_threat = False
                detected_name = ""

                for signature, match_type in THREAT_SIGNATURES.items():
                    # EXACT MATCH (Prevents killing 'support' or 'sudo')
                    if match_type == "exact":
                        if p_name == signature:
                            is_threat = True
                            detected_name = signature
                    
                    # SUBSTRING MATCH (Catches 'nmap -sV ...')
                    elif match_type == "substring":
                        if signature in p_name or signature in p_cmd:
                            is_threat = True
                            detected_name = signature
                            break

                if is_threat:
                    # KILL IT
                    proc.kill()
                    
                    # LOG IT
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] KILLED: {detected_name} (PID: {p_info['pid']})")
                    
                    with open(LOG_FILE, 'a', newline='') as f:
                        csv.writer(f).writerow([timestamp, detected_name, p_info['pid'], "SIGKILL", "⛔ ELIMINATED"])

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        time.sleep(0.5)

if __name__ == "__main__":
    scan_and_neutralize()
