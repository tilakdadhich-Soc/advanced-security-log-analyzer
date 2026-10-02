# main.py

import os
import sys

# Hardcode absolute path resolution to prevent Windows/OneDrive path lookup failures
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.parser import parse_log_line
from core.detector import detect_threats
from core.scorer import calculate_risk_score
from utils.reporter import generate_incident_report

def analyze_log_file(file_path):
    print(f"[*] Starting analysis for log file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"[!] Error: Log file not found at {file_path}")
        return
        
    parsed_logs = []
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                parsed = parse_log_line(line)
                if parsed:
                    parsed_logs.append(parsed)
                    
    print(f"[+] Successfully parsed {len(parsed_logs)} log entries.")
    
    raw_alerts = detect_threats(parsed_logs)
    print(f"[+] Threat detection completed. Found {len(raw_alerts)} potential security alerts.")
    
    scored_alerts = []
    for alert in raw_alerts:
        scored_alert = calculate_risk_score(alert)
        scored_alerts.append(scored_alert)
        
    report_path = generate_incident_report(scored_alerts)
    print(f"[+] Security Log Analyzer pipeline completed successfully! Report saved at: {report_path}")

if __name__ == "__main__":
    default_log = os.path.join(ROOT_DIR, "tests", "synthetic_logs.log")
    target_log = sys.argv[1] if len(sys.argv) > 1 else default_log
    analyze_log_file(target_log)