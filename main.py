# main.py

import os
import sys

# Core aur Utils modules ko import karne ke liye path set kar rahe hain
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.parser import parse_log_line
from core.detector import detect_threats
from core.scorer import calculate_risk_score
from utils.reporter import generate_incident_report

def analyze_log_file(file_path):
    """
    Log file ko line-by-line read karta hai, parse karta hai, 
    threats detect karta hai, aur risk scores assign karta hai.
    """
    print(f"[*] Starting analysis for log file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"[!] Error: Log file not found at {file_path}")
        return
        
    parsed_logs = []
    
    # Step 1: Parse logs line by line
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                parsed = parse_log_line(line)
                if parsed:
                    parsed_logs.append(parsed)
                    
    print(f"[+] Successfully parsed {len(parsed_logs)} log entries.")
    
    # Step 2: Detect threats (Brute-force, suspicious IPs, etc.)
    raw_alerts = detect_threats(parsed_logs)
    print(f"[+] Threat detection completed. Found {len(raw_alerts)} potential security alerts.")
    
    # Step 3: Calculate risk scores and severity
    scored_alerts = []
    for alert in raw_alerts:
        scored_alert = calculate_risk_score(alert)
        scored_alerts.append(scored_alert)
        
    # Step 4: Generate incident report
    report_path = generate_incident_report(scored_alerts)
    print(f"[+] Security Log Analyzer pipeline completed successfully! Report saved at: {report_path}")

if __name__ == "__main__":
    # By default hum apni synthetic test log file ko analyze karenge
    default_log = os.path.join("tests", "synthetic_logs.log")
    
    # Agar user ne command line mein koi aur log file di hai toh woh use hogi
    target_log = sys.argv[1] if len(sys.argv) > 1 else default_log
    
    analyze_log_file(target_log)