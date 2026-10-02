# main.py
import os
import sys
import json
import argparse
from datetime import datetime, timezone
from core.parser import parse_log_line
from core.detector import detect_threats
from core.scorer import calculate_risk_score

def analyze_log_file(log_file_path):
    """Main security log analysis pipeline."""
    if not os.path.exists(log_file_path):
        print(f"[-] Error: Log file not found at {log_file_path}")
        return

    print(f"[*] Starting analysis for log file: {log_file_path}")
    
    parsed_logs = []
    with open(log_file_path, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)
                
    print(f"[+] Successfully parsed {len(parsed_logs)} log entries.")
    
    # Step 2: Threat Detection
    raw_alerts = detect_threats(parsed_logs)
    
    # Step 3: Risk Scoring & Enrichment
    enriched_alerts = []
    for alert in raw_alerts:
        scored_alert = calculate_risk_score(alert)
        enriched_alerts.append(scored_alert)
        
    print(f"[+] Threat detection completed. Found {len(enriched_alerts)} potential security alerts.")
    
    # Step 4: Generate Incident Report (Warning-free UTC timestamp)
    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "target_file": log_file_path,
        "total_logs_analyzed": len(parsed_logs),
        "total_alerts": len(enriched_alerts),
        "alerts": enriched_alerts
    }
    
    os.makedirs("reports", exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"reports/security_incident_report_{timestamp_str}.json"
    
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
        
    print(f"[+] Incident report successfully generated: {report_filename}")
    print(f"[+] Security Log Analyzer pipeline completed successfully!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional SOC Log Analyzer & Threat Detection Engine")
    parser.add_argument(
        "--log", 
        type=str, 
        default="tests/synthetic_logs.log", 
        help="Path to the log file to analyze (default: tests/synthetic_logs.log)"
    )
    
    args = parser.parse_args()
    analyze_log_file(args.log)