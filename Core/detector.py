# core/detector.py

from utils.reputation import check_ip_reputation

def detect_threats(parsed_logs):
    """Parsed logs par sliding-window logic aur IOC reputation check lagakar threats detect karta hai."""
    alerts = []
    failed_attempts = {}
    
    for log in parsed_logs:
        ip = log["source_ip"]
        
        # Step 1: Check IP against Threat Intelligence IOC list
        rep_result = check_ip_reputation(ip)
        if rep_result and rep_result.get("is_malicious"):
            alerts.append({
                "timestamp": log["timestamp"],
                "source_ip": ip,
                "detection_type": "MALICIOUS_IOC",
                "message": rep_result.get("description", f"Malicious IP detected: {ip}")
            })
            
        # Step 2: Brute-force & Account Takeover detection logic
        if log["event_type"] == "auth_failure":
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            if failed_attempts[ip] >= 3:
                alerts.append({
                    "timestamp": log["timestamp"],
                    "source_ip": ip,
                    "detection_type": "BRUTE_FORCE",
                    "message": f"Multiple authentication failures detected from IP {ip} (Count: {failed_attempts[ip]})"
                })
        elif log["event_type"] == "auth_success" and ip in failed_attempts:
            if failed_attempts[ip] >= 2:
                alerts.append({
                    "timestamp": log["timestamp"],
                    "source_ip": ip,
                    "detection_type": "ACCOUNT_TAKEOVER",
                    "message": f"Successful login from IP {ip} after multiple authentication failures."
                })
                
    return alerts