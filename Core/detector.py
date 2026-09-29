from utils.reputation import check_ip_reputation

def detect_threats(parsed_logs):
    alerts = []
    failed_attempts_tracker = {}

    for log in parsed_logs:
        ip = log.get("source_ip", "unknown")
        event_type = log.get("event_type", "unknown")
        user = log.get("user", "unknown")
        timestamp = log.get("timestamp", "unknown")

        is_malicious, reason = check_ip_reputation(ip)
        if is_malicious:
            alerts.append({
                "timestamp": timestamp,
                "source_ip": event_type,
                "event_type": event_type,
                "detection_type": "IOC_MATCH",
                "serverity": "HIGH",
                "message": f"Malicious IP detected: {ip}. Reason: {reason}"
            })

        if event_type == "auth_failure":
            if ip not in failed_attempts_tracker:
                failed_attempts_tracker[ip] = 0
            failed_attempts_tracker[ip] += 1

            if failed_attempts_tracker[ip] >= 3:
                alerts.append({
                    "timestamp": timestamp,
                    "source_ip": ip,
                    "event_type": event_type,
                    "detection_type": "BRUTE_FORCE",
                    "serverity": "MEDIUM",
                    "message": f"Potential Brute-Force attack detected targeting user '{user}' from IP {ip} ({failed_attempts_tracker[ip]} consecutive failures)"
                })
        elif event_type == "auth_success":
            if ip in failed_attempts_tracker and  failed_attempts_tracker[ip] >= 2:
                alerts.append({
                    "timestamp": timestamp,
                    "source_ip": ip,
                    "event_type": event_type,
                    "detection_type": "ACCOUNT_TAKEOVER",
                    "serverity": "CRITICAL",
                    "message": f"Successful login after multiple failed attempts from IP {ip} for user '{user}' ({failed_attempts_tracker[ip]} consecutive failures)"
                })
                print(f"[DETECTOR] Total {len(alerts)} security alerts trigger hue hain.")
    return alerts