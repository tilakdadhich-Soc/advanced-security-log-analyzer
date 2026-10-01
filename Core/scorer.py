def calculate_risk_score(alert):
    score = 0
    detection_type = str(alert.get("detection_type", "")).lower()
    message = str(alert.get("message", "")).lower()

    if detection_type == "account_takeover":
        score += 80
    elif detection_type == "ioc_match":
        score += 50
    elif detection_type == "brute_force":
        score += 30
    else:
        score += 10

    if "root" in message or "admin" in message or "administrator" in message:
        score += 25
    if "malicious" in message or "botnet" in message or "malware" in message or "trojan" in message:
        score += 20

    if score >= 80:
        severity = "critical"
    elif score >= 55:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    alert["risk_score"] = score
    alert["calculated_severity"] = severity
    alert["calculated-severity"] = severity

    return alert


def calculate(alert):
    return calculate_risk_score(alert)
