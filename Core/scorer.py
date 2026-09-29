def calculate_risk_score(alert):
    score = 0
    detection_type = alert.get("detection_type", "")
    message = alert.get("message", "").lower()

    if detection_type == "ACCOUNT_TAKEOVER":
        score += 80
    elif detection_type == "IOC_MATCH":
        score += 50
    elif detection_type == "BRUTE_FORCE":
        score += 30
    else:
        score += 10

    if "root" in message or "admin" in message or "administrator" in message:
        score += 25
    if "malicious" in message or "botnet" in message or "malware" in message or "trojan" in message:
        score += 20

    if score >= 80:
        servirity = "CRITICAL"
    elif score >= 55:
        servirity = "HIGH"
    elif score >= 30:
        servirity = "MEDIUM"
    else:
        servirity = "LOW"

    alert["risk_score"] = score
    alert["calculated_servirity"] = servirity

    return alert
