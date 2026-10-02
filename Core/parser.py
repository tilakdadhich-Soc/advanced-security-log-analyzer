# core/parser.py
import re
import json

def parse_log_line(line):
    """
    Multi-format log parser:
    1. Attempts to parse JSON logs.
    2. Falls back to Syslog / ISO timestamp logs.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Try parsing as JSON first
    try:
        data = json.loads(line)
        return {
            "timestamp": data.get("timestamp", "UNKNOWN"),
            "service": data.get("service", "json_app"),
            "event_type": data.get("event_type", "generic_event"),
            "source_ip": data.get("source_ip", data.get("ip", "127.0.0.1")),
            "user": data.get("user", "unknown"),
            "raw_message": line
        }
    except json.JSONDecodeError:
        pass

    # Fallback: Syslog or ISO timestamp format
    pattern = r"^(?P<timestamp>\S+(?:\s+\S+){0,2}) (?P<service>\S+) (?P<message>.*)"
    match = re.match(pattern, line)
    
    if not match:
        return {
            "timestamp": "UNKNOWN",
            "service": "unknown_service",
            "event_type": "UNKNOWN",
            "source_ip": extract_ip(line),
            "user": "unknown",
            "raw_message": line
        }
        
    data = match.groupdict()
    msg = data["message"]
    
    event_type = "UNKNOWN"
    source_ip = extract_ip(msg)
    user = "unknown"
    
    if "Failed password" in msg or "authentication failure" in msg.lower():
        event_type = "auth_failure"
    elif "Accepted password" in msg or "session opened" in msg.lower():
        event_type = "auth_success"
    elif "GET" in msg or "POST" in msg or "HTTP/" in msg:
        event_type = "web_request"
        
    # Robust user extraction handling "invalid user <name>" or "for <name>"
    if "for " in msg:
        parts = msg.split("for ")
        if len(parts) > 1:
            tokens = parts[1].split()
            if tokens and tokens[0] == "invalid":
                tokens = tokens[2:] if len(tokens) > 2 and tokens[1] == "user" else tokens[1:]
            elif tokens and tokens[0] == "user":
                tokens = tokens[1:]
            user = tokens[0] if tokens else "unknown"
            
    return {
        "timestamp": data["timestamp"],
        "service": data["service"],
        "event_type": event_type,
        "source_ip": source_ip,
        "user": user,
        "raw_message": msg
    }

def extract_ip(text):
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    return ip_match.group(0) if ip_match else "127.0.0.1"