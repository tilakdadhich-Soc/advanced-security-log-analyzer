import os


def parse_log_line(line):
    raw_line = str(line).strip()
    if not raw_line or raw_line.startswith("#"):
        return None

    parts = raw_line.split()
    parsed = {
        "timestamp": None,
        "service": "unknown",
        "event_type": "unknown",
        "source_ip": "unknown",
        "user": "unknown",
        "raw_line": raw_line,
    }

    if len(parts) < 2:
        parsed["event_type"] = "unparsed_anomaly"
        return parsed

    parsed["timestamp"] = parts[0]
    parsed["service"] = parts[1]

    lowered = raw_line.lower()
    if "failed password" in lowered:
        parsed["event_type"] = "auth_failure"
    elif "accepted password" in lowered:
        parsed["event_type"] = "auth_success"
    elif "get" in lowered or "post" in lowered:
        parsed["event_type"] = "http_request"
    else:
        parsed["event_type"] = "unparsed_anomaly"

    for index, token in enumerate(parts):
        if token.lower() == "for" and index + 1 < len(parts):
            parsed["user"] = parts[index + 1]
        if token.lower() == "from" and index + 1 < len(parts):
            parsed["source_ip"] = parts[index + 1]

    if parsed["source_ip"] == "unknown":
        for token in parts:
            if token.count(".") == 3 and all(part.isdigit() for part in token.split(".")):
                parsed["source_ip"] = token
                break

    return parsed


def parse_log_file(file_path):
    parsed_logs = []
    if not os.path.exists(file_path):
        print(f"[Error] File not found: {file_path}")
        return parsed_logs

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            result = parse_log_line(line)
            if result:
                parsed_logs.append(result)

    print(f"[PARSER] Total {len(parsed_logs)} log entries parsed from {file_path}.")
    return parsed_logs
