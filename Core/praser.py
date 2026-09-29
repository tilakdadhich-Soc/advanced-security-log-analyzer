import re
import os
def parse_log_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parsed_data = {
    "timestamp": None,
    "service": "unknown",
    "event_type": "unknown",
    "source_ip": "unknown",
    "user": "unknown",
    "raw_line": line
}
    try: 
        auth_pattern = r"^(\S+)\s+(\S+)\s+(.*?)\s+(for|from)\s+(.*?)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})"

        if "Failed password" in line or "Accepted password" in line:
          parts = line.split()
        parsed_data["timestamp"] = parts[0]
        parsed_data["service"] = parts[1]

        if "Failed password" in line:
            parsed_data["event_type"] = "auth_failure"
        elif "Accepted password" in line:
            parsed_data["event_type"] = "auth_success"

        try: 
            for_index = parts.index("for")
            parsed_data["user"] = parts[for_index + 1]
        except ValueError:
            parsed_data["user"] = "unknown"

        try: 
            from_index = parts.index("from")
            parsed_data["source_ip"] = parts[from_index + 1]
        except ValueError:
            parsed_data["source_ip"] = "unknown"
        return parsed_data
    except Exception as e:


        if "web_server" in line or "GET" in line or "POST" in line:
            parts = line.split()
            parsed_data["timestamp"] = parts[0]
            parsed_data["service"] = parts[1]
            parsed_data["event_type"] = "http_request"
            parsed_data ["user"] = "anonymous"
            parsed_data["source_ip"] = parts[-1]
            return parsed_data 
    
    
    except  Exception as e:
            parsed_data["event_type"] = "unparsed_anomaly"
            parsed_data["error"] = str(e)
            return parsed_data

    def parse_log_file(file_path):
        parsed_logs = []

        if not os.path.exists(file_path):
                print(f"[Error] File not found: {file_path}")
        return parsed_logs

        with open(file_path, 'r', encoding='utf-8') as file:
                for line_number, line in enumerate(file, 1):
                    result = parse_log_line(line)
                if result:
                    parsed_logs.append(result)
        print(f"[PARSER] Total {len(parsed_logs)} log entries parsed from {file_path}.")
        return parsed_logs
