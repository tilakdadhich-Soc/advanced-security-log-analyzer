# tests/test_parser.py

import pytest
from core.parser import parse_log_line

def test_parse_syslog_auth_failure():
    """Test traditional syslog format for authentication failure."""
    line = "Oct  2 08:30:01 authserver sshd[4521]: Failed password for invalid user root from 193.168.1.100 port 22 ssh2"
    result = parse_log_line(line)
    
    assert result is not None
    assert result["event_type"] == "auth_failure"
    assert result["source_ip"] == "193.168.1.100"
    assert result["user"] == "root"
    assert result["service"] == "authserver"

def test_parse_json_log():
    """Test modern JSON log format (e.g., CloudTrail/Docker logs)."""
    line = '{"timestamp": "2026-10-02T08:35:00Z", "service": "aws-cloudtrail", "event_type": "auth_failure", "source_ip": "193.168.1.100", "user": "admin"}'
    result = parse_log_line(line)
    
    assert result is not None
    assert result["service"] == "aws-cloudtrail"
    assert result["event_type"] == "auth_failure"
    assert result["source_ip"] == "193.168.1.100"
    assert result["user"] == "admin"

def test_parse_empty_and_comments():
    """Test that empty lines or comments return None gracefully."""
    assert parse_log_line("") is None
    assert parse_log_line("   ") is None
    assert parse_log_line("# This is a comment line") is None

def test_parse_fallback_unstructured():
    """Test fallback mechanism for unstructured raw text logs containing an IP."""
    line = "Random system notification message generated from IP 192.168.50.25"
    result = parse_log_line(line)
    
    assert result is not None
    assert result["source_ip"] == "192.168.50.25"
    assert result["event_type"] == "UNKNOWN"
    