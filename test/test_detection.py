import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.detector import detect_threats
from core.parser import parse_log_line
from core.scorer import calculate, calculate_risk_score


class TestSecurityAnalyzer(unittest.TestCase):

    def test_parser_auth_failure(self):
        raw_log = "026-09-30T08:05:12Z auth_service Failed password for root from 192.168.1.50 port 22"
        parsed = parse_log_line(raw_log)
        self.assertEqual(parsed["service"], "auth_service")
        self.assertEqual(parsed["event_type"], "auth_failure")
        self.assertEqual(parsed["source_ip"], "192.168.1.50")
        self.assertEqual(parsed["user"], "root")

    def test_detector_brute_force(self):
        logs = [
            {"timestamp": "2026-09-30T08:05:12Z", "service": "auth_service", "event_type": "auth_failure", "source_ip": "192.168.1.50", "user": "root"},
            {"timestamp": "2026-09-30T08:05:15Z", "service": "auth_service", "event_type": "auth_failure", "source_ip": "192.168.1.50", "user": "root"},
            {"timestamp": "2026-09-30T08:05:18Z", "service": "auth_service", "event_type": "auth_failure", "source_ip": "192.168.1.50", "user": "root"},
        ]
        alerts = detect_threats(logs)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["detection_type"], "brute_force")

    def test_risk_score(self):
        alert = {
            "timestamp": "2026-09-30T08:06:00Z",
            "source_ip": "192.168.1.50",
            "detection_type": "ACCOUNT_TAKEOVER",
            "message": "Successful login for root from 192.168.1.50 after multiple failures",
        }
        score_alert = calculate(alert)

        self.assertIn(score_alert["calculated-severity"], ["high", "critical"])


if __name__ == "__main__":
    unittest.main()