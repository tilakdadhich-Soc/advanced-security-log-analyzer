# tests/test_detection.py
import unittest
from core.detector import detect_threats
from core.scorer import calculate_risk_score
from core.parser import parse_log_line

class TestSecurityAnalyzer(unittest.TestCase):
    
    def test_parser_auth_failure(self):
        raw_log = "Sep 30 08:05:12 auth_service Failed password for root from 10.99.99.99 port 22"
        parsed = parse_log_line(raw_log)
        self.assertEqual(parsed["service"], "auth_service")
        self.assertEqual(parsed["event_type"], "auth_failure")
        self.assertEqual(parsed["source_ip"], "10.99.99.99")
        self.assertEqual(parsed["user"], "root")

    def test_detector_brute_force(self):
        logs = [
            {"timestamp": "2026-09-30T08:05:12Z", "service": "auth_service", "event_type": "auth_failure", "source_ip": "10.99.99.99", "user": "root"},
            {"timestamp": "2026-09-30T08:05:15Z", "service": "auth_service", "event_type": "auth_failure", "source_ip": "10.99.99.99", "user": "root"},
            {"timestamp": "2026-09-30T08:05:18Z", "service": "auth_service", "event_type": "auth_failure", "source_ip": "10.99.99.99", "user": "root"},
        ]
        alerts = detect_threats(logs)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["detection_type"], "BRUTE_FORCE")

    def test_risk_score(self):
        alert = {"detection_type": "BRUTE_FORCE", "source_ip": "10.99.99.99"}
        scored = calculate_risk_score(alert)
        self.assertIn("risk_score", scored)
        self.assertGreater(scored["risk_score"], 0)

if __name__ == "__main__":
    unittest.main()