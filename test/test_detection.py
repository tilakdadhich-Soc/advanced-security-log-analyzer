import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.parser import parse_log_line
from core.detector import detect_threats
from core.scorer import calculate

class TestSecurityAnalyzer(unittest.TestCase):

    def test_parser_auth_failure(self):
        raw_log = "026-09-30T08:05:12Z auth_service Failed password for root from 192.168.1.50 port 22"
        parsed = parse_log_line(raw_log)
        self.assertEqual(parsed["service"], "auth_service")
        self.assertEqual(parsed["event_type"], "auth_failure")
        self.assertEqual(parsed["source_ip"], "192.168.1.50")
        self.assertEqual(parsed["user"], "root")
        