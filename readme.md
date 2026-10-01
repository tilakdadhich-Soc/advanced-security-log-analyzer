# Advanced Security Log Analyzer

An enterprise-grade, modular Python tool designed for Security Operations Center (SOC) analysts to parse raw security logs, detect sliding-window brute-force attempts, cross-reference Threat Intelligence IOCs, and assign automated risk-based severity scores.

---

## 🚀 Project Architecture

```text
advanced-security-log-analyzer/
│
├── config/                  # Configuration & Threat Intelligence Feeds
│   ├── schema.json          # Log schema validation rules
│   └── ioc_list.yaml        # Malicious IP threat intel watchlist
│
├── core/                    # Core Security Engine Logic
│   ├── __init__.py
│   ├── parser.py            # Regex-based raw log line parser
│   ├── detector.py          # Sliding-window brute-force & threat detector
│   └── scorer.py            # Dynamic risk score & severity calculator
│
├── utils/                   # Helper Modules
│   ├── __init__.py
│   ├── reputation.py        # IOC / IP reputation checker
│   └── reporter.py          # Automated JSON incident report generator
│
├── tests/                   # Automated Unit Tests & Datasets
│   ├── __init__.py
│   ├── synthetic_logs.log   # Sample security event dataset
│   └── test_detection.py    # Unittest automation suite
│
├── reports/                 # Generated Incident Reports (JSON)
├── main.py                  # Main CLI runner script
└── requirements.txt         # Project dependencies