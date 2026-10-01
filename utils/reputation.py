# utils/reputation.py

import yaml
import os

def load_ioc_list():
    """Config folder se IOC threat intelligence list load karta hai."""
    # Root folder ke config/ioc_list.yaml ka path set kar rahe hain
    ioc_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'ioc_list.yaml')
    try:
        with open(ioc_path, 'r') as f:
            data = yaml.safe_load(f)
            return data.get("malicious_ips", [])
    except Exception as e:
        print(f"[!] Warning: Could not load IOC list: {e}")
        return []

def check_ip_reputation(ip_address):
    """Check karta hai ki di gayi IP malicious IOC list mein hai ya nahi."""
    malicious_ips = load_ioc_list()
    if ip_address in malicious_ips:
        return {
            "is_malicious": True,
            "threat_type": "KNOWN_MALICIOUS_IOC",
            "description": f"IP {ip_address} matches known threat intelligence feed."
        }
    return {
        "is_malicious": False,
        "threat_type": "CLEAN",
        "description": "IP not found in current IOC database."
    }