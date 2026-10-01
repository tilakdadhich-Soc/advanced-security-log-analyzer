# utils/reporter.py

import json
import os
from datetime import datetime

def generate_incident_report(scored_alerts, output_dir="reports"):
    """Detected aur scored alerts ka ek professional JSON incident report banata hai."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = os.path.join(output_dir, f"security_incident_report_{timestamp_str}.json")
    
    report_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_alerts": len(scored_alerts),
        "alerts": scored_alerts
    }
    
    with open(report_filename, 'w') as f:
        json.dump(report_data, f, indent=4)
        
    print(f"[+] Incident report successfully generated: {report_filename}")
    return report_filename