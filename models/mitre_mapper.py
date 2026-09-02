from typing import Dict, Any

class ThreatIntelMapper:
    def __init__(self):
        self.tactics_db = {
            "BENIGN": {
                "tactic": "None",
                "technique_id": "None",
                "technique_name": "Normal Traffic",
                "severity": "None",
            },
            # --- Reconnaissance ---
            "PortScan": {
                "tactic": "Reconnaissance",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "severity": "Low",
            },
            # --- Credential Access ---
            "FTP-BruteForce": {
                "tactic": "Credential Access",
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "severity": "Medium",
            },
            "SSH-Bruteforce": {
                "tactic": "Credential Access",
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "severity": "High",
            },
            "Brute Force -Web": {
                "tactic": "Credential Access",
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "severity": "Medium",
            },
            "Brute Force -XSS": {
                "tactic": "Initial Access",
                "technique_id": "T1189",
                "technique_name": "Drive-by Compromise",
                "severity": "Medium",
            },
            # --- Initial Access & Execution ---
            "SQL Injection": {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "severity": "Critical",
            },
            "Infiltration": {
                "tactic": "Lateral Movement",
                "technique_id": "T1210",
                "technique_name": "Exploitation of Remote Services",
                "severity": "Critical",
            },
            "Bot": {
                "tactic": "Command and Control",
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "severity": "High",
            },
            # --- Denial of Service & Impact ---
            "DoS-GoldenEye": {
                "tactic": "Impact",
                "technique_id": "T1499.003",
                "technique_name": "Endpoint DoS: Application Exhaustion Flood",
                "severity": "High",
            },
            "DoS-Slowloris": {
                "tactic": "Impact",
                "technique_id": "T1499.003",
                "technique_name": "Endpoint DoS: Application Exhaustion Flood",
                "severity": "High",
            },
            "DoS-SlowHTTPTest": {
                "tactic": "Impact",
                "technique_id": "T1499.003",
                "technique_name": "Endpoint DoS: Application Exhaustion Flood",
                "severity": "High",
            },
            "DoS-Hulk": {
                "tactic": "Impact",
                "technique_id": "T1498.001",
                "technique_name": "Network DoS: Direct Network Flood",
                "severity": "High",
            },
            "DDoS-LOIC-HTTP": {
                "tactic": "Impact",
                "technique_id": "T1498.001",
                "technique_name": "Network DoS: Direct Network Flood",
                "severity": "Critical",
            },
            "DDoS-HOIC": {
                "tactic": "Impact",
                "technique_id": "T1498.001",
                "technique_name": "Network DoS: Direct Network Flood",
                "severity": "Critical",
            },
            # --- Generic Anomaly Fallback ---
            "ANOMALY": {
                "tactic": "Defense Evasion",
                "technique_id": "T1001",
                "technique_name": "Data Obfuscation / Unknown Traffic Anomaly",
                "severity": "Medium",
            }
        }

    def enrich(self, attack_type: str, anomaly_score: float) -> Dict[str, Any]:
        # Exact match or fallback to Uncategorized Anomaly
        intel = self.tactics_db.get(
            attack_type,
            {
                "tactic": "Unknown",
                "technique_id": "T0000",
                "technique_name": "Uncategorized Anomaly",
                "severity": "Informational",
            }
        )
        return {
            **intel,
            "anomaly_score": round(anomaly_score, 4),
            "forecasting_horizon_sec": 30.0,
        }