from typing import Dict, Any

class ThreatIntelMapper:
    def __init__(self):
        self.tactics_db = {
            "PORT_SCAN": {
                "tactic": "Reconnaissance",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "severity": "Low"
            },
            "BRUTE_FORCE": {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "severity": "Medium"
            },
            "VOLUMETRIC_SPIKE": {
                "tactic": "Impact",
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service",
                "severity": "High"
            },
            "ANOMALOUS_TUNNEL": {
                "tactic": "Command and Control",
                "technique_id": "T1572",
                "technique_name": "Protocol Tunneling",
                "severity": "Critical"
            }
        }

    def enrich(self, attack_type: str, anomaly_score: float) -> Dict[str, Any]:
        intel = self.tactics_db.get(attack_type, {
            "tactic": "Unknown",
            "technique_id": "T0000",
            "technique_name": "Uncategorized Anomaly",
            "severity": "Informational"
        })
        return {
            **intel,
            "anomaly_score": anomaly_score,
            "forecasting_horizon_sec": 30.0
        }