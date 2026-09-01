from fastapi import FastAPI
import uvicorn

from controllers.core.health_controller import get_health_status
from controllers.core.inference_controller import analyze_pcap
from controllers.core.threat_intel_controller import get_mitre_mapping

app = FastAPI(
    title="Network Attack Forecasting Engine",
    description="Real-time predictive telemetry engine trained on intrusion datasets and mapped to MITRE ATT&CK.",
    version="1.0.0"
)

app.add_api_route(
    "/health", 
    get_health_status, 
    methods=["GET"], 
    tags=["System"]
)

app.add_api_route(
    "/api/v1/forecast/pcap", 
    analyze_pcap, 
    methods=["POST"], 
    tags=["Inference"]
)

app.add_api_route(
    "/api/v1/intel/mitre/{attack_type}", 
    get_mitre_mapping, 
    methods=["GET"], 
    tags=["Threat Intel"]
)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)