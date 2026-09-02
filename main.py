from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from controllers.core.health_controller import get_health_status
from controllers.core.inference_controller import analyze_pcap
from controllers.core.threat_intel_controller import get_mitre_mapping
from controllers.core.summarizer_controller import generate_threat_summary

app = FastAPI(
    title="Network Attack Forecasting Engine",
    description="Real-time predictive telemetry engine trained on intrusion datasets and mapped to MITRE ATT&CK.",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

app.add_api_route(
    "/api/v1/summarize",
    generate_threat_summary,
    methods=["POST"],
    tags=["Threat Intel"],
)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)