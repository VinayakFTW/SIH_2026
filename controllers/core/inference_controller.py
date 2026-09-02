import os
import shutil
import uuid
from typing import List, Dict, Any
import tempfile
import numpy as np
import torch
from torch import nn
from fastapi import UploadFile, HTTPException
from fastapi.responses import JSONResponse
import asyncio

from pipeline.pcap_parser import PCAPParser
from pipeline.flow_aggregator import FlowAggregator
from models.mitre_mapper import ThreatIntelMapper
from training.CausalTransformer import AdvancedCausalNetworkIDS
from utils.get_prediction import predict_flows  # Inference utility

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
CHECKPOINT_PATH = "checkpoints/advanced_causal_network_ids.pt"

# Label mapping matching the 15 output classes
LABEL_MAPPING = {
    0: "BENIGN",
    1: "FTP-BruteForce",
    2: "SSH-Bruteforce",
    3: "DoS-GoldenEye",
    4: "DoS-Slowloris",
    5: "DoS-SlowHTTPTest",
    6: "DoS-Hulk",
    7: "DDoS-LOIC-HTTP",
    8: "DDoS-HOIC",
    9: "Brute Force -Web",
    10: "Brute Force -XSS",
    11: "SQL Injection",
    12: "Infiltration",
    13: "Bot",
    14: "PortScan"
}

mapper = ThreatIntelMapper()
aggregator = FlowAggregator()


def load_model(checkpoint_path: str) -> torch.nn.Module:
    if not os.path.exists(checkpoint_path):
        raise FileNotFoundError(f"Checkpoint not found at {checkpoint_path}")

    model = AdvancedCausalNetworkIDS(
        num_numeric_features=76,
        num_classes=15,
        d_model=128,
        nhead=4,
        num_layers=3,
        ff_dim=512,
        max_seq_len=32
    )

    checkpoint = torch.load(checkpoint_path, map_location=DEVICE)
    if isinstance(checkpoint, dict):
        if "state_dict" in checkpoint:
            state_dict = checkpoint["state_dict"]
        elif "model_state_dict" in checkpoint:
            state_dict = checkpoint["model_state_dict"]
        elif "model" in checkpoint and isinstance(checkpoint["model"], dict):
            state_dict = checkpoint["model"]
        else:
            state_dict = checkpoint
    elif isinstance(checkpoint, nn.Module):
        model = checkpoint
        model.to(DEVICE)
        model.eval()
        return model
    else:
        raise TypeError(f"Unsupported checkpoint format: {type(checkpoint)}")

    cleaned_state_dict = {
        (k[7:] if k.startswith("module.") else k): v
        for k, v in state_dict.items()
    }

    model.load_state_dict(cleaned_state_dict)
    model.to(DEVICE)
    model.eval()
    return model


model = load_model(CHECKPOINT_PATH)


async def analyze_pcap(file: UploadFile) -> JSONResponse:
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file extension. Provide .pcap or .pcapng"
        )

    temp_dir = tempfile.gettempdir()
    temp_filename = f"{uuid.uuid4()}_{file.filename}"
    temp_path = os.path.join(temp_dir, temp_filename)
    
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        parser = PCAPParser(temp_path)
        
        # Offload parsing and aggregation to worker thread
        packets = await asyncio.to_thread(parser.extract_packets, 2000)
        flows = await asyncio.to_thread(aggregator.aggregate_flows, packets)

        if not flows:
            return JSONResponse(content={"processed_flows": 0, "results": []})

        # Run inference
        predictions, anomaly_scores = predict_flows(
            flows=flows,
            model=model,
            label_mapping=LABEL_MAPPING,
            device=DEVICE,
            max_seq_len=32
        )

        results = []
        for flow, pred_label, anomaly_score in zip(flows, predictions, anomaly_scores):
            detected_type = pred_label if pred_label != "BENIGN" else ("ANOMALY" if anomaly_score >= 0.5 else "BENIGN")
            enrichment = mapper.enrich(detected_type, anomaly_score=float(anomaly_score))
            
            results.append({
                "flow_id": flow.get("flow_id"),
                "detected_label": pred_label,
                "anomaly_score": round(float(anomaly_score), 4),
                "metrics": flow,
                "threat_assessment": enrichment
            })

        return JSONResponse(content={"processed_flows": len(flows), "results": results})

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)