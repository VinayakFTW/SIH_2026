import os
import shutil
from fastapi import UploadFile, HTTPException
from fastapi.responses import JSONResponse

from pipeline.pcap_parser import PCAPParser
from pipeline.flow_aggregator import FlowAggregator
from models.mitre_mapper import ThreatIntelMapper

mapper = ThreatIntelMapper()
aggregator = FlowAggregator()

async def analyze_pcap(file: UploadFile) -> JSONResponse:
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file extension. Provide .pcap or .pcapng")

    temp_path = f"/tmp/{file.filename}"
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        parser = PCAPParser(temp_path)
        packets = parser.extract_packets(max_packets=2000)
        flows = aggregator.aggregate_flows(packets)
        
        results = []
        for flow in flows:
            # Baseline rule-check / inference dummy logic before checkpoint integration
            is_anomaly = flow["packets_per_second"] > 500 or flow["mean_iat"] < 0.0001
            detected_type = "VOLUMETRIC_SPIKE" if is_anomaly else "NORMAL"
            
            enrichment = mapper.enrich(detected_type, anomaly_score=0.92 if is_anomaly else 0.05)
            results.append({
                "flow_id": flow["flow_id"],
                "metrics": flow,
                "threat_assessment": enrichment
            })

        return JSONResponse(content={"processed_flows": len(flows), "results": results})
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)