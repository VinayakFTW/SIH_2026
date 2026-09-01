import numpy as np
from collections import defaultdict
from typing import List, Dict, Any

class FlowAggregator:
    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = window_seconds

    def aggregate_flows(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        flows = defaultdict(list)

        # Group by bidirectional 5-tuple
        for pkt in packets:
            endpoints = tuple(sorted([(pkt["src_ip"], pkt["src_port"]), (pkt["dst_ip"], pkt["dst_port"])]))
            flow_key = (endpoints[0], endpoints[1], pkt["protocol"])
            flows[flow_key].append(pkt)

        flow_features = []
        for key, pkts in flows.items():
            pkts = sorted(pkts, key=lambda x: x["timestamp"])
            timestamps = [p["timestamp"] for p in pkts]
            lengths = [p["length"] for p in pkts]

            duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.001
            iats = np.diff(timestamps) if len(timestamps) > 1 else [0.0]

            # Forward / Backward split based on flow initiator
            initiator_ip = pkts[0]["src_ip"]
            fwd_pkts = [p for p in pkts if p["src_ip"] == initiator_ip]
            bwd_pkts = [p for p in pkts if p["src_ip"] != initiator_ip]

            flow_record = {
                "flow_id": f"{key[0][0]}:{key[0][1]}->{key[1][0]}:{key[1][1]}_{key[2]}",
                "duration": duration,
                "total_fwd_packets": len(fwd_pkts),
                "total_bwd_packets": len(bwd_pkts),
                "total_length": sum(lengths),
                "mean_packet_length": float(np.mean(lengths)),
                "std_packet_length": float(np.std(lengths)) if len(lengths) > 1 else 0.0,
                "mean_iat": float(np.mean(iats)),
                "std_iat": float(np.std(iats)) if len(iats) > 1 else 0.0,
                "bytes_per_second": sum(lengths) / duration if duration > 0 else 0.0,
                "packets_per_second": len(pkts) / duration if duration > 0 else 0.0,
            }
            flow_features.append(flow_record)

        return flow_features