import pyshark
from typing import List, Dict, Any

class PCAPParser:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def extract_packets(self, max_packets: int = 5000) -> List[Dict[str, Any]]:
        cap = pyshark.FileCapture(
            self.pcap_path,
            use_json=True,
            include_names=False,
            keep_packets=False
        )
        parsed_packets = []
        
        try:
            for idx, pkt in enumerate(cap):
                if idx >= max_packets:
                    break
                if 'IP' not in pkt:
                    continue

                proto = pkt.transport_layer if pkt.transport_layer else "OTHER"
                src_port = pkt[pkt.transport_layer].srcport if pkt.transport_layer else 0
                dst_port = pkt[pkt.transport_layer].dstport if pkt.transport_layer else 0

                pkt_data = {
                    "timestamp": float(pkt.sniff_timestamp),
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "protocol": proto,
                    "src_port": int(src_port),
                    "dst_port": int(dst_port),
                    "length": int(pkt.length),
                    "tcp_flags": pkt.tcp.flags if 'TCP' in pkt else None,
                }
                parsed_packets.append(pkt_data)
        finally:
            cap.close()

        return parsed_packets