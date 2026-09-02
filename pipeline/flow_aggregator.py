import numpy as np
from collections import defaultdict
from typing import List, Dict, Any

class FlowAggregator:
    def __init__(self):
        pass

    def _extract_packet_meta(self, pkt):
        """Safely extracts 5-tuple and packet length/timestamp across PyShark or Scapy."""
        # --- Handle PyShark Packet Objects ---
        if hasattr(pkt, "layers"):
            ip_layer = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
            if not ip_layer:
                return None  # Non-IP packet (ARP, STP, LLC, etc.)

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = int(getattr(ip_layer, "proto", getattr(ip_layer, "nxt", 0)))

            src_port = 0
            dst_port = 0
            if hasattr(pkt, "tcp"):
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
            elif hasattr(pkt, "udp"):
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)

            length = int(pkt.length) if hasattr(pkt, "length") else 0
            timestamp = float(pkt.sniff_timestamp) if hasattr(pkt, "sniff_timestamp") else 0.0

            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "length": length,
                "timestamp": timestamp,
                "raw_pkt": pkt
            }

        # --- Handle Scapy Packet Objects (Fallback if switched to Scapy) ---
        elif hasattr(pkt, "haslayer"):
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6

            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                return None

            ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto if hasattr(ip_layer, "proto") else 0

            src_port = 0
            dst_port = 0
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            length = len(pkt)
            timestamp = float(pkt.time)

            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "length": length,
                "timestamp": timestamp,
                "raw_pkt": pkt
            }

        return None

    def aggregate_flows(self, packets):
        flow_groups = {}

        for pkt in packets:
            meta = self._extract_packet_meta(pkt)
            if not meta:
                continue  # Skip unroutable/non-IP packets

            # Bidirectional 5-tuple flow key
            endpoints = tuple(sorted([
                (meta["src_ip"], meta["src_port"]),
                (meta["dst_ip"], meta["dst_port"])
            ]))
            flow_key = (endpoints, meta["protocol"])

            if flow_key not in flow_groups:
                flow_groups[flow_key] = []
            flow_groups[flow_key].append(meta)

        flows = []
        for (endpoints, proto), pkt_list in flow_groups.items():
            first_pkt = pkt_list[0]
            flow_id = f"{first_pkt['src_ip']}:{first_pkt['src_port']} <-> {first_pkt['dst_ip']}:{first_pkt['dst_port']}"
            
            # Base flow metadata dictionary
            flow_dict = {
                "flow_id": flow_id,
                "src_ip": first_pkt["src_ip"],
                "dst_ip": first_pkt["dst_ip"],
                "dst_port": first_pkt["dst_port"],
                "protocol": proto,
                "tot_fwd_pkts": len(pkt_list),
                "tot_bwd_pkts": 0,
                "flow_duration": max(p["timestamp"] for p in pkt_list) - min(p["timestamp"] for p in pkt_list),
            }

            flows.append(flow_dict)

        return flows