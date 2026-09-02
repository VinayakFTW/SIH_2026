import asyncio

import pyshark
from typing import List, Dict, Any
import nest_asyncio
nest_asyncio.apply()

class PCAPParser:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def extract_packets(self, max_packets: int = 2000):
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        cap = pyshark.FileCapture(
            self.pcap_path,
            keep_packets=False
        )

        packets = []
        try:
            for idx, pkt in enumerate(cap):
                if idx >= max_packets:
                    break
                packets.append(pkt)
        finally:
            cap.close()

        return packets