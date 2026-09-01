CANONICAL_FEATURES = [
    "duration",
    "total_fwd_pkts",
    "total_bwd_pkts",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "mean_packet_len",
    "std_packet_len",
    "mean_iat",
    "std_iat",
    "flow_bytes_per_sec",
    "flow_pkts_per_sec",
    "label"
]

DATASET_COLUMN_MAPPINGS = {
    # CIC-IDS2017 / CIC-IDS2018 / CICIoT2023 conventions
    "cic": {
        "Flow Duration": "duration",
        "Total Fwd Packets": "total_fwd_pkts",
        "Total Backward Packets": "total_bwd_pkts",
        "Total Length of Fwd Packets": "total_fwd_bytes",
        "Total Length of Bwd Packets": "total_bwd_bytes",
        "Packet Length Mean": "mean_packet_len",
        "Packet Length Std": "std_packet_len",
        "Flow IAT Mean": "mean_iat",
        "Flow IAT Std": "std_iat",
        "Flow Bytes/s": "flow_bytes_per_sec",
        "Flow Packets/s": "flow_pkts_per_sec",
        "Label": "label"
    },
    # UNSW-NB15 conventions
    "unsw": {
        "dur": "duration",
        "spkts": "total_fwd_pkts",
        "dpkts": "total_bwd_pkts",
        "sbytes": "total_fwd_bytes",
        "dbytes": "total_bwd_bytes",
        "smeansz": "mean_packet_len",
        "sinpkt": "mean_iat",
        "rate": "flow_pkts_per_sec",
        "attack_cat": "label"
    }
}