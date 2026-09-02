import os
import tempfile
import torch
import numpy as np
import pandas as pd
from cicflowmeter.sniffer import create_sniffer
from typing import List, Dict, Any, Tuple
# ---------------------------------------------------------
# 1. Feature Specifications
# ---------------------------------------------------------
CATEGORICAL_COLS = ["dst_port", "protocol"]

NUMERIC_COLS = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
    "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean",
    "bwd_pkt_len_std", "flow_bytes_per_sec", "flow_pkts_per_sec", "flow_iat_mean",
    "flow_iat_std", "flow_iat_max", "flow_iat_min", "fwd_iat_tot",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max",
    "bwd_iat_min", "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags",
    "bwd_urg_flags", "fwd_header_len", "bwd_header_len", "fwd_pkts_per_sec",
    "bwd_pkts_per_sec", "pkt_len_min", "pkt_len_max", "pkt_len_mean",
    "pkt_len_std", "pkt_len_var", "fin_flag_cnt", "syn_flag_cnt",
    "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt",
    "cwe_flag_count", "ece_flag_cnt", "down_up_ratio", "pkt_size_avg",
    "fwd_seg_size_avg", "bwd_seg_size_avg", "fwd_byts_b_avg", "fwd_pkts_b_avg",
    "fwd_blk_rate_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg",
    "subflow_fwd_pkts", "subflow_fwd_byts", "subflow_bwd_pkts", "subflow_bwd_byts",
    "init_fwd_win_byts", "init_bwd_win_byts", "fwd_act_data_pkts", "fwd_seg_size_min",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min"
]

# Standard name normalization mapping from CICFlowMeter raw CSV output
COLUMN_MAPPING = {
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "tot_fwd_pkts",
    "Tot Bwd Pkts": "tot_bwd_pkts",
    "TotLen Fwd Pkts": "totlen_fwd_pkts",
    "TotLen Bwd Pkts": "totlen_bwd_pkts",
    "Fwd Pkt Len Max": "fwd_pkt_len_max",
    "Fwd Pkt Len Min": "fwd_pkt_len_min",
    "Fwd Pkt Len Mean": "fwd_pkt_len_mean",
    "Fwd Pkt Len Std": "fwd_pkt_len_std",
    "Bwd Pkt Len Max": "bwd_pkt_len_max",
    "Bwd Pkt Len Min": "bwd_pkt_len_min",
    "Bwd Pkt Len Mean": "bwd_pkt_len_mean",
    "Bwd Pkt Len Std": "bwd_pkt_len_std",
    "Flow Byts/s": "flow_bytes_per_sec",
    "Flow Pkts/s": "flow_pkts_per_sec",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Tot": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Tot": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Len": "fwd_header_len",
    "Bwd Header Len": "bwd_header_len",
    "Fwd Pkts/s": "fwd_pkts_per_sec",
    "Bwd Pkts/s": "bwd_pkts_per_sec",
    "Pkt Len Min": "pkt_len_min",
    "Pkt Len Max": "pkt_len_max",
    "Pkt Len Mean": "pkt_len_mean",
    "Pkt Len Std": "pkt_len_std",
    "Pkt Len Var": "pkt_len_var",
    "FIN Flag Cnt": "fin_flag_cnt",
    "SYN Flag Cnt": "syn_flag_cnt",
    "RST Flag Cnt": "rst_flag_cnt",
    "PSH Flag Cnt": "psh_flag_cnt",
    "ACK Flag Cnt": "ack_flag_cnt",
    "URG Flag Cnt": "urg_flag_cnt",
    "CWE Flag Count": "cwe_flag_count",
    "ECE Flag Cnt": "ece_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Pkt Size Avg": "pkt_size_avg",
    "Fwd Seg Size Avg": "fwd_seg_size_avg",
    "Bwd Seg Size Avg": "bwd_seg_size_avg",
    "Fwd Byts/b Avg": "fwd_byts_b_avg",
    "Fwd Pkts/b Avg": "fwd_pkts_b_avg",
    "Fwd Blk Rate Avg": "fwd_blk_rate_avg",
    "Bwd Byts/b Avg": "bwd_byts_b_avg",
    "Bwd Pkts/b Avg": "bwd_pkts_b_avg",
    "Bwd Blk Rate Avg": "bwd_blk_rate_avg",
    "Subflow Fwd Pkts": "subflow_fwd_pkts",
    "Subflow Fwd Byts": "subflow_fwd_byts",
    "Subflow Bwd Pkts": "subflow_bwd_pkts",
    "Subflow Bwd Byts": "subflow_bwd_byts",
    "Init Fwd Win Byts": "init_fwd_win_byts",
    "Init Bwd Win Byts": "init_bwd_win_byts",
    "Fwd Act Data Pkts": "fwd_act_data_pkts",
    "Fwd Seg Size Min": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}

# ---------------------------------------------------------
# 2. PCAP to DataFrame Conversion
# ---------------------------------------------------------
def pcap_to_df(pcap_path: str) -> pd.DataFrame:
    """Runs cicflowmeter on a pcap and returns a cleaned DataFrame."""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp_csv:
        output_csv = tmp_csv.name

    try:
        # Sniff and write flow CSV
        sniffer = create_sniffer(
            input_file=pcap_path,
            output_mode="csv",
            output_destination=output_csv,
        )
        sniffer.start()
        sniffer.join()

        df = pd.read_csv(output_csv)
    finally:
        if os.path.exists(output_csv):
            os.remove(output_csv)

    # Clean and standardize column names
    df.columns = df.columns.str.strip()
    df.rename(columns=COLUMN_MAPPING, inplace=True)
    
    # Fill missing expected features with 0 if absent
    for col in CATEGORICAL_COLS + NUMERIC_COLS:
        if col not in df.columns:
            df[col] = 0.0

    return df

# ---------------------------------------------------------
# 3. Model Inference Pipeline
# ---------------------------------------------------------
def predict_flows(
    flows: List[Dict[str, Any]],
    model: torch.nn.Module,
    label_mapping: Dict[int, str],
    scaler=None,
    device: torch.device = torch.device("cpu"),
    max_seq_len: int = 32
) -> Tuple[List[str], List[float]]:
    df = pd.DataFrame(flows)

    # Ensure all required numeric columns exist
    for col in NUMERIC_COLS:
        if col not in df.columns:
            df[col] = 0.0

    numeric_df = df[NUMERIC_COLS].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    if scaler is not None:
        numeric_arr = scaler.transform(numeric_df)
    else:
        numeric_arr = np.log1p(np.maximum(numeric_df.values, 0.0))

    dst_port_arr = np.clip(df.get("dst_port", pd.Series(0, index=df.index)).fillna(0).astype(int).values, 0, 65535)
    protocol_arr = np.clip(df.get("protocol", pd.Series(0, index=df.index)).fillna(0).astype(int).values, 0, 255)

    num_flows = len(df)
    pred_labels = []
    anomaly_scores = []

    with torch.no_grad():
        for start_idx in range(0, num_flows, max_seq_len):
            end_idx = min(start_idx + max_seq_len, num_flows)

            x_num = torch.tensor(
                numeric_arr[start_idx:end_idx], dtype=torch.float32
            ).unsqueeze(0).to(device)

            x_cat = {
                "dst_port": torch.tensor(
                    dst_port_arr[start_idx:end_idx], dtype=torch.long
                ).unsqueeze(0).to(device),
                "protocol": torch.tensor(
                    protocol_arr[start_idx:end_idx], dtype=torch.long
                ).unsqueeze(0).to(device),
            }

            out = model(x_num, x_cat)
            logits = out["classification"].squeeze(0)
            scores = out["anomaly_score"].squeeze(0)

            classes = torch.argmax(logits, dim=-1).cpu().numpy()
            pred_labels.extend([label_mapping.get(c, "UNKNOWN") for c in classes])
            anomaly_scores.extend(scores.cpu().numpy().tolist())

    return pred_labels, anomaly_scores