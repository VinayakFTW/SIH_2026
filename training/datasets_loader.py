import pandas as pd
import numpy as np
import torch
from torch.utils.data import Dataset

ATTACK_CLASSES = [
    "attack_bot", "attack_dos_slowhttptest", "attack_dos_hulk",
    "attack_bruteforce_web", "attack_bruteforce_xss", "attack_sql_injection",
    "attack_ddos_loic_http", "attack_infiltration", "attack_dos_goldeneye",
    "attack_dos_slowloris", "attack_ftp_bruteforce", "attack_ssh_bruteforce",
    "attack_ddos_loic_udp", "attack_ddos_hoic"
]

class SequenceDataset(Dataset):
    def __init__(
        self,
        df: pd.DataFrame,
        numeric_cols: list,
        label_col: str = "Label",
        seq_len: int = 32,
        stride: int = 16,
        scaler_stats: tuple = None,
        num_ports: int = 65536,
        num_protocols: int = 256
    ):
        self.seq_len = seq_len
        self.stride = stride
        self.has_labels = label_col is not None and label_col in df.columns

        # Extract Categorical Features
        dst_ports = df["dst_port"].fillna(0).to_numpy(dtype=np.int64) if "dst_port" in df.columns else np.zeros(len(df), dtype=np.int64)
        protocols = df["protocol"].fillna(0).to_numpy(dtype=np.int64) if "protocol" in df.columns else np.zeros(len(df), dtype=np.int64)

        # Clip categorical values to valid range
        self.dst_ports = np.clip(dst_ports, 0, num_ports - 1)
        self.protocols = np.clip(protocols, 0, num_protocols - 1)

        # Extract & Clean Continuous Features
        raw_num = df[numeric_cols].to_numpy(dtype=np.float32)
        raw_num = np.nan_to_num(raw_num, nan=0.0, posinf=0.0, neginf=0.0)

        # Z-Score Standard Scaling
        if scaler_stats is None:
            self.mean = np.mean(raw_num, axis=0, keepdims=True)
            self.std = np.std(raw_num, axis=0, keepdims=True) + 1e-6
        else:
            self.mean, self.std = scaler_stats

        self.data_num = (raw_num - self.mean) / self.std

        # Process Multi-Class Attack Labels
        if self.has_labels:
            # Map labels: 0 -> Benign, 1..N -> Specific Attack Classes
            label_map = {cls_name.lower(): idx + 1 for idx, cls_name in enumerate(ATTACK_CLASSES)}
            
            def map_label(val):
                s = str(val).strip().lower()
                if s == "benign" or s == "0":
                    return 0
                return label_map.get(s, 1) # Default fallback to class 1 if unmapped attack

            self.labels = df[label_col].apply(map_label).to_numpy(dtype=np.int64)
        else:
            self.labels = None

        self.num_samples = max(0, (len(df) - self.seq_len) // self.stride)

    def __len__(self):
        return self.num_samples

    def __getitem__(self, idx):
        start = idx * self.stride
        end = start + self.seq_len

        x_num = torch.tensor(self.data_num[start:end], dtype=torch.float32)
        x_cat = {
            "dst_port": torch.tensor(self.dst_ports[start:end], dtype=torch.long),
            "protocol": torch.tensor(self.protocols[start:end], dtype=torch.long)
        }

        if self.has_labels:
            # Sequence token-level class labels [seq_len]
            seq_labels = torch.tensor(self.labels[start:end], dtype=torch.long)
            return x_num, x_cat, seq_labels

        return x_num, x_cat