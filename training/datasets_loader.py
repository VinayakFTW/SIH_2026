import os
import glob
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset
from sklearn.preprocessing import RobustScaler

from training.schema_mappings import CANONICAL_FEATURES, DATASET_COLUMN_MAPPINGS


class UnifiedNetworkDataset(Dataset):
    """
    Unified PyTorch dataset that loads and normalizes all .parquet and .csv 
    files from the root 'datasets/' folder.
    """
    def __init__(
        self,
        datasets_dir: str = "datasets",
        sequence_length: int = 20,
        prediction_horizon: int = 1,
        scaler: Optional[RobustScaler] = None,
        is_train: bool = True
    ):
        self.datasets_dir = Path(datasets_dir)
        self.sequence_length = sequence_length
        self.prediction_horizon = prediction_horizon
        self.is_train = is_train

        self.raw_df = self._load_and_harmonize_all()
        
        feature_cols = [col for col in self.raw_df.columns if col != "label"]
        raw_features = self.raw_df[feature_cols].values.astype(np.float32)
        
        labels = self.raw_df["label"].apply(lambda x: 0 if str(x).strip().lower() in ["benign", "normal", "0"] else 1).values

        # Feature scaling (RobustScaler handles heavy-tailed network outliers)
        if self.is_train or scaler is None:
            self.scaler = RobustScaler(quantile_range=(5.0, 95.0))
            self.scaled_features = self.scaler.fit_transform(raw_features)
        else:
            self.scaler = scaler
            self.scaled_features = self.scaler.transform(raw_features)

        self.labels = labels

    def _detect_format_and_read(self, file_path: Path) -> pd.DataFrame:
        """Reads CSV or Parquet files based on file extension."""
        ext = file_path.suffix.lower()
        if ext == ".parquet":
            return pd.read_parquet(file_path, engine="pyarrow")
        elif ext == ".csv":
            return pd.read_csv(file_path, low_memory=False)
        else:
            return pd.DataFrame()

    def _normalize_columns(self, df: pd.DataFrame, filename: str) -> pd.DataFrame:
        """Applies column alias transformations to align with CANONICAL_FEATURES."""
        df_cols_lower = {col.strip(): col for col in df.columns}
        
        mapping_key = "unsw" if "unsw" in filename.lower() else "cic"
        mapping = DATASET_COLUMN_MAPPINGS.get(mapping_key, {})

        rename_dict = {}
        for src_col, target_col in mapping.items():
            if src_col in df_cols_lower:
                rename_dict[df_cols_lower[src_col]] = target_col

        df = df.rename(columns=rename_dict)
        df = df.loc[:, ~df.columns.duplicated()]
        available_cols = [c for c in CANONICAL_FEATURES if c in df.columns]
        df = df[available_cols]

        for missing_col in set(CANONICAL_FEATURES) - set(available_cols):
            if missing_col == "label":
                df[missing_col] = "BENIGN"
            else:
                df[missing_col] = 0.0

        return df[CANONICAL_FEATURES]

    def _load_and_harmonize_all(self) -> pd.DataFrame:
        data_files = list(self.datasets_dir.glob("*.parquet")) + list(self.datasets_dir.glob("*.csv"))
        if not data_files:
            raise FileNotFoundError(f"No .csv or .parquet files found in directory: {self.datasets_dir.resolve()}")

        dataframes = []
        for file in data_files:
            df = self._detect_format_and_read(file)
            if df.empty:
                continue

            df = self._normalize_columns(df, file.name)
            
            num_cols = [c for c in df.columns if c != "label"]
            df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
            df[num_cols] = df[num_cols].fillna(0.0)

            dataframes.append(df)

        return pd.concat(dataframes, ignore_index=True)

    def __len__(self) -> int:
        return max(0, len(self.scaled_features) - self.sequence_length - self.prediction_horizon + 1)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Returns:
            x_seq: [sequence_length, num_features] - Historical traffic window
            y_forecasting: [num_features] - Future traffic vector at (t + horizon)
            y_threat_label: scalar (0 = Benign, 1 = Attack progression)
        """
        x_seq = self.scaled_features[idx : idx + self.sequence_length]
        target_idx = idx + self.sequence_length + self.prediction_horizon - 1
        
        y_forecasting = self.scaled_features[target_idx]
        y_threat_label = self.labels[target_idx]

        return (
            torch.tensor(x_seq, dtype=torch.float32),
            torch.tensor(y_forecasting, dtype=torch.float32),
            torch.tensor(y_threat_label, dtype=torch.float32)
        )