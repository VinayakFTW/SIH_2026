import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_curve

from training.CausalTransformer import AdvancedCausalNetworkIDS
from training.datasets_loader import SequenceDataset, ATTACK_CLASSES

def train_and_evaluate(
    parquet_path: str,
    label_col: str = "Label",
    seq_len: int = 32,
    batch_size: int = 256,
    epochs: int = 5,
    lr: float = 1e-3,
    train_split: float = 0.7
):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Running on device: {device}")

    df = pd.read_parquet(parquet_path)
    print(f"[*] Loaded dataset: {len(df):,} total rows.")

    # Exclude categorical and label columns to isolate continuous features
    categorical_cols = ["dst_port", "protocol"]
    exclude_cols = categorical_cols + ([label_col] if label_col else [])
    
    numeric_cols = [
        c for c in df.select_dtypes(include=[np.number]).columns
        if c not in exclude_cols
    ]
    print(f"[*] Identified {len(numeric_cols)} continuous features.")

    # Chronological Split
    split_idx = int(len(df) * train_split)
    train_df = df.iloc[:split_idx].reset_index(drop=True)
    test_df = df.iloc[split_idx:].reset_index(drop=True)

    # Dataset Instantiation
    train_dataset = SequenceDataset(
        train_df, numeric_cols, label_col=label_col, seq_len=seq_len, stride=16
    )
    scaler_stats = (train_dataset.mean, train_dataset.std)

    test_dataset = SequenceDataset(
        test_df, numeric_cols, label_col=label_col, seq_len=seq_len, stride=8, scaler_stats=scaler_stats
    )

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, pin_memory=True, num_workers=0)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, pin_memory=True, num_workers=0)

    # Initialize Advanced Causal Transformer
    num_classes = len(ATTACK_CLASSES) + 1  # 0: Benign, 1..14: Attack Classes
    model = AdvancedCausalNetworkIDS(
        num_numeric_features=len(numeric_cols),
        num_classes=num_classes,
        num_ports=65536,
        num_protocols=256,
        d_model=128,
        nhead=4,
        num_layers=3,
        ff_dim=512,
        max_seq_len=seq_len
    ).to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    
    mse_criterion = nn.MSELoss()
    ce_criterion = nn.CrossEntropyLoss()

    print("\n--- Training Dual-Task Transformer (Next-Flow + Classification) ---")
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0

        for batch in train_loader:
            if train_dataset.has_labels:
                x_num, x_cat, labels = batch
                labels = labels.to(device)
            else:
                x_num, x_cat = batch
                labels = None

            x_num = x_num.to(device)
            x_cat = {k: v.to(device) for k, v in x_cat.items()}

            optimizer.zero_grad()
            
            # Forward pass through model
            outputs = model(x_num, x_cat)
            
            # Loss 1: Next-flow prediction loss (x_{1..t-1} predicts x_{2..t})
            pred_next_flow = outputs["next_flow"][:, :-1, :]
            target_next_flow = x_num[:, 1:, :]
            loss_next_flow = mse_criterion(pred_next_flow, target_next_flow)

            # Loss 2: Token classification loss
            loss_cls = 0.0
            if labels is not None:
                logits = outputs["classification"].reshape(-1, num_classes)
                loss_cls = ce_criterion(logits, labels.reshape(-1))

            # Total Loss combination
            loss = loss_next_flow + (0.5 * loss_cls if labels is not None else 0.0)
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss += loss.item() * x_num.size(0)

        scheduler.step()
        epoch_loss = total_loss / len(train_dataset)
        print(f"Epoch [{epoch+1}/{epochs}] - Loss: {epoch_loss:.6f}")

    # Evaluation Step
    print("\n--- Computing Anomaly Verification on Test Set ---")
    model.eval()
    all_scores = []
    all_labels = []

    with torch.no_grad():
        for batch in test_loader:
            if test_dataset.has_labels:
                x_num, x_cat, labels = batch
                # Binary Window-level Ground Truth (1 if any flow in sequence is an attack)
                window_has_attack = (labels > 0).any(dim=1).numpy()
                all_labels.extend(window_has_attack)
            else:
                x_num, x_cat = batch

            x_num = x_num.to(device)
            x_cat = {k: v.to(device) for k, v in x_cat.items()}

            outputs = model(x_num, x_cat)

            # Compute Anomaly Score using Next-Flow Prediction MSE Error
            pred_next_flow = outputs["next_flow"][:, :-1, :]
            target_next_flow = x_num[:, 1:, :]
            
            window_mse = torch.mean((pred_next_flow - target_next_flow) ** 2, dim=[1, 2]).cpu().numpy()
            all_scores.extend(window_mse)

    all_scores = np.array(all_scores)

    if test_dataset.has_labels:
        all_labels = np.array(all_labels)
        auc = roc_auc_score(all_labels, all_scores)
        pr_auc = average_precision_score(all_labels, all_scores)

        precisions, recalls, thresholds = precision_recall_curve(all_labels, all_scores)
        f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
        best_idx = np.argmax(f1_scores)
        best_threshold = thresholds[min(best_idx, len(thresholds) - 1)]

        print("\n================ Results ================")
        print(f"ROC-AUC Score          : {auc:.4f}")
        print(f"PR-AUC (Avg Precision) : {pr_auc:.4f}")
        print(f"Optimal MSE Threshold  : {best_threshold:.6f}")
        print(f"Best Window F1-Score   : {f1_scores[best_idx]:.4f}")
        print("=========================================")

    torch.save(model.state_dict(), "advanced_causal_network_ids.pt")
    print("\n[+] Saved model checkpoint to 'advanced_causal_network_ids.pt'")

if __name__ == "__main__":
    PARQUET_FILE = "D:\\Work\\Github\\SIH_2026\\cache\\unified_dataset_final.parquet"
    LABEL_COLUMN = "Label"

    if os.path.exists(PARQUET_FILE):
        train_and_evaluate(
            parquet_path=PARQUET_FILE,
            label_col=LABEL_COLUMN,
            seq_len=32,
            batch_size=512,
            epochs=5,
            train_split=0.7
        )
    else:
        print(f"File not found: '{PARQUET_FILE}'. Please verify path.")