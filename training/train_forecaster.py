import torch
from torch.utils.data import DataLoader, random_split
from training.datasets_loader import UnifiedNetworkDataset

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    dataset = UnifiedNetworkDataset(
        datasets_dir="datasets",
        sequence_length=15,
        prediction_horizon=1,
        is_train=True
    )

    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_set, val_set = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_set, batch_size=256, shuffle=True, pin_memory=True)
    val_loader = DataLoader(val_set, batch_size=256, shuffle=False)

    print(f"Successfully loaded {len(dataset)} sequence windows across datasets.")
    print(f"Training batches: {len(train_loader)} | Validation batches: {len(val_loader)}")

    for x_seq, y_next, y_label in train_loader:
        print(f"Batch sequence shape: {x_seq.shape}")
        print(f"Batch target shape:   {y_next.shape}")
        print(f"Batch label shape:    {y_label.shape}")
        break

    
    
if __name__ == "__main__":
    main()