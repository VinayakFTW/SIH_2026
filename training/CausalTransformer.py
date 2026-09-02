import math
from typing import Dict, Optional, Sequence

import torch
import torch.nn as nn
import torch.nn.functional as F


class MLP(nn.Module):
    def __init__(
        self,
        in_dim: int,
        hidden_dim: int,
        out_dim: int,
        dropout: float = 0.1,
    ):
        super().__init__()

        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, out_dim),
        )

    def forward(self, x):
        return self.net(x)


class FeatureGate(nn.Module):
    """
    Learns which input features should be emphasized/suppressed.
    """

    def __init__(self, input_dim: int, hidden_dim: int = 128):
        super().__init__()

        self.gate = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return x * self.gate(x)


class CausalTransformerBlock(nn.Module):
    """
    Standard causal Transformer encoder block.
    """

    def __init__(
        self,
        d_model: int,
        nhead: int,
        ff_dim: int,
        dropout: float,
    ):
        super().__init__()

        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)

        self.attention = nn.MultiheadAttention(
            embed_dim=d_model,
            num_heads=nhead,
            dropout=dropout,
            batch_first=True,
        )

        self.ffn = nn.Sequential(
            nn.Linear(d_model, ff_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(ff_dim, d_model),
            nn.Dropout(dropout),
        )

    def forward(self, x, causal_mask):
        # Pre-norm attention
        h = self.norm1(x)

        attn_out, _ = self.attention(
            h,
            h,
            h,
            attn_mask=causal_mask,
            need_weights=False,
        )

        x = x + attn_out

        # Feed-forward
        x = x + self.ffn(self.norm2(x))

        return x


class AdvancedCausalNetworkIDS(nn.Module):
    """
    Advanced causal Transformer for network IDS.

    Inputs:
        x_numeric:
            [B, L, num_numeric_features]

        x_categorical:
            dict containing integer categorical tensors:
                {
                    "dst_port": [B, L],
                    "protocol": [B, L],
                }

    Outputs:
        {
            "classification": [B, L, num_classes],
            "next_flow": [B, L, num_numeric_features],
            "embedding": [B, L, d_model],
            "anomaly_score": [B, L]
        }

    Training concept:

        x[:, :-1] -> predict x[:, 1:]

    so the model learns future network behavior rather than
    reconstructing the current flow.
    """

    def __init__(
        self,
        num_numeric_features: int,
        num_classes: int,
        num_ports: int = 65536,
        num_protocols: int = 256,
        d_model: int = 128,
        nhead: int = 4,
        num_layers: int = 4,
        ff_dim: int = 512,
        max_seq_len: int = 512,
        port_embedding_dim: int = 32,
        protocol_embedding_dim: int = 16,
        dropout: float = 0.1,
    ):
        super().__init__()

        self.num_numeric_features = num_numeric_features
        self.num_classes = num_classes
        self.d_model = d_model
        self.max_seq_len = max_seq_len

        # ---------------------------------------------------------
        # 1. Categorical feature embeddings
        # ---------------------------------------------------------

        self.port_embedding = nn.Embedding(
            num_embeddings=num_ports,
            embedding_dim=port_embedding_dim,
        )

        self.protocol_embedding = nn.Embedding(
            num_embeddings=num_protocols,
            embedding_dim=protocol_embedding_dim,
        )

        # ---------------------------------------------------------
        # 2. Numerical feature encoder
        # ---------------------------------------------------------

        self.numeric_encoder = nn.Sequential(
            nn.Linear(num_numeric_features, 128),
            nn.LayerNorm(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
        )

        # ---------------------------------------------------------
        # 3. Feature gate
        # ---------------------------------------------------------

        self.feature_gate = FeatureGate(
            input_dim=num_numeric_features,
            hidden_dim=128,
        )

        # ---------------------------------------------------------
        # 4. Feature fusion
        # ---------------------------------------------------------

        fusion_dim = (
            64
            + port_embedding_dim
            + protocol_embedding_dim
        )

        self.fusion = nn.Sequential(
            nn.Linear(fusion_dim, d_model),
            nn.LayerNorm(d_model),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # ---------------------------------------------------------
        # 5. Learned positional embedding
        #
        # No timestamp required.
        #
        # Position 0, 1, 2, ...
        # represents temporal order in the flow sequence.
        # ---------------------------------------------------------

        self.position_embedding = nn.Parameter(
            torch.randn(1, max_seq_len, d_model) * 0.02
        )

        self.input_dropout = nn.Dropout(dropout)

        # ---------------------------------------------------------
        # 6. Causal Transformer
        # ---------------------------------------------------------

        self.layers = nn.ModuleList(
            [
                CausalTransformerBlock(
                    d_model=d_model,
                    nhead=nhead,
                    ff_dim=ff_dim,
                    dropout=dropout,
                )
                for _ in range(num_layers)
            ]
        )

        self.final_norm = nn.LayerNorm(d_model)

        # ---------------------------------------------------------
        # 7. Attack classification head
        # ---------------------------------------------------------

        self.classification_head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, num_classes),
        )

        # ---------------------------------------------------------
        # 8. Next-flow prediction head
        #
        # Predict the numerical features of the NEXT flow.
        # ---------------------------------------------------------

        self.next_flow_head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, num_numeric_features),
        )

        # ---------------------------------------------------------
        # 9. Projection head for anomaly detection
        # ---------------------------------------------------------

        self.embedding_head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, d_model),
        )

        # ---------------------------------------------------------
        # Cache causal masks
        # ---------------------------------------------------------

        self._mask_cache = {}

    def _get_causal_mask(self, seq_len: int, device):
        key = (seq_len, device)

        if key not in self._mask_cache:
            mask = torch.triu(
                torch.ones(
                    seq_len,
                    seq_len,
                    device=device,
                    dtype=torch.bool,
                ),
                diagonal=1,
            )

            self._mask_cache[key] = mask

        return self._mask_cache[key]

    def forward(
        self,
        x_numeric: torch.Tensor,
        x_categorical: Dict[str, torch.Tensor],
    ) -> Dict[str, torch.Tensor]:

        """
        x_numeric:
            [B, L, F]

        x_categorical:
            {
                "dst_port": [B, L],
                "protocol": [B, L],
            }
        """

        B, L, F = x_numeric.shape

        if F != self.num_numeric_features:
            raise ValueError(
                f"Expected {self.num_numeric_features} numerical "
                f"features, got {F}"
            )

        if L > self.max_seq_len:
            raise ValueError(
                f"Sequence length {L} exceeds max_seq_len "
                f"{self.max_seq_len}"
            )

        # ---------------------------------------------------------
        # Numerical feature gating
        # ---------------------------------------------------------

        gated_numeric = self.feature_gate(x_numeric)

        numeric_features = self.numeric_encoder(
            gated_numeric
        )

        # ---------------------------------------------------------
        # Categorical embeddings
        # ---------------------------------------------------------

        dst_port = x_categorical["dst_port"].long()
        protocol = x_categorical["protocol"].long()

        port_features = self.port_embedding(dst_port)
        protocol_features = self.protocol_embedding(protocol)

        # ---------------------------------------------------------
        # Fuse all feature types
        # ---------------------------------------------------------

        h = torch.cat(
            [
                numeric_features,
                port_features,
                protocol_features,
            ],
            dim=-1,
        )

        h = self.fusion(h)

        # ---------------------------------------------------------
        # Positional encoding
        # ---------------------------------------------------------

        h = (
            h
            + self.position_embedding[:, :L]
        )

        h = self.input_dropout(h)

        # ---------------------------------------------------------
        # Causal Transformer
        # ---------------------------------------------------------

        causal_mask = self._get_causal_mask(
            L,
            x_numeric.device,
        )

        for layer in self.layers:
            h = layer(
                h,
                causal_mask,
            )

        h = self.final_norm(h)

        # ---------------------------------------------------------
        # Heads
        # ---------------------------------------------------------

        classification = self.classification_head(h)

        next_flow = self.next_flow_head(h)

        embedding = self.embedding_head(h)

        # ---------------------------------------------------------
        # Anomaly score based on embedding magnitude.
        #
        # This is useful as an initial score, but during training
        # you should preferably compute anomaly scores from
        # prediction error or a fitted normal-data distribution.
        # ---------------------------------------------------------

        anomaly_score = torch.norm(
            embedding,
            p=2,
            dim=-1,
        )

        return {
            "classification": classification,
            "next_flow": next_flow,
            "embedding": embedding,
            "anomaly_score": anomaly_score,
        }