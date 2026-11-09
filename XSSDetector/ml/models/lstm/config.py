from dataclasses import dataclass
from pathlib import Path

@dataclass
class ModelConfig:
    model_dir: Path = Path(__file__).resolve().parent / "weights"
    model_filename: str = "lstm_xss_model.h5"
    tokenizer_filename: str = "lstm_tokenizer.pkl"
    
    max_len: int = 100
    vocab_size: int = 10000
    embedding_dim: int = 64
    lstm_units: int = 64
    dropout: float = 0.2
    recurrent_dropout: float = 0.2
    dense_units: int = 32
    dense_dropout: float = 0.3
    epochs: int = 5
    batch_size: int = 256
    test_size: float = 0.2
    
    def __post_init__(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
    @property
    def model_path(self) -> Path:
        return self.model_dir / self.model_filename
        
    @property
    def tokenizer_path(self) -> Path:
        return self.model_dir / self.tokenizer_filename

@dataclass
class DataConfig:
    dataset_path: str = "XSSDetector/ml/datasets/processed/unified_dataset.csv"
    text_column: str = "text"
    label_column: str = "label"