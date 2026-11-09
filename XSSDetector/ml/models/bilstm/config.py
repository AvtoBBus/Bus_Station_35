from dataclasses import dataclass
from pathlib import Path

@dataclass
class ModelConfig:
    # Путь к весам теперь внутри папки модели
    model_dir: Path = Path(__file__).resolve().parent / "weights"
    model_filename: str = "bilstm_decoded_model.h5"
    tokenizer_filename: str = "bilstm_decoded_tokenizer.pkl"
    
    # Ограничения выборок
    max_train_samples: int = 40000
    max_test_samples: int = 10000
    max_len: int = 64
    vocab_size: int = 10000
    embedding_dim: int = 64
    
    epochs: int = 10
    batch_size: int = 64
    seed: int = 42
    
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