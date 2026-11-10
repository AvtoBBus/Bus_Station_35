from dataclasses import dataclass
from pathlib import Path
from ml.paths import UNIFIED_DATASET

@dataclass
class ModelConfig:
    base_dir: Path = Path(__file__).resolve().parent / "weights"
    model_dir: Path = base_dir / "best_model"
    tokenizer_dir: Path = base_dir / "tokenizer"
    
    # Параметры обучения
    max_train_samples: int = 40000
    max_test_samples: int = 10000
    max_len: int = 64
    
    num_epochs: float = 3.0
    train_batch_size: int = 16
    eval_batch_size: int = 64
    gradient_accumulation_steps: int = 2
    seed: int = 42
    
    def __post_init__(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.tokenizer_dir.mkdir(parents=True, exist_ok=True)

@dataclass
class DataConfig:
    dataset_path: str = str(UNIFIED_DATASET)
    text_column: str = "text"
    label_column: str = "label"