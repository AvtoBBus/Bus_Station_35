from dataclasses import dataclass
from pathlib import Path
from ml.paths import UNIFIED_DATASET

@dataclass
class ModelConfig:
    model_dir: Path = Path(__file__).resolve().parent / "weights"
    model_filename: str = "charcnn_xss.keras"
    meta_filename: str = "charcnn_config.json"
    
    # Ограничения под аппаратные ресурсы
    max_train_samples: int = 40000
    max_test_samples: int = 10000
    max_len: int = 64
    
    # Параметры архитектуры нейросети
    embedding_dim: int = 32
    dropout: float = 0.3
    
    # Настройки обучения графа
    epochs: int = 20
    batch_size: int = 64
    validation_split: float = 0.1
    seed: int = 42
    
    def __post_init__(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)

    @property
    def model_path(self) -> Path:
        return self.model_dir / self.model_filename

    @property
    def meta_path(self) -> Path:
        return self.model_dir / self.meta_filename

@dataclass
class DataConfig:
    dataset_path: str = str(UNIFIED_DATASET)
    text_column: str = "text"
    label_column: str = "label"