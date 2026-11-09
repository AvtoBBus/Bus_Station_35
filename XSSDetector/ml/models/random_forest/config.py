from dataclasses import dataclass
from pathlib import Path

@dataclass
class ModelConfig:
    model_dir: Path = Path(__file__).resolve().parent / "weights"
    model_filename: str = "random_forest_xss.pkl"
    
    n_estimators: int = 200
    max_depth: int = 15
    random_state: int = 42
    n_jobs: int = -1
    n_jobs_features: int = -1   # -1 = все ядра
    
    test_size: float = 0.2
    
    def __post_init__(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
    @property
    def model_path(self) -> Path:
        return self.model_dir / self.model_filename

@dataclass
class DataConfig:
    dataset_path: str = "XSSDetector/ml/datasets/processed/unified_dataset.csv"
    text_column: str = "text"
    label_column: str = "label"
    batch_size: int = 500