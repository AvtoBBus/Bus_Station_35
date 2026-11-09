from dataclasses import dataclass
from pathlib import Path

@dataclass
class ModelConfig:
    model_dir: Path = Path(__file__).resolve().parent / "weights"
    model_filename: str = "svm_rbf_xss.pkl"
    scaler_filename: str = "svm_scaler.pkl"
    n_jobs_features: int = -1   # -1 = все ядра
    
    kernel: str = "rbf"
    C: float = 1.0
    gamma: str = "scale"
    probability: bool = True
    random_state: int = 42
    class_weight: str = None # Для обычного обучения None, для LODO 'balanced'
    
    test_size: float = 0.2
    
    def __post_init__(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
    @property
    def model_path(self) -> Path:
        return self.model_dir / self.model_filename
        
    @property
    def scaler_path(self) -> Path:
        return self.model_dir / self.scaler_filename

@dataclass
class DataConfig:
    dataset_path: str = "XSSDetector/ml/datasets/processed/unified_dataset.csv"
    text_column: str = "text"
    label_column: str = "label"
    batch_size: int = 500
    max_samples_per_class: int = 50000 