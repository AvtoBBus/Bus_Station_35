from dataclasses import dataclass
from pathlib import Path
from ml.paths import UNIFIED_DATASET

@dataclass
class ModelConfig:
    model_dir: Path = Path(__file__).resolve().parent / "weights"
    model_filename: str = "catboost_xss_model.cbm"
    metadata_filename: str = "model_metadata.pkl"
    
    iterations: int = 10000
    depth: int = 6
    learning_rate: float = 0.05
    loss_function: str = "Logloss"
    eval_metric: str = "AUC"
    early_stopping_rounds: int = 50
    bootstrap_type: str = "Bernoulli"
    subsample: float = 0.8
    l2_leaf_reg: int = 3
    random_seed: int = 42
    task_type: str = "GPU"  # Для CPU поставьте "CPU"
    
    js_weight: float = 1.0
    html_weight: float = 0.7
    default_weight: float = 0.5
    
    default_threshold: float = 0.5
    test_threshold: float = 0.35
    test_size: float = 0.2
    n_jobs_features: int = -1   # -1 = все ядра
    
    def __post_init__(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
    
    @property
    def model_path(self) -> Path:
        return self.model_dir / self.model_filename
    
    @property
    def metadata_path(self) -> Path:
        return self.model_dir / self.metadata_filename
    
    def get_model_params(self) -> dict:
        return {
            'iterations': self.iterations,
            'depth': self.depth,
            'learning_rate': self.learning_rate,
            'loss_function': self.loss_function,
            'verbose': 100,
            'random_seed': self.random_seed,
            'task_type': self.task_type,
            'eval_metric': self.eval_metric,
            'early_stopping_rounds': self.early_stopping_rounds,
            'use_best_model': True,
            'bootstrap_type': self.bootstrap_type,
            'subsample': self.subsample,
            'l2_leaf_reg': self.l2_leaf_reg,
            'metric_period': 50,
        }
    
@dataclass
class DataConfig:
    dataset_path: str = str(UNIFIED_DATASET)
    text_column: str = "text"
    label_column: str = "label"
    batch_size: int = 500