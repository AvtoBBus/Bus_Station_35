import json
from pathlib import Path
from datetime import datetime

def create_run_directory(artifacts_dir: str, model_name: str) -> Path:
    """Создает уникальную папку для текущего запуска обучения."""
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(artifacts_dir) / "runs" / f"{model_name}_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir

def save_metrics(run_dir: Path, metrics: dict):
    """Сохраняет метрики в JSON внутри папки запуска."""
    metrics_file = run_dir / "metrics.json"
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4, ensure_ascii=False)