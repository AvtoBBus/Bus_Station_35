"""Единый источник путей проекта.

Все пути считаются от расположения этого файла, а не от текущей директории,
поэтому код одинаково работает локально, из любой папки и в Docker.
Любой путь можно переопределить переменной окружения.
"""
import os
from pathlib import Path

ML_ROOT = Path(__file__).resolve().parent          # .../XSSDetector/ml
PROJECT_ROOT = ML_ROOT.parent                      # .../XSSDetector  (в Docker: /xssdetector)


def _env_path(name: str, default: Path) -> Path:
    value = os.getenv(name)
    return Path(value).expanduser().resolve() if value else default


def _first_existing(candidates, default: Path) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return default


ARTIFACTS_DIR = _env_path("XSS_ARTIFACTS_DIR", ML_ROOT / "artifacts")
RESULTS_DIR = _env_path("XSS_RESULTS_DIR", PROJECT_ROOT / "results")
DATASETS_DIR = _env_path("XSS_DATASETS_DIR", ML_ROOT / "datasets")

PROCESSED_DIR = DATASETS_DIR / "processed"
UNIFIED_DATASET = PROCESSED_DIR / "unified_dataset.csv"
BALANCED_DATASET = PROCESSED_DIR / "balanced_unified_dataset.csv"

# Тестовый набор для SHAP-референса и сравнения с CRS: ищем в обоих местах,
# где он мог оказаться после переноса.
DATASETS_TEST_DIR = _env_path(
    "XSS_DATASETS_TEST_DIR",
    _first_existing(
        [ML_ROOT / "datasets_test", PROJECT_ROOT / "datasets_test", DATASETS_DIR / "test"],
        PROJECT_ROOT / "datasets_test",
    ),
)
TEST_DATASET = DATASETS_TEST_DIR / "xss_dataset.csv"
