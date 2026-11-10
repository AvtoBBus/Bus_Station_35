import sys
import subprocess
from pathlib import Path

from ..paths import ARTIFACTS_DIR, RESULTS_DIR

def run_training(model_name: str, dataset_path: str = None, artifacts_dir: str = str(ARTIFACTS_DIR)):
    """
    Центральный оркестратор обучения.
    Вызывает соответствующий скрипт train.py для выбранной модели.
    """
    base_dir = Path(__file__).resolve().parent.parent
    model_dir = base_dir / "models" / model_name
    
    if not model_dir.exists():
        print(f"Ошибка: Директория модели '{model_name}' не найдена по пути {model_dir}")
        return False

    script_path = model_dir / "train.py"
    if not script_path.exists():
        print(f"Ошибка: Скрипт обучения для '{model_name}' не найден ({script_path})")
        return False

    cmd = [sys.executable, str(script_path)]
    if dataset_path:
        cmd.extend(["--dataset", dataset_path])
    if artifacts_dir:
        cmd.extend(["--artifacts-dir", artifacts_dir])

    print(f"\n{'='*60}")
    print(f"🚀 ЗАПУСК ОБУЧЕНИЯ: {model_name.upper()}")
    print(f"{'='*60}")
    
    # Запускаем скрипт как отдельный процесс
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        print(f"✅ Обучение {model_name} успешно завершено.")
        return True
    else:
        print(f"❌ Ошибка при обучении {model_name} (код возврата: {result.returncode}).")
        return False

def run_evaluation(model_name: str, dataset_path: str = None, output_dir: str = str(RESULTS_DIR)):
    """Запускает LODO-валидацию для модели."""
    base_dir = Path(__file__).resolve().parent.parent
    model_dir = base_dir / "models" / model_name
    script_path = model_dir / "evaluate_lodo.py"
    
    if not script_path.exists():
        print(f"Ошибка: Скрипт LODO для '{model_name}' не найден.")
        return False

    cmd = [sys.executable, str(script_path)]
    if dataset_path:
        cmd.extend(["--dataset", dataset_path])
    if output_dir:
        cmd.extend(["--output-dir", output_dir])

    print(f"\n{'='*60}")
    print(f"📊 ЗАПУСК LODO ВАЛИДАЦИИ: {model_name.upper()}")
    print(f"{'='*60}")
    
    result = subprocess.run(cmd)
    return result.returncode == 0

def run_adversarial_training():
    """Запускает цикл состязательного обучения CatBoost."""
    script_path = Path(__file__).resolve().parent / "adversarial" / "adversarial_training.py"
    if not script_path.exists():
        print(f"Ошибка: Скрипт не найден {script_path}")
        return False
        
    print(f"\n{'='*60}")
    print(f"🥊 ЗАПУСК СОСТЯЗАТЕЛЬНОГО ОБУЧЕНИЯ")
    print(f"{'='*60}")
    
    result = subprocess.run([sys.executable, str(script_path)])
    return result.returncode == 0