import sys
import argparse
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from joblib import Parallel, delayed

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from ml.paths import ARTIFACTS_DIR
from ml.features.extract_features import extract_features
from config import ModelConfig, DataConfig

# Импортируем общие модули
from ml.training.metrics import calculate_metrics, save_metrics_json, save_standard_plots
from ml.training.artifacts import create_run_directory

def load_data(csv_file: str, cfg: DataConfig, n_jobs:int = -1, chunk_size: int = 20000):
    print(f"Загрузка данных из {csv_file}...")
    df = pd.read_csv(csv_file)
    texts = df[cfg.text_column].tolist()
    total = len(texts)
    
    print(f"Извлечение признаков для {total} строк (ядер: {n_jobs})...")
    
    all_features = []
    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        chunk = texts[start:end]
        
        chunk_features = Parallel(n_jobs=n_jobs)(
            delayed(extract_features)(text, False) for text in chunk
        )
        all_features.extend(chunk_features)
        
        pct = 100 * end // total
        print(f"  Обработано {end}/{total} ({pct}%)")
    
    X = pd.DataFrame(all_features)
    y = df[cfg.label_column].values
    print(f"✅ {X.shape[0]} примеров, {X.shape[1]} признаков")
    return X, y

def plot_feature_importance(model, feature_names, run_dir):
    """Специфичный для RF график важности признаков."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    
    plt.figure(figsize=(10, 6))
    plt.barh(range(10), importances[indices])
    plt.yticks(range(10), [feature_names[i] for i in indices])
    plt.gca().invert_yaxis()
    plt.title("Топ-10 важных признаков (Random Forest)")
    plt.tight_layout()
    plt.savefig(run_dir / "feature_importance.png", dpi=150)
    plt.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR))
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    X, y = load_data(args.dataset, data_cfg, model_cfg.n_jobs_features)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=model_cfg.test_size, random_state=model_cfg.random_state, stratify=y
    )

    print("Обучение Random Forest...")
    model = RandomForestClassifier(
        n_estimators=model_cfg.n_estimators,
        max_depth=model_cfg.max_depth,
        random_state=model_cfg.random_state,
        n_jobs=model_cfg.n_jobs
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_val)
    y_proba = model.predict_proba(X_val)[:, 1]

    # Сохранение модели
    joblib.dump(model, model_cfg.model_path)
    print(f"💾 Модель сохранена в {model_cfg.model_path}")

    # --- ИСПОЛЬЗОВАНИЕ ОБЩИХ МОДУЛЕЙ ---
    run_dir = create_run_directory(args.artifacts_dir, "random_forest")
    
    # 1. Стандартные графики и метрики
    save_standard_plots(y_val, y_pred, y_proba, run_dir, model_name="Random Forest")
    metrics = calculate_metrics(y_val, y_pred, y_proba)
    metrics.update({"model": "random_forest", "dataset": args.dataset})
    save_metrics_json(metrics, run_dir)

    # 2. Специфичный график
    plot_feature_importance(model, X.columns, run_dir)

    print(f"✅ Обучение завершено. Артефакты в {run_dir}")

if __name__ == "__main__":
    main()