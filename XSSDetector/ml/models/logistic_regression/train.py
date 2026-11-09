import sys
import argparse
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from joblib import Parallel, delayed

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

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

def plot_top_coefficients(model, feature_names, run_dir):
    """Специфичный для LR график важности признаков."""
    coef = model.coef_[0]
    top_coef_idx = np.argsort(np.abs(coef))[::-1][:10]
    
    plt.figure(figsize=(10, 6))
    plt.barh(range(10), coef[top_coef_idx])
    plt.yticks(range(10), [feature_names[i] for i in top_coef_idx])
    plt.gca().invert_yaxis()
    plt.title("Топ-10 весов признаков (Logistic Regression)")
    plt.tight_layout()
    plt.savefig(run_dir / "lr_coefficients.png", dpi=150)
    plt.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--artifacts-dir", default="XSSDetector/ml/artifacts")
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    X, y = load_data(args.dataset, data_cfg, model_cfg.n_jobs_features)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=model_cfg.test_size, random_state=model_cfg.random_state, stratify=y
    )

    print("Масштабирование признаков...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    print("Обучение Logistic Regression...")
    model = LogisticRegression(
        C=model_cfg.C, 
        max_iter=model_cfg.max_iter, 
        random_state=model_cfg.random_state, 
        n_jobs=model_cfg.n_jobs
    )
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_val_scaled)
    y_proba = model.predict_proba(X_val_scaled)[:, 1]

    # Сохранение модели и скалера
    joblib.dump(model, model_cfg.model_path)
    joblib.dump(scaler, model_cfg.scaler_path)
    print(f"💾 Модель сохранена в {model_cfg.model_path}")

    # --- ИСПОЛЬЗОВАНИЕ ОБЩИХ МОДУЛЕЙ ---
    run_dir = create_run_directory(args.artifacts_dir, "logistic_regression")
    
    # 1. Стандартные графики и метрики
    save_standard_plots(y_val, y_pred, y_proba, run_dir, model_name="Logistic Regression")
    metrics = calculate_metrics(y_val, y_pred, y_proba)
    metrics.update({"model": "logistic_regression", "dataset": args.dataset})
    save_metrics_json(metrics, run_dir)

    # 2. Специфичный график
    plot_top_coefficients(model, X.columns, run_dir)

    print(f"✅ Обучение завершено. Артефакты в {run_dir}")

if __name__ == "__main__":
    main()