import sys
import argparse
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from joblib import Parallel, delayed

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from ml.paths import ARTIFACTS_DIR
from ml.features.extract_features import extract_features
from config import ModelConfig, DataConfig

# Импортируем общие модули
from ml.training.metrics import calculate_metrics, save_metrics_json, save_standard_plots
from ml.training.artifacts import create_run_directory

def load_data(csv_file: str, cfg: DataConfig, n_jobs: int = -1, chunk_size: int = 20000):
    print(f"Загрузка данных из {csv_file}...")
    df = pd.read_csv(csv_file)
    
    n_samples = getattr(cfg, 'max_samples_per_class', 50000)
    if n_samples > 0:
        print(f"Балансировка датасета: по {n_samples} строк на класс...")
        df_0 = df[df[cfg.label_column] == 0].sample(n=min(n_samples, len(df[df[cfg.label_column] == 0])), random_state=42)
        df_1 = df[df[cfg.label_column] == 1].sample(n=min(n_samples, len(df[df[cfg.label_column] == 1])), random_state=42)
        df = pd.concat([df_0, df_1]).sample(frac=1, random_state=42).reset_index(drop=True)
    
    texts = df[cfg.text_column].tolist()
    y = df[cfg.label_column].values
    total = len(texts)
    
    print(f"Извлечение признаков для {total} строк (ядер: {n_jobs}, чанк: {chunk_size})...")

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

    # Защита от случайного рассинхрона  
    assert X.shape[0] == len(y), f"Ошибка: X={X.shape[0]}, y={len(y)}"
    
    print(f"✅ {X.shape[0]} примеров, {X.shape[1]} признаков")
    return X, y

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

    print("Масштабирование признаков...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    print("Обучение SVM (RBF)...")
    model = SVC(
        kernel=model_cfg.kernel,
        C=model_cfg.C,
        gamma=model_cfg.gamma,
        probability=model_cfg.probability,
        random_state=model_cfg.random_state,
        class_weight=model_cfg.class_weight
    )
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_val_scaled)
    y_proba = model.predict_proba(X_val_scaled)[:, 1]

    # Сохранение модели и скалера
    joblib.dump(model, model_cfg.model_path)
    joblib.dump(scaler, model_cfg.scaler_path)
    print(f"💾 Модель сохранена в {model_cfg.model_path}")
    print(f"💾 Скалер сохранен в {model_cfg.scaler_path}")

    # --- ИСПОЛЬЗОВАНИЕ ОБЩИХ МОДУЛЕЙ ---
    run_dir = create_run_directory(args.artifacts_dir, "svm")
    
    # Стандартные графики и метрики
    save_standard_plots(y_val, y_pred, y_proba, run_dir, model_name="SVM RBF")
    metrics = calculate_metrics(y_val, y_pred, y_proba)
    metrics.update({"model": "svm", "dataset": args.dataset})
    save_metrics_json(metrics, run_dir)

    print(f"✅ Обучение завершено. Артефакты в {run_dir}")

if __name__ == "__main__":
    main()