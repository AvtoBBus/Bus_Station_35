import sys
import argparse
import joblib
import pandas as pd
import numpy as np
import tempfile
from pathlib import Path
from joblib import Parallel, delayed

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from catboost import CatBoostClassifier, Pool, cv
from sklearn.model_selection import train_test_split
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from ml.paths import ARTIFACTS_DIR
from ml.features.extract_features import extract_features
from config import ModelConfig, DataConfig
# Импортируем наши новые модули
from ml.training.metrics import calculate_metrics, save_metrics_json, save_standard_plots
from ml.training.artifacts import create_run_directory

def load_and_prepare_data(csv_file: str, cfg: DataConfig, n_jobs: int = -1, chunk_size: int = 20000):
    print(f"Загрузка данных из {csv_file}...")
    df = pd.read_csv(csv_file)
    texts = df[cfg.text_column].tolist()
    total = len(texts)

    print(f"Извлечение признаков для {total} строк (ядер: {n_jobs}, чанк: {chunk_size})...")

    all_features = []
    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        chunk = texts[start:end]

        # Параллельно обрабатываем чанк
        chunk_features = Parallel(n_jobs=n_jobs, backend="loky")(
            delayed(extract_features)(text) for text in chunk
        )
        all_features.extend(chunk_features)

        pct = 100 * end // total
        print(f"  Обработано {end}/{total} ({pct}%)")

    X = pd.DataFrame(all_features)
    for col in X.columns:
        if col != 'text':
            X[col] = X[col].astype('float32')
    
    y = df[cfg.label_column].values

    print(f"✅ Готово: {X.shape[0]} примеров, {X.shape[1]} признаков")
    return X, y

def get_categorical_features(X: pd.DataFrame):
    return [col for col in X.columns if X[col].nunique() <= 8 and set(X[col].unique()).issubset({0,1})]

def get_feature_weights(cat_features: list, cfg: ModelConfig):
    return [cfg.js_weight if 'js' in f else cfg.html_weight if 'html' in f else cfg.default_weight for f in cat_features]

def plot_feature_importance(model, X_cols, run_dir):
    """Специфичный для CatBoost график."""
    importance = model.get_feature_importance()
    imp_df = pd.DataFrame({'feature': X_cols, 'importance': importance}).sort_values('importance', ascending=False).head(15)
    imp_df.to_csv(run_dir / "feature_importance.csv", index=False)
    
    plt.figure(figsize=(10, 8))
    plt.barh(imp_df['feature'][::-1], imp_df['importance'][::-1])
    plt.xlabel('Важность')
    plt.title('Топ-15 важных признаков')
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

    X, y = load_and_prepare_data(args.dataset, data_cfg, model_cfg.n_jobs_features)
    cat_features = get_categorical_features(X)

    for col in cat_features:
        if col in X.columns:
            X[col] = X[col].astype(str)

    catboost_base_dir = model_cfg.model_dir.parent
    
    catboost_base_dir.mkdir(parents=True, exist_ok=True)

    params = model_cfg.get_model_params()
    params['allow_writing_files'] = False

    # Кросс-валидация
    pool = Pool(X, y, cat_features=cat_features, text_features=['text'])
    cv_data = cv(pool, params, fold_count=5, shuffle=True, partition_random_seed=model_cfg.random_seed, stratified=True)
    print(f"Среднее AUC на CV: {cv_data['test-AUC-mean'].mean():.4f}")

    # Финальное обучение
    params['feature_weights'] = get_feature_weights(cat_features, model_cfg)
    X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=model_cfg.test_size, random_state=model_cfg.random_seed, stratify=y)
    
    model = CatBoostClassifier(**params)
    train_pool = Pool(X_tr, y_tr, cat_features=cat_features, text_features=['text'])
    val_pool = Pool(X_val, y_val, cat_features=cat_features, text_features=['text'])
    
    model.fit(train_pool, eval_set=val_pool, verbose=100)
    
    y_pred = model.predict(X_val)
    y_proba = model.predict_proba(X_val)[:, 1]
    
    # Сохранение модели
    model.save_model(str(model_cfg.model_path))
    metadata = {'feature_names': list(X.columns), 'cat_features': cat_features, 'model_type': 'CatBoost', 'version': '1.0'}
    joblib.dump(metadata, model_cfg.metadata_path)
    print(f"💾 Модель сохранена в {model_cfg.model_path}")

    # --- ИСПОЛЬЗОВАНИЕ ОБЩИХ МОДУЛЕЙ ---
    run_dir = create_run_directory(args.artifacts_dir, "catboost")
    
    # 1. Стандартные графики и метрики
    save_standard_plots(y_val, y_pred, y_proba, run_dir, model_name="CatBoost")
    metrics = calculate_metrics(y_val, y_pred, y_proba)
    metrics.update({"model": "catboost", "dataset": args.dataset})
    save_metrics_json(metrics, run_dir)

    # 2. Специфичный график
    plot_feature_importance(model, X.columns, run_dir)

    print(f"✅ Обучение завершено. Артефакты в {run_dir}")

if __name__ == "__main__":
    main()