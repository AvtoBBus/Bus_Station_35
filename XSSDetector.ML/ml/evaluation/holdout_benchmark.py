import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from ml.paths import RESULTS_DIR, BALANCED_DATASET
from ml.datasets.scripts.normalize_datasets import build_lodo_splits, _sample_by_class
from ml.registry.loader import ModelRegistry
from ml.serving.predictor import model_manager
from ml.training.metrics import calculate_metrics
from ml.evaluation.advanced_metrics import compute_source_metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', default=str(BALANCED_DATASET))
    parser.add_argument('--models', nargs='+', default=['catboost', 'transformer'])
    parser.add_argument('--output-dir', default=str(RESULTS_DIR))
    args = parser.parse_args()

    splits = build_lodo_splits(args.dataset, None)
    results = []

    for model_name in args.models:
        print(f"\n=== Бенчмарк предобученной модели: {model_name.upper()} ===")
        
        # Используем наш менеджер, который загрузит модель из реестра
        model = model_manager.get_model(model_name)
        if not model:
            print(f"Модель {model_name} не найдена в реестре.")
            continue

        for source_name, split in splits.items():
            test_df = _sample_by_class(split['test'], 1000, 42)
            if test_df.empty or test_df['label'].nunique() < 2: continue
            
            texts = test_df['text'].astype(str).tolist()
            y_true = test_df['label'].values
            
            # Предсказания
            try:
                if model_name in ["catboost", "random_forest", "logistic_regression", "svm"]:
                    from ml.features.extract_features import extract_features
                    with_text = (model_name == "catboost")
                    feats = pd.DataFrame([extract_features(t, not with_text) for t in texts])
                    y_proba = model.predict_proba(feats)[:, 1]
                else:
                    y_proba = model.predict_proba(texts)
                    if hasattr(y_proba, 'flatten'): y_proba = y_proba.flatten()
            except Exception as e:
                print(f"Ошибка предсказания {model_name} на {source_name}: {e}")
                continue

            y_pred = (y_proba >= 0.5).astype(int)
            
            # Базовые метрики
            metrics = calculate_metrics(y_true, y_pred, y_proba)
            
            # Продвинутые метрики (hard negative)
            adv_metrics = compute_source_metrics(source_name, y_true, y_proba, texts)
            
            row = {
                'model': model_name,
                'source': source_name,
                'roc_auc': metrics['roc_auc'],
                'pr_auc': metrics['pr_auc'],
                'tpr_at_1pct_fpr': metrics['tpr_at_1pct_fpr'],
                **adv_metrics
            }
            results.append(row)
            print(f"  {source_name}: PR-AUC={row['pr_auc']:.4f}, HardNeg FPR={row['hard_negative_fpr']:.4f}")

    if results:
        df = pd.DataFrame(results)
        output_path = Path(args.output_dir) / "holdout_benchmark_results.csv"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"\n✅ Результаты сохранены в {output_path}")
        print(df[['model', 'source', 'pr_auc', 'hard_negative_fpr']].round(4).to_string(index=False))

if __name__ == '__main__':
    main()