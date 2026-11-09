import sys
import argparse
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from catboost import CatBoostClassifier, Pool
from ml.features.extract_features import extract_features
from config import ModelConfig, DataConfig
from ml.training.metrics import calculate_metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default="XSSDetector/results")
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    df = pd.read_csv(args.dataset)
    sources_for_test = df['source'].value_counts()[df['source'].value_counts() > 1000].index.tolist()
    
    params = model_cfg.get_model_params()
    params['verbose'] = False
    
    lodo_results = []
    
    for test_source in sources_for_test:
        print(f"\n===== Тестируем на {test_source} =====")
        train_df = df[df['source'] != test_source]
        test_df = df[df['source'] == test_source]
        
        X_train = pd.DataFrame([extract_features(t) for t in train_df['text']])
        X_test = pd.DataFrame([extract_features(t) for t in test_df['text']])
        y_train, y_test = train_df['label'].values, test_df['label'].values
        
        model = CatBoostClassifier(**params)
        model.fit(Pool(X_train, y_train), eval_set=Pool(X_test, y_test), use_best_model=True)
        
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        y_pred = model.predict(X_test)
        
        # Используем общую функцию
        metrics = calculate_metrics(y_test, y_pred, y_pred_proba)
        
        lodo_results.append({
            'source': test_source,
            'n_train': len(train_df),
            'n_test': len(test_df),
            'roc_auc': metrics['roc_auc'],
            'pr_auc': metrics['pr_auc'],
            'f1': metrics['f1_score'],
            'tpr@1%fpr': metrics['tpr_at_1pct_fpr'],
            'accuracy': metrics['accuracy']
        })
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}, F1: {metrics['f1_score']:.4f}")

    results_df = pd.DataFrame(lodo_results)
    print("\n=== Итоговая таблица LODO ===")
    print(results_df.to_string(index=False))
    
    output_path = Path(args.output_dir) / "lodo_catboost_results.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    results_df.to_csv(output_path, index=False)
    print(f"\nРезультаты сохранены в {output_path}")

if __name__ == "__main__":
    main()