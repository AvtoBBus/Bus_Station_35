import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from sklearn.ensemble import RandomForestClassifier
from ml.features.extract_features import extract_features
from config import ModelConfig, DataConfig
# Импорт единого калькулятора
from ml.training.metrics import calculate_metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default="XSSDetector/results")
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    print(f"Загрузка {args.dataset}...")
    df = pd.read_csv(args.dataset)
    
    print("Извлечение признаков...")
    features_list = []
    for i, text in enumerate(df[data_cfg.text_column]):
        if i % 1000 == 0:
            print(f"Обработано {i}/{len(df)}")
        features_list.append(extract_features(text, False))
        
    X_all = pd.DataFrame(features_list)
    y_all = df[data_cfg.label_column].values
    sources = df['source'].values
    
    source_names = ['fwaf', 'csic2010', 'kaggle', 'vulnxss', 'httpparams']
    results = {}
    
    for test_source in source_names:
        if test_source not in sources:
            print(f"Источник {test_source} не найден. Пропуск.")
            continue
            
        print(f"\n===== Тестируем на {test_source} =====")
        
        test_mask = (sources == test_source)
        X_test = X_all[test_mask].values
        y_test = y_all[test_mask]
        
        train_mask = ~test_mask
        X_train = X_all[train_mask].values
        y_train = y_all[train_mask]
        
        # В LODO используется class_weight='balanced'
        model = RandomForestClassifier(
            n_estimators=model_cfg.n_estimators,
            max_depth=model_cfg.max_depth,
            random_state=model_cfg.random_state,
            n_jobs=model_cfg.n_jobs,
            class_weight='balanced'
        )
        model.fit(X_train, y_train)
        
        y_proba = model.predict_proba(X_test)[:, 1]
        y_pred = (y_proba >= 0.5).astype(int)
        
        # Использование единого калькулятора метрик
        metrics = calculate_metrics(y_test, y_pred, y_proba)
        
        results[test_source] = {
            'roc_auc': metrics['roc_auc'], 
            'pr_auc': metrics['pr_auc'], 
            'f1': metrics['f1_score'], 
            'accuracy': metrics['accuracy'], 
            'tpr@1%fpr': metrics['tpr_at_1pct_fpr']
        }
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}, F1: {metrics['f1_score']:.4f}")

    result_df = pd.DataFrame(results).T
    print("\n=== Итоговая таблица LODO (Random Forest) ===")
    print(result_df.round(4))
    
    output_path = Path(args.output_dir) / "lodo_results_rf.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path)
    print(f"\nРезультаты сохранены в {output_path}")

if __name__ == "__main__":
    main()