import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from ml.features.extract_features import extract_features
from config import DataConfig
# Импорт единого калькулятора
from ml.training.metrics import calculate_metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default="XSSDetector/results")
    args = parser.parse_args()

    data_cfg = DataConfig()
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
    
    unique_sources = df['source'].unique()
    source_names = [s for s in ['fwaf', 'csic2010', 'kaggle', 'vulnxss', 'httpparams'] if s in unique_sources]
    
    results = {}
    
    for test_source in source_names:
        print(f"\n===== Тестируем на {test_source} =====")
        
        test_mask = (sources == test_source)
        X_test = X_all[test_mask].values
        y_test = y_all[test_mask]
        
        train_mask = ~test_mask
        X_train = X_all[train_mask].values
        y_train = y_all[train_mask]
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # В LODO используется class_weight='balanced'
        model = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42, n_jobs=-1)
        model.fit(X_train_scaled, y_train)
        
        y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
        y_pred = (y_pred_proba >= 0.5).astype(int)
        
        # Использование единого калькулятора метрик
        metrics = calculate_metrics(y_test, y_pred, y_pred_proba)
        
        results[test_source] = {
            'roc_auc': metrics['roc_auc'], 
            'pr_auc': metrics['pr_auc'], 
            'f1': metrics['f1_score'], 
            'accuracy': metrics['accuracy'], 
            'tpr@1%fpr': metrics['tpr_at_1pct_fpr']
        }
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}, F1: {metrics['f1_score']:.4f}")

    result_df = pd.DataFrame(results).T
    print("\n=== Итоговая таблица LODO (Logistic Regression) ===")
    print(result_df.round(4))
    
    output_path = Path(args.output_dir) / "lodo_results_lr.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path)
    print(f"\nРезультаты сохранены в {output_path}")

if __name__ == "__main__":
    main()