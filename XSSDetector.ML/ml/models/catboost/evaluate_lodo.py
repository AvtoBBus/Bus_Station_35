import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from joblib import Parallel, delayed

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from catboost import CatBoostClassifier, Pool
from ml.features.extract_features import extract_features
from config import ModelConfig, DataConfig
from ml.training.metrics import calculate_metrics

def get_categorical_features(X: pd.DataFrame):
    return [col for col in X.columns if X[col].nunique() <= 8 and set(X[col].unique()).issubset({0,1})]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default="XSSDetector/results")
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    df = pd.read_csv(args.dataset)
    
    # Ограничиваем выборку для скорости LODO (как в train.py)
    max_samples = getattr(data_cfg, 'max_samples_per_class', 50000)
    if max_samples > 0:
        print(f"Балансировка датасета для LODO: по {max_samples} строк на класс...")
        df_0 = df[df[data_cfg.label_column] == 0].sample(n=min(max_samples, len(df[df[data_cfg.label_column] == 0])), random_state=42)
        df_1 = df[df[data_cfg.label_column] == 1].sample(n=min(max_samples, len(df[df[data_cfg.label_column] == 1])), random_state=42)
        df = pd.concat([df_0, df_1]).sample(frac=1, random_state=42).reset_index(drop=True)

    sources_for_test = df['source'].value_counts()[df['source'].value_counts() > 1000].index.tolist()
    
    params = model_cfg.get_model_params()
    params['verbose'] = False
    params['allow_writing_files'] = False
    
    lodo_results = []
    
    for test_source in sources_for_test:
        print(f"\n===== Тестируем на {test_source} =====")
        train_df = df[df['source'] != test_source]
        test_df = df[df['source'] == test_source]
        
        # Параллельное извлечение признаков
        print(f"  Извлечение признаков для Train ({len(train_df)} строк)...")
        X_train_feats = Parallel(n_jobs=-1, backend="threading")(delayed(extract_features)(t) for t in train_df['text'])
        X_train = pd.DataFrame(X_train_feats)
        
        print(f"  Извлечение признаков для Test ({len(test_df)} строк)...")
        X_test_feats = Parallel(n_jobs=-1, backend="threading")(delayed(extract_features)(t) for t in test_df['text'])
        X_test = pd.DataFrame(X_test_feats)
        
        y_train, y_test = train_df['label'].values, test_df['label'].values
        
        # Определяем категориальные признаки
        cat_features = get_categorical_features(X_train)
        for col in cat_features:
            if col in X_train.columns:
                X_train[col] = X_train[col].astype(str)
            if col in X_test.columns:
                X_test[col] = X_test[col].astype(str)
                
        # Создаем Pool с указанием текстовых и категориальных фичей
        train_pool = Pool(X_train, y_train, cat_features=cat_features, text_features=['text'])
        test_pool = Pool(X_test, y_test, cat_features=cat_features, text_features=['text'])
        
        model = CatBoostClassifier(**params)
        model.fit(train_pool, eval_set=test_pool, use_best_model=True)
        
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