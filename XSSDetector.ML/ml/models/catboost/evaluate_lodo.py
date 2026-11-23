import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from joblib import Parallel, delayed
from sklearn.model_selection import train_test_split

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from catboost import CatBoostClassifier, Pool
from ml.evaluation.lodo_sources import select_lodo_sources, cap_per_class
from ml.paths import RESULTS_DIR
from ml.features.extract_features import extract_features
from config import ModelConfig, DataConfig
from ml.training.metrics import calculate_metrics

def get_categorical_features(X: pd.DataFrame):
    return [col for col in X.columns if X[col].nunique() <= 8 and set(X[col].unique()).issubset({0,1})]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default=str(RESULTS_DIR))
    parser.add_argument("--sources", nargs="*", default=None, help="LODO-источники (по умолчанию общий список из ml/evaluation/lodo_sources.py)")
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    df = pd.read_csv(args.dataset)
    
    # Ограничение числа обучающих примеров (до max_samples на класс) делается ВНУТРИ фолда, только для train.
    max_samples = getattr(data_cfg, 'max_samples_per_class', 50000)

    sources_for_test = select_lodo_sources(df, args.sources)
    
    params = model_cfg.get_model_params()
    params['verbose'] = False
    params['allow_writing_files'] = False
    
    lodo_results = []
    
    for test_source in sources_for_test:
        print(f"\n===== Тестируем на {test_source} =====")
        train_df = df[df['source'] != test_source]
        train_df = train_df.iloc[cap_per_class(train_df['label'].values, max_samples)]
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
        # Выбор итерации (use_best_model) делаем на отложенной части ОБУЧАЮЩИХ источников,
        # а не на тестовом источнике: иначе модель подгоняется под целевой источник и LODO завышен.
        X_fit, X_val, y_fit, y_val = train_test_split(X_train, y_train, test_size=0.1, stratify=y_train, random_state=42)
        fit_pool = Pool(X_fit, y_fit, cat_features=cat_features, text_features=['text'])
        val_pool = Pool(X_val, y_val, cat_features=cat_features, text_features=['text'])

        model = CatBoostClassifier(**params)
        model.fit(fit_pool, eval_set=val_pool, use_best_model=True)
        
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