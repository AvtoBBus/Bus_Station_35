"""
LODO evaluation for classical ML models (CatBoost, RF, LR, SVM).

Uses the same leave-one-dataset-out splits and metrics as the complex models
in evaluate_lodo_complex.py. Metrics: PR-AUC, ROC-AUC, TPR@1%FPR, plus
hard-negative / hard-benign FPR reports.

Run from xssdetector/:

    python evaluate_lodo_classical.py --model catboost
    python evaluate_lodo_classical.py --model all
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data.scripts.normalize_datasets import (  # noqa: E402
    build_lodo_splits,
    _sample_by_class,
    _compute_lodo_metrics,
    _negative_false_positive_rate,
)
from utils.preprocess import (  # noqa: E402
    decode_recursive,
    classify_injection_context,
    INJECTION_CONTEXTS,
)
from utils.extract_features import extract_features  # noqa: E402
from catboost import CatBoostClassifier, Pool
import joblib

def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """Decode + extract features for classical models."""
    rows = []
    for text in df['text'].astype(str).tolist():
        decoded = decode_recursive(text)
        feats = extract_features(decoded, withText=False)
        rows.append(feats)
    return pd.DataFrame(rows)


def _source_row(source_name: str, train_df: pd.DataFrame, test_df: pd.DataFrame,
                proba: np.ndarray, model_name: str) -> dict:
    y_true = test_df['label'].astype(int).to_numpy()
    metrics = _compute_lodo_metrics(y_true, proba)
    negative_mask = y_true == 0
    test_sources = test_df['source'].astype(str)
    hard_negative_mask = negative_mask & test_sources.isin(HARD_NEGATIVE_SOURCES)
    hard_benign_mask = negative_mask & (test_sources == 'hard_benign')

    contexts = pd.Series([classify_injection_context(t) for t in test_df['text'].astype(str)])
    context_counts = contexts.value_counts().to_dict()

    return {
        'source': source_name,
        'model': model_name,
        'train_rows': int(len(train_df)),
        'test_rows': int(len(test_df)),
        'train_xss': int(train_df['label'].sum()),
        'test_xss': int(test_df['label'].sum()),
        'negative_rows': int(negative_mask.sum()),
        'negative_fpr': _negative_false_positive_rate(y_true, proba, threshold=0.5),
        'hard_negative_rows': int(hard_negative_mask.sum()),
        'hard_negative_fpr': (
            float(np.mean(proba[hard_negative_mask] >= 0.5)) if hard_negative_mask.any() else float('nan')
        ),
        'hard_benign_rows': int(hard_benign_mask.sum()),
        'hard_benign_fpr': (
            float(np.mean(proba[hard_benign_mask] >= 0.5)) if hard_benign_mask.any() else float('nan')
        ),
        'roc_auc': metrics['roc_auc'],
        'pr_auc': metrics['pr_auc'],
        'tpr_at_1pct_fpr': metrics['tpr_at_1pct_fpr'],
    }
HARD_NEGATIVE_SOURCES = {'modsecurity', 'capec', 'fwaf', 'ecmlpkdd2007', 'csic2010', 'httpparams'}
DEFAULT_DATASET = ROOT / 'data' / 'processed' / 'balanced_unified_dataset.csv'
RESULTS_DIR = ROOT / 'results'
MODEL_DIRS = {
    'catboost': ROOT / 'CatBoost',
    'rf': ROOT / 'RandomForest',
    'lr': ROOT / 'LogisticRegression',
    'svm': ROOT / 'SVM',
}
def _iter_splits(dataset_path: Path, max_rows: int, seed: int, sources: list[str] | None):
    splits = build_lodo_splits(str(dataset_path), None)
    selected = sources or sorted(splits)
    for index, source_name in enumerate(selected):
        split = splits.get(source_name)
        if not split:
            continue
        train_df = _sample_by_class(split['train'], max_rows, seed, suffix=index)
        test_df = _sample_by_class(split['test'], max_rows, seed + 1, suffix=index + 17)
        if train_df.empty or test_df.empty:
            continue
        if train_df['label'].nunique() < 2 or test_df['label'].nunique() < 2:
            print(f'  Skip {source_name}: need both classes in train and test.')
            continue
        yield source_name, train_df.reset_index(drop=True), test_df.reset_index(drop=True)


def evaluate_catboost(args) -> pd.DataFrame:
    rows = []
    for source_name, train_df, test_df in _iter_splits(
        Path(args.dataset), args.max_rows_per_class, args.seed, args.sources,
    ):
        print(f'\\n=== catboost LODO held-out source: {source_name} ===')

        X_train_df = _prepare_features(train_df)
        X_test_df = _prepare_features(test_df)
        y_train = train_df['label'].astype(int).to_numpy()

        model_path = MODEL_DIRS['catboost'] / 'catboost_xss_model.cbm'
        metadata_path = MODEL_DIRS['catboost'] / 'model_metadata.pkl'
        if not model_path.is_file():
            raise FileNotFoundError(f'CatBoost model not found: {model_path}')

        model = CatBoostClassifier()
        model.load_model(str(model_path))
        metadata = joblib.load(str(metadata_path))
        expected_features = metadata['feature_names']
        cat_features = metadata.get('cat_features', [])

        # CatBoost expects 'text' as text_feature, but we fill missing with 0 (int) which fails.
        # We only need engineered features; drop 'text' from the feature matrix.
        model_features = [f for f in expected_features if f != 'text']
        cat_features = [f for f in cat_features if f != 'text']

        # Ensure exact column order matching the trained model
        for feature in model_features:
            if feature not in X_train_df.columns:
                X_train_df[feature] = 0
            if feature not in X_test_df.columns:
                X_test_df[feature] = 0
        X_train_df = X_train_df.reindex(columns=model_features, fill_value=0)
        X_test_df = X_test_df.reindex(columns=model_features, fill_value=0)

        for col in cat_features:
            if col in X_train_df.columns:
                X_train_df[col] = X_train_df[col].astype('category')
            if col in X_test_df.columns:
                X_test_df[col] = X_test_df[col].astype('category')

        # Rebuild DataFrame in exact model order including 'text' as first column.
        # CatBoost remembers original positions from training; we must match them.
        full_features = list(expected_features)  # includes 'text' at position 0
        X_train_full = pd.DataFrame(index=X_train_df.index, columns=full_features)
        X_test_full = pd.DataFrame(index=X_test_df.index, columns=full_features)
        X_train_full['text'] = ''
        X_test_full['text'] = ''
        for col in model_features:
            if col in cat_features:
                X_train_full[col] = X_train_df[col].astype(str)
                X_test_full[col] = X_test_df[col].astype(str)
            else:
                X_train_full[col] = X_train_df[col].astype(float)
                X_test_full[col] = X_test_df[col].astype(float)

        train_pool = Pool(X_train_full, feature_names=list(X_train_full.columns),
                          cat_features=cat_features, text_features=['text'])
        test_pool = Pool(X_test_full, feature_names=list(X_test_full.columns),
                         cat_features=cat_features, text_features=['text'])

        proba = model.predict_proba(test_pool)[:, 1]
        row = _source_row(source_name, train_df, test_df, proba, 'catboost')
        rows.append(row)
        print(f"  PR-AUC={row['pr_auc']:.4f} TPR@1%FPR={row['tpr_at_1pct_fpr']:.4f} neg_fpr={row['negative_fpr']:.4f}")

def evaluate_sklearn_model(model_name: str, args) -> pd.DataFrame:
    """Generic LODO for RF / LR / SVM using joblib models + scaler."""
    rows = []
    model_dir = MODEL_DIRS[model_name]
    model_path = model_dir / f'{model_name}_xss_model.pkl'
    scaler_path = model_dir / f'{model_name}_scaler.pkl'

    if not model_path.is_file():
        # Search: any .pkl that is not a scaler
        for fname in sorted(model_dir.iterdir()):
            if fname.suffix == '.pkl' and 'scaler' not in fname.name.lower():
                model_path = fname
                break
    if not model_path.is_file():
        raise FileNotFoundError(f'{model_name} model not found in {model_dir}')

    model = joblib.load(str(model_path))
    scaler = joblib.load(str(scaler_path)) if scaler_path.is_file() else None

    for source_name, train_df, test_df in _iter_splits(
        Path(args.dataset), args.max_rows_per_class, args.seed, args.sources,
    ):
        print(f'\n=== {model_name} LODO held-out source: {source_name} ===')

        X_train_df = _prepare_features(train_df)
        X_test_df = _prepare_features(test_df)

        common_cols = list(X_train_df.columns)
        X_train = X_train_df[common_cols].to_numpy()
        X_test = X_test_df[common_cols].to_numpy()

        if scaler is not None:
            X_train = scaler.transform(X_train)
            X_test = scaler.transform(X_test)

        proba = model.predict_proba(X_test)[:, 1]
        row = _source_row(source_name, train_df, test_df, proba, model_name)
        rows.append(row)
        print(f"  PR-AUC={row['pr_auc']:.4f} TPR@1%FPR={row['tpr_at_1pct_fpr']:.4f} neg_fpr={row['negative_fpr']:.4f}")

    return pd.DataFrame(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='LODO evaluation for classical models')
    parser.add_argument('--model', choices=('catboost', 'rf', 'lr', 'svm', 'all'), default='all')
    parser.add_argument('--dataset', default=str(DEFAULT_DATASET))
    parser.add_argument('--max-rows-per-class', type=int, default=int(os.getenv('LODO_MAX_ROWS', '3000')))
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--sources', nargs='*', default=None)
    parser.add_argument('--output', default='')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    models_to_run = ['catboost', 'rf', 'lr', 'svm'] if args.model == 'all' else [args.model]
    all_rows = []

    for m in models_to_run:
        if m == 'catboost':
            df = evaluate_catboost(args)
        else:
            df = evaluate_sklearn_model(m, args)
        all_rows.append(df)

    results = pd.concat(all_rows, ignore_index=True) if all_rows else pd.DataFrame()
    output = Path(args.output) if args.output else RESULTS_DIR / 'lodo_classical.csv'
    results.to_csv(output, index=False)

    print('\n=== LODO summary (classical models) ===')
    if not results.empty:
        summary = results.groupby('model')[['pr_auc', 'roc_auc', 'tpr_at_1pct_fpr', 'negative_fpr']].mean()
        print(summary.round(4).to_string())
        print('\nPer-source:')
        print(results[['source', 'model', 'pr_auc', 'tpr_at_1pct_fpr', 'negative_fpr',
                       'hard_negative_fpr', 'hard_benign_fpr']].round(4).to_string(index=False))
    print(f'\nSaved {output}')


if __name__ == '__main__':
    main()