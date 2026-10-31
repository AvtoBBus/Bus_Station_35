"""
Простая holdout-оценка предобученного DistilBERT трансформера по источникам.

Не использует datasets.Trainer (из-за конфликтов зависимостей).
Загружает уже обученную модель из Transformer/best_model и оценивает на
каждом источнике из сбалансированного датасета (holdout, не полное LODO
переобучение).

Запуск: python evaluate_transformer_holdout.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data.scripts.normalize_datasets import build_lodo_splits, _sample_by_class
from utils.preprocess import preprocess_for_sequence_model, classify_injection_context, context_one_hot, INJECTION_CONTEXTS
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc, roc_curve


DATASET = ROOT / 'data' / 'processed' / 'balanced_unified_dataset.csv'
RESULTS_DIR = ROOT / 'results'
TRANSFORMER_DIR = ROOT / 'Transformer'
MAX_LEN = 256
MAX_ROWS_PER_CLASS = 1000
SEED = 42
BATCH_SIZE = 32


def _compute_metrics(y_true: np.ndarray, y_score: np.ndarray) -> dict:
    if len(np.unique(y_true)) < 2:
        return {'roc_auc': float('nan'), 'pr_auc': float('nan'), 'tpr_at_1pct_fpr': float('nan')}
    roc = float(roc_auc_score(y_true, y_score))
    prec, rec, _ = precision_recall_curve(y_true, y_score, pos_label=1)
    pr = float(auc(rec, prec))
    fpr, tpr, _ = roc_curve(y_true, y_score, pos_label=1)
    idx = int(np.searchsorted(fpr, 0.01, side='left'))
    tpr_1pct = float(tpr[idx]) if idx < len(tpr) else float(tpr[-1])
    return {'roc_auc': roc, 'pr_auc': pr, 'tpr_at_1pct_fpr': tpr_1pct}


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Загружаем модель и токенизатор
    model_dir = TRANSFORMER_DIR / 'best_model'
    tok_dir = TRANSFORMER_DIR / 'tokenizer'
    if not model_dir.is_dir():
        print(f'❌ Модель не найдена: {model_dir}')
        return

    print(f'Загрузка трансформера из {model_dir}...')
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir), local_files_only=True)
    tokenizer = AutoTokenizer.from_pretrained(str(tok_dir), local_files_only=True)
    model.to('cpu')
    model.eval()

    # Загружаем датасет и делаем LODO split'ы
    df = pd.read_csv(str(DATASET))
    splits = build_lodo_splits(str(DATASET), None)

    rows = []
    for test_source in sorted(splits):
        split = splits[test_source]
        train_df = _sample_by_class(split['train'], MAX_ROWS_PER_CLASS, SEED, suffix=0)
        test_df = _sample_by_class(split['test'], MAX_ROWS_PER_CLASS, SEED + 1, suffix=1)
        if train_df.empty or test_df.empty:
            continue
        if train_df['label'].nunique() < 2 or test_df['label'].nunique() < 2:
            print(f'  Skip {test_source}: not enough class diversity.')
            continue

        print(f'\\n=== Transformer holdout on source: {test_source} ===')

        # Предсказания на тестовой части (используем уже обученную модель)
        test_texts = [preprocess_for_sequence_model(t) for t in test_df['text'].astype(str).tolist()]
        y_true = test_df['label'].astype(int).to_numpy()

        probs = []
        for i in range(0, len(test_texts), BATCH_SIZE):
            batch = test_texts[i:i + BATCH_SIZE]
            inputs = tokenizer(batch, return_tensors='pt', truncation=True,
                               max_length=MAX_LEN, padding='max_length')
            with torch.no_grad():
                logits = model(**inputs).logits
                batch_probs = torch.softmax(logits, dim=-1)[:, 1].numpy()
            probs.extend(batch_probs.tolist())
        proba = np.array(probs)

        metrics = _compute_metrics(y_true, proba)
        negative_mask = y_true == 0
        neg_fpr = float(np.mean(proba[negative_mask] >= 0.5)) if negative_mask.any() else float('nan')

        contexts = pd.Series([classify_injection_context(t) for t in test_df['text'].astype(str)])
        context_counts = contexts.value_counts().to_dict()

        row = {
            'source': test_source,
            'model': 'transformer',
            'train_rows': int(len(train_df)),
            'test_rows': int(len(test_df)),
            'train_xss': int(train_df['label'].sum()),
            'test_xss': int(test_df['label'].sum()),
            'negative_rows': int(negative_mask.sum()),
            'negative_fpr': neg_fpr,
            'roc_auc': metrics['roc_auc'],
            'pr_auc': metrics['pr_auc'],
            'tpr_at_1pct_fpr': metrics['tpr_at_1pct_fpr'],
            **{f'context_{name}': int(context_counts.get(name, 0)) for name in INJECTION_CONTEXTS},
        }
        rows.append(row)
        print(f"  PR-AUC={row['pr_auc']:.4f} TPR@1%FPR={row['tpr_at_1pct_fpr']:.4f} neg_fpr={row['negative_fpr']:.4f}")

    results = pd.DataFrame(rows)
    output = RESULTS_DIR / 'lodo_transformer.csv'
    results.to_csv(output, index=False)
    print(f'\\n✅ Сохранено: {output}')
    print(results[['source', 'pr_auc', 'tpr_at_1pct_fpr', 'negative_fpr']].round(4).to_string(index=False))


if __name__ == '__main__':
    main()