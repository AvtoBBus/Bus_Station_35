"""
LODO evaluation for 2.4 sequence models: char-CNN and local DistilBERT.

Comparison uses the same leave-one-dataset-out splits and metrics as the
classical TF-IDF baseline in data/scripts/normalize_datasets.py.

Local-only: no Hub downloads. Transformer folds load weights from
Transformer/best_model or a Hugging Face cache directory if it already exists.

Run from the repository root or xssdetector/:

    python evaluate_lodo_complex.py --model charcnn
    python evaluate_lodo_complex.py --model transformer --epochs 1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT.parent) not in sys.path:
    sys.path.insert(0, str(ROOT.parent))

from data.scripts.normalize_datasets import (  # noqa: E402
    _compute_lodo_metrics,
    _negative_false_positive_rate,
    _sample_by_class,
    build_lodo_splits,
)
from utils.char_sequence import encode_texts  # noqa: E402
from utils.preprocess import (  # noqa: E402
    INJECTION_CONTEXTS,
    classify_injection_context,
    context_one_hot,
    preprocess_for_sequence_model,
)

HARD_NEGATIVE_SOURCES = {'modsecurity', 'capec', 'fwaf', 'ecmlpkdd2007', 'csic2010', 'httpparams'}
DEFAULT_DATASET = ROOT / 'data' / 'processed' / 'unified_dataset.csv'
RESULTS_DIR = ROOT / 'results'


def _prepare_texts(frame: pd.DataFrame) -> list[str]:
    return [preprocess_for_sequence_model(text) for text in frame['text'].astype(str).tolist()]


def _context_matrix(texts: list[str]) -> np.ndarray:
    return np.asarray(
        [context_one_hot(classify_injection_context(text)) for text in texts],
        dtype=np.float32,
    )


def _source_row(source_name: str, train_df: pd.DataFrame, test_df: pd.DataFrame, proba: np.ndarray) -> dict:
    y_true = test_df['label'].astype(int).to_numpy()
    metrics = _compute_lodo_metrics(y_true, proba)
    negative_mask = y_true == 0
    hard_negative_mask = negative_mask & (source_name in HARD_NEGATIVE_SOURCES)
    hard_benign_mask = negative_mask & (source_name == 'hard_benign')
    contexts = pd.Series([classify_injection_context(text) for text in test_df['text'].astype(str)])
    context_counts = contexts.value_counts().to_dict()
    return {
        'source': source_name,
        'model': '',
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
        **{f'context_{name}': int(context_counts.get(name, 0)) for name in INJECTION_CONTEXTS},
    }


def _load_splits(dataset_path: Path, output_dir: Path | None) -> dict[str, dict[str, pd.DataFrame]]:
    if output_dir and output_dir.is_dir():
        existing = {}
        for train_path in sorted(output_dir.glob('train_*.csv')):
            source_name = train_path.stem[len('train_'):]
            test_path = output_dir / f'test_{source_name}.csv'
            if test_path.is_file():
                existing[source_name] = {
                    'train': pd.read_csv(train_path),
                    'test': pd.read_csv(test_path),
                }
        if existing:
            print(f'Loaded {len(existing)} existing LODO splits from {output_dir}')
            return existing
    return build_lodo_splits(str(dataset_path), str(output_dir) if output_dir else None)


def _iter_splits(dataset_path: Path, output_dir: Path | None, max_rows: int, seed: int, sources: list[str] | None):
    splits = _load_splits(dataset_path, output_dir)
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


def _find_local_distilbert_base(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(ROOT / 'Transformer' / 'best_model')
    hub = Path.home() / '.cache' / 'huggingface' / 'hub'
    if hub.is_dir():
        candidates.extend(sorted(hub.glob('models--distilbert-base-uncased/snapshots/*')))
        candidates.extend(sorted(hub.glob('models--microsoft--codebert-base/snapshots/*')))
    for path in candidates:
        if (path / 'config.json').is_file() and (
            (path / 'model.safetensors').is_file() or (path / 'pytorch_model.bin').is_file()
        ):
            return path
    raise FileNotFoundError(
        'No local transformer weights found. Place DistilBERT/CodeBERT files under '
        'xssdetector/Transformer/best_model or a Hugging Face cache directory.'
    )


def evaluate_charcnn(args) -> pd.DataFrame:
    from tensorflow.keras.callbacks import EarlyStopping

    from utils.char_cnn import build_char_cnn

    rows = []
    last_model = None
    for source_name, train_df, test_df in _iter_splits(
        Path(args.dataset), Path(args.split_dir) if args.split_dir else None,
        args.max_rows_per_class, args.seed, args.sources,
    ):
        print(f'\n=== charcnn LODO held-out source: {source_name} ===')
        train_texts = _prepare_texts(train_df)
        test_texts = _prepare_texts(test_df)
        x_train = encode_texts(train_texts, max_len=args.max_len)
        x_test = encode_texts(test_texts, max_len=args.max_len)
        c_train = _context_matrix(train_texts)
        c_test = _context_matrix(test_texts)
        y_train = train_df['label'].astype(int).to_numpy()
        model = build_char_cnn(max_len=args.max_len, context_dim=len(INJECTION_CONTEXTS))
        model.fit(
            [x_train, c_train],
            y_train,
            epochs=args.epochs,
            batch_size=args.batch_size,
            validation_split=0.1,
            callbacks=[EarlyStopping(monitor='val_loss', patience=2, restore_best_weights=True)],
            verbose=2,
        )
        proba = model.predict([x_test, c_test], batch_size=args.batch_size, verbose=0).reshape(-1)
        row = _source_row(source_name, train_df, test_df, proba)
        row['model'] = 'charcnn'
        rows.append(row)
        print(
            f"  PR-AUC={row['pr_auc']:.4f} TPR@1%FPR={row['tpr_at_1pct_fpr']:.4f} "
            f"neg_fpr={row['negative_fpr']:.4f}"
        )
        last_model = model

    if last_model is not None and args.save_model:
        out_dir = ROOT / 'CharCNN'
        out_dir.mkdir(parents=True, exist_ok=True)
        last_model.save(out_dir / 'charcnn_xss.keras')
        (out_dir / 'charcnn_config.json').write_text(
            json.dumps({'max_len': args.max_len, 'context_dim': len(INJECTION_CONTEXTS)}, indent=2),
            encoding='utf-8',
        )
        print(f'Saved last-fold char-CNN to {out_dir}')
    return pd.DataFrame(rows)


def evaluate_transformer(args) -> pd.DataFrame:
    import torch
    from datasets import Dataset
    from sklearn.metrics import roc_auc_score
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    base_dir = _find_local_distilbert_base(args.transformer_dir)
    tokenizer_dir = Path(args.tokenizer_dir) if args.tokenizer_dir else ROOT / 'Transformer' / 'tokenizer'
    if not (tokenizer_dir / 'tokenizer.json').is_file() and not (tokenizer_dir / 'vocab.txt').is_file():
        tokenizer_dir = base_dir
    print(f'Using local transformer weights: {base_dir}')
    print(f'Using local tokenizer: {tokenizer_dir}')

    tokenizer = AutoTokenizer.from_pretrained(str(tokenizer_dir), local_files_only=True)

    def tokenize_batch(batch):
        return tokenizer(batch['text'], truncation=True, padding='max_length', max_length=args.max_len)

    rows = []
    for source_name, train_df, test_df in _iter_splits(
        Path(args.dataset), Path(args.split_dir) if args.split_dir else None,
        args.max_rows_per_class, args.seed, args.sources,
    ):
        print(f'\n=== transformer LODO held-out source: {source_name} ===')
        train_texts = _prepare_texts(train_df)
        test_texts = _prepare_texts(test_df)
        train_ds = Dataset.from_dict({'text': train_texts, 'label': train_df['label'].astype(int).tolist()})
        test_ds = Dataset.from_dict({'text': test_texts, 'label': test_df['label'].astype(int).tolist()})
        train_ds = train_ds.map(tokenize_batch, batched=True, batch_size=256)
        test_ds = test_ds.map(tokenize_batch, batched=True, batch_size=256)
        train_ds.set_format('torch', columns=['input_ids', 'attention_mask', 'label'])
        test_ds.set_format('torch', columns=['input_ids', 'attention_mask', 'label'])

        model = AutoModelForSequenceClassification.from_pretrained(
            str(base_dir),
            local_files_only=True,
            num_labels=2,
            ignore_mismatched_sizes=True,
        )
        output_dir = ROOT / 'Transformer' / 'lodo_runs' / source_name
        training_args = TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=args.batch_size,
            per_device_eval_batch_size=max(args.batch_size, 8),
            learning_rate=2e-5,
            weight_decay=0.01,
            logging_strategy='steps',
            logging_steps=50,
            eval_strategy='no',
            save_strategy='no',
            report_to='none',
            fp16=torch.cuda.is_available(),
        )

        def compute_metrics(eval_pred):
            logits, labels = eval_pred
            probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()[:, 1]
            return {'auc': float(roc_auc_score(labels, probs))}

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_ds,
            compute_metrics=compute_metrics,
        )
        trainer.train()
        predictions = trainer.predict(test_ds)
        proba = torch.softmax(torch.tensor(predictions.predictions), dim=-1).numpy()[:, 1]
        row = _source_row(source_name, train_df, test_df, proba)
        row['model'] = 'transformer'
        rows.append(row)
        print(
            f"  PR-AUC={row['pr_auc']:.4f} TPR@1%FPR={row['tpr_at_1pct_fpr']:.4f} "
            f"neg_fpr={row['negative_fpr']:.4f}"
        )
        del trainer
        del model
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    return pd.DataFrame(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='LODO evaluation for 2.4 complex models')
    parser.add_argument('--model', choices=('charcnn', 'transformer'), default='charcnn')
    parser.add_argument('--dataset', default=str(DEFAULT_DATASET))
    parser.add_argument('--split-dir', default='')
    parser.add_argument('--max-rows-per-class', type=int, default=int(os.getenv('LODO_MAX_ROWS', '1500')))
    parser.add_argument('--epochs', type=int, default=int(os.getenv('LODO_EPOCHS', '4')))
    parser.add_argument('--batch-size', type=int, default=int(os.getenv('LODO_BATCH_SIZE', '64')))
    parser.add_argument('--max-len', type=int, default=256)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--sources', nargs='*', default=None)
    parser.add_argument('--transformer-dir', default='')
    parser.add_argument('--tokenizer-dir', default='')
    parser.add_argument('--save-model', action='store_true')
    parser.add_argument('--output', default='')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.model == 'charcnn':
        results = evaluate_charcnn(args)
    else:
        results = evaluate_transformer(args)

    output = Path(args.output) if args.output else RESULTS_DIR / f'lodo_{args.model}.csv'
    results.to_csv(output, index=False)
    print('\n=== LODO summary ===')
    print(results.to_string(index=False))
    if not results.empty:
        numeric = results[['pr_auc', 'roc_auc', 'tpr_at_1pct_fpr']].mean(numeric_only=True)
        print('\nMeans:')
        print(numeric.to_string())
    print(f'\nSaved {output}')


if __name__ == '__main__':
    main()
