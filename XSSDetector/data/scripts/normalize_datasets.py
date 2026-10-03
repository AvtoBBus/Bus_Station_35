import pandas as pd
import os
import glob
import re
import html
import numpy as np
from typing import Optional
from urllib.parse import unquote
from pathlib import Path


def canonicalize_text(value: str) -> str:
    """Return a stable, lower-case representation for deduplication and LODO grouping."""
    if value is None:
        return ''
    text = str(value)
    for _ in range(3):
        text = html.unescape(text)
        text = unquote(text)
    text = text.replace('\x00', '')
    text = re.sub(r'\s+', ' ', text.lower()).strip()
    return text


def deduplicate_by_normalized_group(frame: pd.DataFrame, text_column: str = 'text') -> pd.DataFrame:
    """Keep one row per normalized payload while preserving metadata from the first occurrence."""
    df = frame.copy()
    if text_column not in df.columns:
        raise ValueError(f'Column {text_column} is missing from the DataFrame.')
    df = df[df[text_column].notna() & (df[text_column].astype(str).str.strip() != '')].copy()
    df['normalized_text'] = df[text_column].map(canonicalize_text)
    df = df[df['normalized_text'] != '']
    df = df.sort_values(['source', 'label'], ascending=[True, False], kind='mergesort')
    df = df.drop_duplicates(subset=['normalized_text'], keep='first').reset_index(drop=True)
    return df.drop(columns=['normalized_text'])


def build_lodo_splits(input_path: str, output_dir: str | None = None) -> dict[str, dict[str, pd.DataFrame]]:
    """Build per-source train/test splits for leave-one-dataset-out evaluation."""
    df = pd.read_csv(input_path)
    required = {'text', 'label', 'source'}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f'Missing required columns: {sorted(missing)}')

    df = df.copy()
    df['text'] = df['text'].fillna('').astype(str)
    df['label'] = pd.to_numeric(df['label'], errors='coerce')
    df = df[df['label'].isin([0, 1])].copy()
    df['source'] = df['source'].astype(str)
    df = deduplicate_by_normalized_group(df, text_column='text')

    splits = {}
    for test_source in sorted(df['source'].unique()):
        test_df = df[df['source'] == test_source].copy()
        train_df = df[df['source'] != test_source].copy()
        splits[test_source] = {'train': train_df.reset_index(drop=True), 'test': test_df.reset_index(drop=True)}

    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for source_name, split in splits.items():
            split['train'].to_csv(out_dir / f'train_{source_name}.csv', index=False)
            split['test'].to_csv(out_dir / f'test_{source_name}.csv', index=False)

    return splits


def _compute_lodo_metrics(y_true: pd.Series | np.ndarray, y_score: pd.Series | np.ndarray) -> dict[str, float]:
    """Compute PR-AUC and TPR@1%FPR for binary detection tasks."""
    y_true = np.asarray(y_true, dtype=int)
    y_score = np.asarray(y_score, dtype=float)
    if y_true.size == 0 or len(np.unique(y_true)) < 2:
        return {'roc_auc': float('nan'), 'pr_auc': float('nan'), 'tpr_at_1pct_fpr': float('nan')}

    from sklearn.metrics import precision_recall_curve, roc_auc_score, roc_curve, auc

    roc_auc = float(roc_auc_score(y_true, y_score))
    precision, recall, _ = precision_recall_curve(y_true, y_score, pos_label=1)
    pr_auc = float(auc(recall, precision))
    fpr, tpr, _ = roc_curve(y_true, y_score, pos_label=1)
    threshold_index = np.searchsorted(fpr, 0.01, side='left')
    if threshold_index >= len(tpr):
        tpr_1pct = float(tpr[-1])
    else:
        tpr_1pct = float(tpr[threshold_index])
    return {'roc_auc': roc_auc, 'pr_auc': pr_auc, 'tpr_at_1pct_fpr': tpr_1pct}


def _sample_by_class(frame: pd.DataFrame, max_rows_per_class: int, random_seed: int, suffix: int) -> pd.DataFrame:
    """Sample rows per label without triggering pandas groupby.apply warnings."""
    groups = []
    for _, group in frame.groupby('label', sort=True):
        n_needed = min(len(group), max_rows_per_class)
        if n_needed <= 0:
            continue
        groups.append(group.sample(n=n_needed, random_state=random_seed + suffix + len(groups)))
    if not groups:
        return frame.iloc[0:0].copy()
    return pd.concat(groups, ignore_index=True)


def _negative_false_positive_rate(y_true: pd.Series | np.ndarray, y_score: pd.Series | np.ndarray, threshold: float = 0.5) -> float:
    y_true = np.asarray(y_true, dtype=int)
    y_score = np.asarray(y_score, dtype=float)
    negatives = y_true == 0
    if not np.any(negatives):
        return float('nan')
    return float(np.mean(y_score[negatives] >= threshold))


def evaluate_lodo_baseline(
    input_path: str,
    output_dir: str | None = None,
    random_seed: int = 42,
    max_features: int = 20000,
    max_rows_per_source_class: int = 5000,
) -> pd.DataFrame:
    """Train a simple TF-IDF + logistic-regression baseline on N-1 sources and evaluate on the held-out source."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    df = pd.read_csv(input_path)
    required = {'text', 'label', 'source'}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f'Missing required columns: {sorted(missing)}')

    splits = build_lodo_splits(input_path, output_dir)
    rows = []
    hard_negative_sources = {'modsecurity', 'capec', 'fwaf', 'ecmlpkdd2007', 'csic2010', 'httpparams'}
    for source_name, split in sorted(splits.items()):
        train_df = split['train'].copy()
        test_df = split['test'].copy()
        if train_df.empty or test_df.empty:
            continue

        train_df = _sample_by_class(train_df, max_rows_per_source_class, random_seed, suffix=0)
        test_df = _sample_by_class(test_df, max_rows_per_source_class, random_seed + 1, suffix=1)
        train_df = train_df.reset_index(drop=True)
        test_df = test_df.reset_index(drop=True)

        if train_df['label'].nunique() < 2 or test_df['label'].nunique() < 2:
            print(f'  Skip source {source_name}: not enough class diversity in train/test split.')
            continue

        vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            strip_accents='unicode',
            max_features=max_features,
        )
        X_train = vectorizer.fit_transform(train_df['text'].astype(str))
        X_test = vectorizer.transform(test_df['text'].astype(str))

        model = LogisticRegression(
            class_weight='balanced',
            max_iter=2000,
            solver='liblinear',
            random_state=random_seed,
        )
        model.fit(X_train, train_df['label'].astype(int))
        proba = model.predict_proba(X_test)[:, 1]
        metrics = _compute_lodo_metrics(test_df['label'].astype(int), proba)

        negative_mask = test_df['label'].astype(int).to_numpy() == 0
        hard_negative_mask = negative_mask & np.array([source_name in hard_negative_sources], dtype=bool) * np.ones(len(test_df), dtype=bool)
        hard_benign_mask = negative_mask & (source_name == 'hard_benign')

        negative_total = int(negative_mask.sum())
        hard_negative_total = int(hard_negative_mask.sum())
        hard_benign_total = int(hard_benign_mask.sum())

        row = {
            'source': source_name,
            'train_rows': int(len(train_df)),
            'test_rows': int(len(test_df)),
            'train_xss': int(train_df['label'].sum()),
            'test_xss': int(test_df['label'].sum()),
            'negative_rows': negative_total,
            'negative_false_positives': int(np.sum((proba[negative_mask] >= 0.5))),
            'negative_fpr': _negative_false_positive_rate(test_df['label'].astype(int), proba, threshold=0.5),
            'hard_negative_rows': hard_negative_total,
            'hard_negative_false_positives': int(np.sum((proba[hard_negative_mask] >= 0.5))),
            'hard_negative_fpr': (
                float(np.mean(proba[hard_negative_mask] >= 0.5)) if hard_negative_total else float('nan')
            ),
            'hard_benign_rows': hard_benign_total,
            'hard_benign_false_positives': int(np.sum((proba[hard_benign_mask] >= 0.5))),
            'hard_benign_fpr': (
                float(np.mean(proba[hard_benign_mask] >= 0.5)) if hard_benign_total else float('nan')
            ),
            'roc_auc': metrics['roc_auc'],
            'pr_auc': metrics['pr_auc'],
            'tpr_at_1pct_fpr': metrics['tpr_at_1pct_fpr'],
        }
        rows.append(row)

    results = pd.DataFrame(rows).sort_values('source').reset_index(drop=True)
    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        results.to_csv(out_dir / 'lodo_baseline_metrics.csv', index=False)
        summary = (
            df.groupby(['source', 'label']).size().unstack(fill_value=0).reindex(columns=[0, 1], fill_value=0)
        )
        summary.columns = ['benign_or_hard_negative', 'xss']
        summary.to_csv(out_dir / 'source_label_counts.csv')
        results[[
            'source', 'negative_rows', 'negative_false_positives', 'negative_fpr',
            'hard_negative_rows', 'hard_negative_false_positives', 'hard_negative_fpr',
            'hard_benign_rows', 'hard_benign_false_positives', 'hard_benign_fpr',
            'pr_auc', 'tpr_at_1pct_fpr'
        ]].to_csv(out_dir / 'source_hard_negative_report.csv', index=False)

    return results


def read_txt_lines(filepath: str) -> list:
    """Read text file and return non-empty lines."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


def _normalize_text_column(series: pd.Series) -> pd.Series:
    return series.fillna('').astype(str).str.replace(r'\s+', ' ', regex=True).str.strip()


def _has_xss_signature(text: str) -> bool:
    decoded = str(text)
    for _ in range(2):
        decoded = html.unescape(unquote(decoded))
    pattern = r'<\s*(?:script|svg|iframe|img|object|body|video|audio|details)\b|\bon[a-z]{3,}\s*=|\b(?:java|vb)script\s*:|data\s*:\s*text/html|\balert\s*\(|\bdocument\s*\.\s*(?:cookie|domain)|\beval\s*\(|\bexpression\s*\(|\bsrcdoc\s*=|\binnerhtml\b'
    return bool(re.search(pattern, decoded, re.IGNORECASE))


def _find_csv_files(raw_path: str) -> list[str]:
    return sorted(glob.glob(os.path.join(raw_path, '**', '*.csv'), recursive=True))


def normalize_vulnxss(raw_path: str) -> pd.DataFrame:
    """Normalize VulnXSS payload files."""
    data = []
    payload_dir = os.path.join(raw_path, 'payloads')
    if not os.path.exists(payload_dir):
        payload_dir = raw_path
    txt_files = glob.glob(os.path.join(payload_dir, '*.txt'))
    for f in txt_files:
        lines = read_txt_lines(f)
        for line in lines:
            data.append({'text': line, 'label': 1, 'source': 'vulnxss'})
    return pd.DataFrame(data)


def normalize_payloadbox(raw_path: str) -> pd.DataFrame:
    """Normalize PayloadBox XSS payloads."""
    data = []
    for root, _, files in os.walk(raw_path):
        for f in files:
            if f.endswith('.txt'):
                filepath = os.path.join(root, f)
                lines = read_txt_lines(filepath)
                for line in lines:
                    data.append({'text': line, 'label': 1, 'source': 'payloadbox'})
    return pd.DataFrame(data)


def normalize_kaggle(raw_path: str) -> pd.DataFrame:
    """Normalize Kaggle XSS/benign CSV dataset."""
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    text_col = None
    label_col = None
    for col in df.columns:
        if 'text' in col.lower() or 'payload' in col.lower() or 'sentence' in col.lower():
            text_col = col
        if 'label' in col.lower() or 'class' in col.lower() or 'type' in col.lower():
            label_col = col
    if text_col is None or label_col is None:
        text_col = df.columns[0]
        label_col = df.columns[1]
    df = df[[text_col, label_col]].rename(columns={text_col: 'text', label_col: 'label'})
    df['label'] = df['label'].astype(int)
    df['source'] = 'kaggle'
    return df


def normalize_httpparams(raw_path: str) -> pd.DataFrame:
    """Normalize HttpParams dataset."""
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    value_col = None
    type_col = None
    for col in df.columns:
        if 'value' in col.lower() or 'payload' in col.lower():
            value_col = col
        if 'type' in col.lower() or 'class' in col.lower():
            type_col = col
    if value_col is None or type_col is None:
        return pd.DataFrame()
    df = df[[value_col, type_col]].rename(columns={value_col: 'text', type_col: 'type'})
    df['label'] = df['type'].apply(lambda x: 1 if str(x).lower() == 'xss' else 0)
    df['source'] = 'httpparams'
    return df[['text', 'label', 'source']]


def normalize_csic2010(raw_path: str) -> pd.DataFrame:
    """Normalize CSIC requests and mark only XSS-like anomalous rows as positive."""
    frames = []
    for csv_file in _find_csv_files(raw_path):
        df = pd.read_csv(csv_file, low_memory=False)
        class_col = next((column for column in df.columns if str(column).lower() in {'classification', 'class', 'label'}), None)
        text_cols = [column for column in ('Method', 'URL', 'content') if column in df.columns]
        if class_col is None or not text_cols:
            continue
        texts = _normalize_text_column(df[text_cols].fillna('').astype(str).agg(' '.join, axis=1))
        classes = df[class_col].fillna('').astype(str).str.strip().str.lower()
        normal = classes.isin({'0', 'normal', 'valid', 'benign'})
        labels = [0 if is_normal else int(_has_xss_signature(value)) for value, is_normal in zip(texts, normal)]
        frames.append(pd.DataFrame({'text': texts, 'label': labels, 'source': 'csic2010'}))
    if not frames:
        return pd.DataFrame(columns=['text', 'label', 'source'])
    result = pd.concat(frames, ignore_index=True)
    result = result[result['text'].str.len() > 0]
    return result.drop_duplicates(subset=['text', 'label']).reset_index(drop=True)


def normalize_fwaf(raw_path: str) -> pd.DataFrame:
    """Normalize FWAF good and bad queries."""
    data = []
    for label, fname in [(1, 'badqueries.txt'), (0, 'goodqueries.txt')]:
        filepath = os.path.join(raw_path, fname)
        if os.path.exists(filepath):
            lines = read_txt_lines(filepath)
            for line in lines:
                data.append({'text': line, 'label': label, 'source': 'fwaf'})
    return pd.DataFrame(data)


def normalize_ecmlpkdd2007(raw_path: str) -> pd.DataFrame:
    """Normalize ECML/PKDD HTTP records and treat non-XSS attacks as negatives."""
    frames = []
    for csv_file in _find_csv_files(raw_path):
        df = pd.read_csv(csv_file, low_memory=False)
        class_col = next((column for column in df.columns if str(column).lower() in {'class', 'classification', 'label'}), None)
        text_cols = [column for column in ('Method', 'URI', 'GET-Query', 'POST-Data', 'URL', 'content') if column in df.columns]
        if class_col is None or not text_cols:
            continue
        texts = _normalize_text_column(df[text_cols].fillna('').astype(str).agg(' '.join, axis=1))
        classes = df[class_col].fillna('').astype(str).str.strip().str.lower()
        normal = classes.isin({'valid', 'normal', 'benign', '0'})
        labels = [0 if is_normal else int(_has_xss_signature(value)) for value, is_normal in zip(texts, normal)]
        frames.append(pd.DataFrame({'text': texts, 'label': labels, 'source': 'ecmlpkdd2007'}))
    if not frames:
        return pd.DataFrame(columns=['text', 'label', 'source'])
    result = pd.concat(frames, ignore_index=True)
    result = result[result['text'].str.len() > 0]
    return result.drop_duplicates(subset=['text', 'label']).reset_index(drop=True)


def normalize_modsecurity(raw_path: str) -> pd.DataFrame:
    """Parse ModSecurity audit transactions and distinguish CRS XSS from other attack rules."""
    rows = []
    marker = re.compile(r'^--.+-([A-Z])--\s*$')
    rule_id = re.compile(r'\[id "(\d+)"\]')
    tag_pattern = re.compile(r'\[tag "([^"]+)"\]', re.IGNORECASE)
    other_prefixes = ('930', '931', '932', '933', '934', '942', '943')
    attack_tags = ('attack-sqli', 'attack-lfi', 'attack-rce', 'attack-injection')

    for file_path in glob.glob(os.path.join(raw_path, '**', '*.log'), recursive=True):
        request_lines, message_lines, active_section = [], [], ''

        def save_transaction():
            if not request_lines or not message_lines:
                return
            metadata = '\n'.join(message_lines)
            ids = rule_id.findall(metadata)
            tags = [tag.lower() for tag in tag_pattern.findall(metadata)]
            is_xss = any(value.startswith('941') for value in ids) or any('attack-xss' in tag for tag in tags)
            is_other_attack = any(value.startswith(other_prefixes) for value in ids) or any(
                any(name in tag for name in attack_tags) for tag in tags
            )
            if is_xss or is_other_attack:
                request = _normalize_text_column(pd.Series([' '.join(request_lines)])).iloc[0]
                if request:
                    rows.append({'text': request, 'label': int(is_xss), 'source': 'modsecurity'})

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as audit_file:
            for line in audit_file:
                boundary = marker.match(line.rstrip('\r\n')) if line.startswith('--') else None
                if boundary:
                    section = boundary.group(1)
                    if section == 'Z':
                        save_transaction()
                        request_lines, message_lines, active_section = [], [], ''
                    else:
                        active_section = section
                elif active_section == 'B':
                    request_lines.append(line.strip())
                elif active_section == 'H':
                    message_lines.append(line.strip())
    return pd.DataFrame(rows, columns=['text', 'label', 'source'])


def normalize_capec(raw_path: str) -> pd.DataFrame:
    """Load CAPEC multi-label HTTP records as benign/hard negatives unless XSS is explicit."""
    frames = []
    for csv_file in _find_csv_files(raw_path):
        columns = pd.read_csv(csv_file, nrows=0, low_memory=False).columns
        text_cols = [column for column in (
            'request_http_method', 'request_http_request', 'request_http_protocol', 'request_body'
        ) if column in columns]
        xss_cols = [column for column in columns if re.search(
            r'xss|cross[- ]site scripting|capec[-_ ]?(591|592)', str(column), re.IGNORECASE
        )]
        if not text_cols:
            continue
        usecols = list(dict.fromkeys(text_cols + xss_cols))
        for chunk in pd.read_csv(csv_file, usecols=usecols, chunksize=100000, low_memory=False):
            texts = _normalize_text_column(chunk[text_cols].fillna('').astype(str).agg(' '.join, axis=1))
            if xss_cols:
                def is_positive(value):
                    try:
                        return float(value) > 0
                    except (TypeError, ValueError):
                        return str(value).strip().lower() in {'true', 'yes', 'xss'}
                labels = chunk[xss_cols].apply(lambda column: column.map(is_positive)).any(axis=1).astype(int)
            else:
                labels = pd.Series(0, index=chunk.index, dtype=int)
            frame = pd.DataFrame({'text': texts, 'label': labels, 'source': 'capec'})
            frames.append(frame[frame['text'].str.len() > 0])
    if not frames:
        return pd.DataFrame(columns=['text', 'label', 'source'])
    result = pd.concat(frames, ignore_index=True)
    return result.drop_duplicates(subset=['text', 'label']).reset_index(drop=True)


def normalize_hard_benign(raw_path: str) -> pd.DataFrame:
    """Normalize a hard-benign dataset with safe HTML-like strings."""
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    text_col = None
    for col in df.columns:
        if 'text' in col.lower() or 'sentence' in col.lower():
            text_col = col
            break
    if text_col is None:
        return pd.DataFrame()
    df = df[[text_col]].rename(columns={text_col: 'text'})
    df['label'] = 0
    df['source'] = 'hard_benign'
    return df


# ---------- Main dataset assembly ----------
def build_unified_dataset(raw_root: str, output_path: str) -> pd.DataFrame:
    """Normalize all available raw sources while retaining source provenance."""
    normalizers = {
        'vulnxss': normalize_vulnxss,
        'payloadbox': normalize_payloadbox,
        'kaggle': normalize_kaggle,
        'httpparams': normalize_httpparams,
        'csic2010': normalize_csic2010,
        'fwaf': normalize_fwaf,
        'ecmlpkdd2007': normalize_ecmlpkdd2007,
        'modsecurity': normalize_modsecurity,
        'capec': normalize_capec,
        'hard_benign': normalize_hard_benign,
    }
    frames = []
    for source, normalizer in normalizers.items():
        source_path = os.path.join(raw_root, source)
        if not os.path.isdir(source_path):
            print(f'Source {source} not found, skipping.')
            continue
        print(f'Processing {source}...')
        try:
            frame = normalizer(source_path)
        except (OSError, ValueError, pd.errors.ParserError) as error:
            print(f'  Error reading source: {error}')
            continue
        if frame.empty:
            print('  No rows found.')
            continue
        frame = frame[['text', 'label', 'source']].copy()
        frame['text'] = _normalize_text_column(frame['text'])
        frame['label'] = pd.to_numeric(frame['label'], errors='coerce')
        frame = frame.dropna(subset=['text', 'label'])
        frame = frame[frame['label'].isin([0, 1]) & (frame['text'].str.len() > 0)]
        frame['label'] = frame['label'].astype(int)
        frame = frame.sort_values('label', ascending=False).drop_duplicates(subset=['text'])
        if not frame.empty:
            frames.append(frame)
            print(f'  Added {len(frame)} rows.')
    if not frames:
        raise ValueError('No data collected from any source.')

    unified = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    unified = deduplicate_by_normalized_group(unified, text_column='text')
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    unified.to_csv(output, index=False)
    counts = unified.groupby(['source', 'label']).size().unstack(fill_value=0).reindex(columns=[0, 1], fill_value=0)
    counts.columns = ['benign_or_hard_negative', 'xss']
    report_path = output.with_name('source_label_counts.csv')
    counts.to_csv(report_path)
    print(f'Unified dataset saved to: {output}')
    print(f'Source × label report: {report_path}')
    print(f'Total rows: {len(unified)}; XSS={int(unified.label.sum())}; benign/hard-negative={int((unified.label == 0).sum())}')
    print(counts)
    return unified


def balance_dataset(input_path: str, output_path: str, random_seed: int = 42) -> pd.DataFrame:
    """Keep all minority-class rows and sample balanced negatives across sources."""
    df = pd.read_csv(input_path)
    required = {'text', 'label', 'source'}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f'Missing required columns: {sorted(missing)}')

    class_counts = df['label'].value_counts()
    if 0 not in class_counts or 1 not in class_counts:
        raise ValueError('Both classes are required for balancing.')
    target_count = int(class_counts.min())
    positives = df[df['label'] == 1]
    if len(positives) > target_count:
        positives = positives.sample(n=target_count, random_state=random_seed)

    negatives = df[df['label'] == 0]
    source_counts = negatives.groupby('source').size().sort_index()
    quotas = {source: min(int(count), target_count // len(source_counts)) for source, count in source_counts.items()}
    remaining = target_count - sum(quotas.values())
    while remaining:
        progressed = False
        for source, count in source_counts.items():
            if quotas[source] < count:
                quotas[source] += 1
                remaining -= 1
                progressed = True
                if remaining == 0:
                    break
        if not progressed:
            raise ValueError('Not enough negative rows to balance classes.')

    negative_frames = []
    for source_index, (source, quota) in enumerate(quotas.items()):
        if quota:
            candidates = negatives[negatives['source'] == source]
            negative_frames.append(candidates.sample(n=quota, random_state=random_seed + source_index + 1))
    balanced = pd.concat([positives, *negative_frames], ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=random_seed).reset_index(drop=True)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    balanced.to_csv(output, index=False)
    counts = balanced.groupby(['source', 'label']).size().unstack(fill_value=0).reindex(columns=[0, 1], fill_value=0)
    labels = balanced['label'].value_counts().to_dict()
    print(f'Balanced dataset saved to: {output}')
    print(f'Total rows: {len(balanced)}; XSS={labels.get(1, 0)}; benign/hard-negative={labels.get(0, 0)}')
    print('Source × label distribution:')
    print(counts)
    return balanced


def source_capped_dataset(
    input_path: str,
    output_path: str,
    max_rows_per_source_class: int = 45000,
    random_seed: int = 42,
) -> pd.DataFrame:
    """Create a source-capped sample for training."""
    df = pd.read_csv(input_path)
    frames = []
    for group_index, ((source, label), candidates) in enumerate(df.groupby(['source', 'label'], sort=True)):
        take = min(len(candidates), max_rows_per_source_class)
        frames.append(candidates.sample(n=take, random_state=random_seed + group_index))
    if not frames:
        raise ValueError('No rows available for source-capped dataset.')
    result = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=random_seed).reset_index(drop=True)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output, index=False)
    print(f'Source-capped dataset saved to: {output}')
    print(f'Total rows: {len(result)}; classes: {result.label.value_counts().to_dict()}')
    return result


if __name__ == '__main__':
    data_dir = Path(__file__).resolve().parent.parent
    processed_dir = data_dir / 'processed'
    unified_path = processed_dir / 'unified_dataset.csv'
    balanced_path = processed_dir / 'balanced_unified_dataset.csv'
    build_unified_dataset(str(data_dir / 'raw'), str(unified_path))
    balance_dataset(str(unified_path), str(balanced_path))
    source_capped_dataset(str(unified_path), str(processed_dir / 'source_capped_unified_dataset.csv'))



