import pandas as pd
import os
import glob
import re
import html
from typing import Optional
from urllib.parse import unquote
from pathlib import Path

# ---------- Вспомогательные утилиты ----------
def read_txt_lines(filepath: str) -> list:
    """Читает текстовый файл, возвращает список непустых строк."""
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

# ---------- Нормализаторы по источникам ----------

def normalize_vulnxss(raw_path: str) -> pd.DataFrame:
    """
    VulnXSS: папка payloads/ содержит .txt файлы с пейлоадами.
    Все строки → label=1, source='vulnxss'.
    """
    data = []
    payload_dir = os.path.join(raw_path, 'payloads')
    if not os.path.exists(payload_dir):
        # пробуем корень
        payload_dir = raw_path
    txt_files = glob.glob(os.path.join(payload_dir, '*.txt'))
    for f in txt_files:
        lines = read_txt_lines(f)
        for line in lines:
            data.append({'text': line, 'label': 1, 'source': 'vulnxss'})
    return pd.DataFrame(data)

def normalize_payloadbox(raw_path: str) -> pd.DataFrame:
    """
    payloadbox/xss-payload-list: обычно один большой .txt или несколько.
    Все строки → label=1.
    """
    data = []
    # Ищем все .txt в папке и подпапках
    for root, _, files in os.walk(raw_path):
        for f in files:
            if f.endswith('.txt'):
                filepath = os.path.join(root, f)
                lines = read_txt_lines(filepath)
                for line in lines:
                    data.append({'text': line, 'label': 1, 'source': 'payloadbox'})
    return pd.DataFrame(data)

def normalize_kaggle(raw_path: str) -> pd.DataFrame:
    """
    Kaggle Syed Saqlain Hussain: CSV с колонками 'text' и 'label' (0/1).
    Если колонки названы иначе, адаптируем.
    """
    # Ищем первый .csv
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    # Пытаемся найти колонки text и label
    text_col = None
    label_col = None
    for col in df.columns:
        if 'text' in col.lower() or 'payload' in col.lower() or 'sentence' in col.lower():
            text_col = col
        if 'label' in col.lower() or 'class' in col.lower() or 'type' in col.lower():
            label_col = col
    if text_col is None or label_col is None:
        # fallback: предполагаем, что первая колонка - текст, вторая - метка
        text_col = df.columns[0]
        label_col = df.columns[1]
    df = df[[text_col, label_col]].rename(columns={text_col: 'text', label_col: 'label'})
    # Приводим label к int (0/1)
    df['label'] = df['label'].astype(int)
    df['source'] = 'kaggle'
    return df

def normalize_httpparams(raw_path: str) -> pd.DataFrame:
    """
    HttpParamsDataset: CSV с колонками 'value' и 'type'.
    type == 'xss' → label=1, всё остальное (включая SQLi) → label=0.
    """
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    # Ищем колонки value и type
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
    df['label'] = df['type'].apply(lambda x: 1 if x.lower() == 'xss' else 0)
    df['source'] = 'httpparams'
    return df[['text', 'label', 'source']]

def normalize_csic2010(raw_path: str) -> pd.DataFrame:
    """Normalize CSIC requests; only XSS-like anomalous requests are positive."""
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
    """
    FWAF: badqueries.txt и goodqueries.txt.
    bad → label=1, good → label=0.
    """
    data = []
    for label, fname in [(1, 'badqueries.txt'), (0, 'goodqueries.txt')]:
        filepath = os.path.join(raw_path, fname)
        if os.path.exists(filepath):
            lines = read_txt_lines(filepath)
            for line in lines:
                data.append({'text': line, 'label': label, 'source': 'fwaf'})
    return pd.DataFrame(data)

def normalize_ecmlpkdd2007(raw_path: str) -> pd.DataFrame:
    """Normalize ECML/PKDD HTTP records, treating non-XSS attacks as negatives."""
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
    """
    Трудный benign, собранный вручную.
    Ожидается CSV с колонками text и label (все label=0).
    """
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    # Ищем колонку text
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

# ---------- Главная функция сборки ----------
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
            print(f'Источник {source} не найден, пропускаем.')
            continue
        print(f'Обработка {source}...')
        try:
            frame = normalizer(source_path)
        except (OSError, ValueError, pd.errors.ParserError) as error:
            print(f'  Ошибка чтения источника: {error}')
            continue
        if frame.empty:
            print('  Нет данных.')
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
            print(f'  Добавлено {len(frame)} записей.')
    if not frames:
        raise ValueError('Нет данных ни из одного источника.')

    unified = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    unified.to_csv(output, index=False)
    counts = unified.groupby(['source', 'label']).size().unstack(fill_value=0).reindex(columns=[0, 1], fill_value=0)
    counts.columns = ['benign_or_hard_negative', 'xss']
    report_path = output.with_name('source_label_counts.csv')
    counts.to_csv(report_path)
    print(f'Сохранён объединённый датасет: {output}')
    print(f'Отчёт source × label: {report_path}')
    print(f'Всего записей: {len(unified)}; XSS={int(unified.label.sum())}; Benign/hard-negative={int((unified.label == 0).sum())}')
    print(counts)
    return unified

def balance_dataset(input_path: str, output_path: str, random_seed: int = 42) -> pd.DataFrame:
    """Keep all minority-class rows and sample an equal, source-diverse negative class."""
    df = pd.read_csv(input_path)
    required = {'text', 'label', 'source'}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f'В датасете нет обязательных колонок: {sorted(missing)}')

    class_counts = df['label'].value_counts()
    if 0 not in class_counts or 1 not in class_counts:
        raise ValueError('Для балансировки нужны оба класса.')
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
            raise ValueError('Недостаточно benign-строк для равной балансировки классов.')

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
    print(f'Сбалансированный датасет сохранён: {output}')
    print(f'Всего записей: {len(balanced)}; XSS={labels.get(1, 0)}; Benign/hard-negative={labels.get(0, 0)}')
    print('Распределение по source × label:')
    print(counts)
    return balanced


def source_capped_dataset(
    input_path: str,
    output_path: str,
    max_rows_per_source_class: int = 45000,
    random_seed: int = 42,
) -> pd.DataFrame:
    """Create a large source-capped sample for class-weighted training."""
    df = pd.read_csv(input_path)
    frames = []
    for group_index, ((source, label), candidates) in enumerate(
        df.groupby(['source', 'label'], sort=True)
    ):
        take = min(len(candidates), max_rows_per_source_class)
        frames.append(candidates.sample(n=take, random_state=random_seed + group_index))
    if not frames:
        raise ValueError('Для source-capped набора нет данных.')
    result = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=random_seed).reset_index(drop=True)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output, index=False)
    print(f'Source-capped набор сохранён: {output}')
    print(f'Всего записей: {len(result)}; классы: {result.label.value_counts().to_dict()}')
    return result


if __name__ == '__main__':
    data_dir = Path(__file__).resolve().parent.parent
    processed_dir = data_dir / 'processed'
    unified_path = processed_dir / 'unified_dataset.csv'
    balanced_path = processed_dir / 'balanced_unified_dataset.csv'
    build_unified_dataset(str(data_dir / 'raw'), str(unified_path))
    balance_dataset(str(unified_path), str(balanced_path))
    source_capped_dataset(
        str(unified_path), str(processed_dir / 'source_capped_unified_dataset.csv')
    )
