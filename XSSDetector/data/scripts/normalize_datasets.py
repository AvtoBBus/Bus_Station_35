import pandas as pd
import os
import glob
import re
from typing import Optional

# ---------- Вспомогательные утилиты ----------
def read_txt_lines(filepath: str) -> list:
    """Читает текстовый файл, возвращает список непустых строк."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines

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
    """
    CSIC 2010 в формате CSV (csic_final.csv).
    Читает CSV, извлекает текст запроса (URL + тело POST) и метку.
    """
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    
    df = pd.read_csv(csv_files[0])
    
    # Проверяем наличие нужных колонок
    required_cols = ['classification', 'URL', 'content']
    if not all(col in df.columns for col in required_cols):
        # Может быть, колонки названы иначе? Попробуем поискать похожие
        # Если нет, возвращаем пустой DataFrame
        print("Не найдены колонки classification, URL, content")
        return pd.DataFrame()
    
    # Очищаем от пустых значений
    df = df.dropna(subset=['URL', 'classification'])
    
    # Формируем текст запроса
    def build_text(row):
        url = row['URL']
        content = row['content'] if pd.notna(row['content']) else ''
        # Для POST-запросов content часто содержит параметры, добавляем их
        if content.strip():
            return f"{url} {content}"
        return url
    
    df['text'] = df.apply(build_text, axis=1)
    
    # Метка: Normal → 0, Anomalous → 1
    df['label'] = df['classification'].apply(lambda x: 0 if str(x).strip().lower() == 'normal' else 1)
    df['source'] = 'csic2010'
    
    # Оставляем нужные колонки
    result = df[['text', 'label', 'source']]
    
    return result

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
    """
    ECML/PKDD 2007: архив с папками, содержащими HTTP-логи.
    Упрощённо: ищем файлы с расширением .txt, содержащие метки.
    Если структура неизвестна, возвращаем пустой DataFrame.
    """
    # Предположим, что есть файлы с колонками: время, src, dst, метод, URL, код, метка
    # На практике лучше скачать готовый обработанный CSV.
    # Возвращаем пустой, чтобы не ломать сборку.
    return pd.DataFrame()

def normalize_modsecurity(raw_path: str) -> pd.DataFrame:
    """
    ModSecurity 30-day dataset: обычно CSV или JSON с полями запроса.
    Если есть колонка 'request' или 'payload' → label=1.
    """
    # Ищем CSV или JSON
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if csv_files:
        df = pd.read_csv(csv_files[0])
        # Ищем колонку с текстом запроса
        text_col = None
        for col in df.columns:
            if 'request' in col.lower() or 'payload' in col.lower() or 'query' in col.lower():
                text_col = col
                break
        if text_col is None:
            return pd.DataFrame()
        df = df[[text_col]].rename(columns={text_col: 'text'})
        df['label'] = 1
        df['source'] = 'modsecurity'
        return df
    # Если JSON
    json_files = glob.glob(os.path.join(raw_path, '*.json'))
    if json_files:
        df = pd.read_json(json_files[0])
        # аналогично ищем колонку
        text_col = None
        for col in df.columns:
            if 'request' in col.lower() or 'payload' in col.lower():
                text_col = col
                break
        if text_col is None:
            return pd.DataFrame()
        df = df[[text_col]].rename(columns={text_col: 'text'})
        df['label'] = 1
        df['source'] = 'modsecurity'
        return df
    return pd.DataFrame()

def normalize_capec(raw_path: str) -> pd.DataFrame:
    """
    Multi-label CAPEC (Riera et al.): обычно CSV с колонками text и label.
    Если есть метка 'XSS' → label=1, иначе 0.
    """
    csv_files = glob.glob(os.path.join(raw_path, '*.csv'))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    # Ищем text и колонку с меткой XSS (может быть несколько колонок)
    text_col = None
    xss_col = None
    for col in df.columns:
        if 'text' in col.lower() or 'payload' in col.lower():
            text_col = col
        if 'xss' in col.lower() or 'attack' in col.lower():
            xss_col = col
    if text_col is None or xss_col is None:
        return pd.DataFrame()
    df = df[[text_col, xss_col]].rename(columns={text_col: 'text', xss_col: 'label'})
    df['label'] = df['label'].astype(int)
    df['source'] = 'capec'
    return df

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
    """
    Обходит все папки в raw_root и применяет соответствующую функцию нормализации.
    """
    # Сопоставление имени папки с функцией
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
    all_dfs = []
    for folder_name, func in normalizers.items():
        folder_path = os.path.join(raw_root, folder_name)
        if not os.path.exists(folder_path):
            print(f"Папка {folder_path} не найдена, пропускаем.")
            continue
        print(f"Обработка {folder_name}...")
        df = func(folder_path)
        if not df.empty:
            all_dfs.append(df)
            print(f"  Добавлено {len(df)} записей.")
        else:
            print(f"  Нет данных.")
    
    if not all_dfs:
        raise ValueError("Нет данных ни из одного источника.")
    
    unified = pd.concat(all_dfs, ignore_index=True)
    # Дедупликация по тексту (приводим к нижнему регистру)
    unified['text_norm'] = unified['text'].str.lower().str.strip()
    unified = unified.drop_duplicates(subset=['text_norm']).drop(columns=['text_norm'])
    # Перемешивание
    unified = unified.sample(frac=1, random_state=42).reset_index(drop=True)
    # Сохраняем
    unified.to_csv(output_path, index=False)
    print(f"Сохранён объединённый датасет: {output_path}")
    print(f"Всего записей: {len(unified)}")
    print(f"Классы: XSS={unified[unified.label==1].shape[0]}, Benign={unified[unified.label==0].shape[0]}")
    print("Распределение по источникам:")
    print(unified['source'].value_counts())
    return unified


def balance_dataset(input_path: str, output_path: str, random_seed: int = 42) -> pd.DataFrame:
    """
    Создаёт сбалансированный датасет, беря все XSS и такое же количество случайных Benign.
    """
    df = pd.read_csv(input_path)
    
    # Разделяем на классы
    xss = df[df['label'] == 1]
    benign = df[df['label'] == 0]
    
    # Берём случайную выборку из benign размером = количеству XSS
    benign_sampled = benign.sample(n=len(xss), random_state=random_seed)
    
    # Объединяем и перемешиваем
    balanced = pd.concat([xss, benign_sampled], ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=random_seed).reset_index(drop=True)
    
    # Сохраняем
    balanced.to_csv(output_path, index=False)
    
    print(f"Сбалансированный датасет сохранён: {output_path}")
    print(f"Всего записей: {len(balanced)}")
    print(f"XSS: {balanced[balanced.label==1].shape[0]}, Benign: {balanced[balanced.label==0].shape[0]}")
    return balanced


if __name__ == "__main__":
    build_unified_dataset(
        raw_root='../raw/',
        output_path='../processed/unified_dataset.csv'
    )
    balanced_df = balance_dataset(
        input_path='../processed/unified_dataset.csv',
        output_path='../processed/balanced_unified_dataset.csv'
    )