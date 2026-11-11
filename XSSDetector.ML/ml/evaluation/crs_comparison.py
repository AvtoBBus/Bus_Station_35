"""
Режимы работы:
  1. regex      — симуляция CRS-правил на уровне строк (regex-based, fallback)
  2. modsec     — реальный ModSecurity v3 + OWASP CRS через HTTP
  3. compare    — объединённое сравнение ML-моделей vs CRS на общих ROC/PR осях

Семейство правил: 941xxx (XSS Detection) из OWASP CRS.
"""

import argparse
import os
import sys
import re
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (
    average_precision_score, confusion_matrix, precision_recall_curve,
    roc_auc_score, roc_curve,
)

# Добавляем корень проекта в sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from ml.features.preprocess import decode_recursive
from ml.registry.stats import load_all_metrics
from ml.evaluation.advanced_metrics import tpr_at_fpr
from ml.paths import ARTIFACTS_DIR, PROJECT_ROOT, TEST_DATASET

ROOT = PROJECT_ROOT
OUTPUT_DIR = ROOT / "CRS_baseline"  # создаётся в main()

# ============================================================================
# Правила OWASP CRS 941xxx (XSS Detection) — regex-аналоги (fallback mode)
# Каждое правило = regex + score. Anomaly score threshold = 5 (PL1)
# ============================================================================

CRS_XSS_RULES_PL1 = [
    (r'libinjection', 5, '941100'),
    (r'<\s*script[^>]*>', 5, '941110'),
    (r'<!--.*?-->', 3, '941120'),
    (r'<\s*img[^>]+onerror\s*=', 5, '941130'),
    (r'<\s*img[^>]+onload\s*=', 5, '941140'),
    (r'<\s*iframe[^>]*>', 5, '941150'),
    (r'<\s*object[^>]*>', 5, '941160'),
    (r'<\s*embed[^>]*>', 5, '941170'),
    (r'on[a-z]+\s*=', 4, '941180'),
    (r'<\s*style[^>]*>', 4, '941190'),
    (r'expression\s*\(', 5, '941200'),
    (r'javascript\s*:', 5, '941210'),
    (r'vbscript\s*:', 5, '941220'),
    (r'<\s*base[^>]+href', 5, '941230'),
    (r'<\s*svg[^>]*>', 3, '941240'),
    (r'<\s*body[^>]+on[a-z]+\s*=', 5, '941250'),
    (r'<!--#', 5, '941260'),
    (r'&#\d+;', 3, '941270'),
    (r'&#x[0-9a-fA-F]+;', 3, '941280'),
    (r'<\s*meta[^>]+http-equiv', 3, '941290'),
    (r'<\s*link[^>]+rel\s*=[\"]?import', 5, '941300'),
    (r'data\s*:\s*text/html', 5, '941310'),
    (r'<\s*a[^>]+href\s*=[\"]?\s*javascript', 5, '941320'),
    (r'\balert\s*\(', 3, '941330'),
    (r'\bconfirm\s*\(', 3, '941340'),
    (r'\bprompt\s*\(', 3, '941350'),
    (r'\bdocument\.\s*cookie', 5, '941360'),
    (r'\bdocument\.\s*write', 4, '941370'),
    (r'\bwindow\.\s*location', 4, '941380'),
    (r'\beval\s*\(', 5, '941390'),
    (r'fromCharCode', 5, '941400'),
]

CRS_XSS_RULES_PL2 = CRS_XSS_RULES_PL1 + [
    (r'<\s*[a-z]+\s+[^>]*\bon\w+\s*=', 3, '941180_pl2'),
    (r'\\u[0-9a-fA-F]{4}', 3, '941410'),
    (r'\\x[0-9a-fA-F]{2}', 3, '941420'),
    (r'\.innerHTML\s*=', 3, '941430'),
    (r'String\.fromCharCode', 4, '941440'),
]

CRS_XSS_RULES_PL3 = CRS_XSS_RULES_PL2 + [
    (r'<\s*[a-z]+', 2, '941900'),
    (r'\bcookie\b', 2, '941910'),
    (r'\bdocument\b', 2, '941920'),
]

CRS_XSS_RULES_PL4 = CRS_XSS_RULES_PL3 + [
    (r'=', 1, '941990'),
    (r';', 1, '941991'),
]

THRESHOLDS = {1: 5, 2: 4, 3: 3, 4: 2}
RULE_SETS = {1: CRS_XSS_RULES_PL1, 2: CRS_XSS_RULES_PL2, 3: CRS_XSS_RULES_PL3, 4: CRS_XSS_RULES_PL4}


# ---------------------------------------------------------------------------
# Regex-based CRS simulation (fallback)
# ---------------------------------------------------------------------------

def crs_score(text: str, paranoia_level: int = 1) -> tuple[int, list[str]]:
    rules = RULE_SETS.get(paranoia_level, CRS_XSS_RULES_PL1)
    total_score = 0
    triggered = []
    text_lower = text.lower()
    for pattern, score, rule_id in rules:
        if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
            total_score += score
            triggered.append(rule_id)
    return total_score, triggered


def crs_predict(text: str, paranoia_level: int = 1) -> tuple[bool, float, list[str]]:
    score, triggered = crs_score(text, paranoia_level)
    threshold = THRESHOLDS[paranoia_level]
    is_xss = score >= threshold
    max_possible = sum(s for _, s, _ in RULE_SETS[paranoia_level])
    normalized = min(score / max_possible, 1.0) if max_possible > 0 else 0.0
    return is_xss, normalized, triggered


def crs_scores(texts: list[str], paranoia_level: int):
    """Нормализованные CRS-скоры и бинарные решения для всех текстов (считаются один раз)."""
    probs, preds = [], []
    for text in texts:
        is_xss, prob, _ = crs_predict(text, paranoia_level)
        probs.append(prob)
        preds.append(int(is_xss))
    return np.array(probs, dtype=float), np.array(preds, dtype=int)


def summarize_scores(name: str, kind: str, labels, probs, preds=None, threshold: float = 0.5) -> dict:
    """Единый набор метрик для CRS и ML (одни и те же определения для обоих)."""
    labels = np.asarray(labels)
    probs = np.asarray(probs, dtype=float)
    if preds is None:
        preds = (probs >= threshold).astype(int)
    cm = confusion_matrix(labels, preds, labels=[0, 1])
    tn, fp, fn, tp = (int(x) for x in cm.ravel())
    nan = float('nan')
    two_classes = len(np.unique(labels)) > 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        'model': name,
        'type': kind,
        'n_test': int(len(labels)),
        'roc_auc': float(roc_auc_score(labels, probs)) if two_classes else nan,
        'pr_auc': float(average_precision_score(labels, probs)) if two_classes else nan,
        'tpr_at_1pct_fpr': tpr_at_fpr(labels, probs, 0.01),
        'precision_xss': precision,
        'recall_xss': recall,
        'f1_xss': f1,
        'fpr': fp / (fp + tn) if (fp + tn) else nan,   # доля нормальных, ошибочно помеченных XSS
        'tnr': tn / (fp + tn) if (fp + tn) else nan,   # specificity = 1 - FPR
        'accuracy': (tp + tn) / len(labels) if len(labels) else nan,
        'confusion_matrix': cm.tolist(),
    }


def evaluate_crs_on_dataset(texts: list[str], labels: list[int], paranoia_level: int = 1, scores=None) -> dict:
    probs, preds = scores if scores is not None else crs_scores(texts, paranoia_level)
    res = summarize_scores(f'CRS_PL{paranoia_level}', 'Rule-based', labels, probs, preds=preds)
    res.update({
        'paranoia_level': paranoia_level,
        'tpr_1pct_fpr': res['tpr_at_1pct_fpr'],  # старое имя колонки, оставлено для совместимости
        'threshold': THRESHOLDS[paranoia_level],
        'n_rules': len(RULE_SETS[paranoia_level]),
    })
    return res


# ---------------------------------------------------------------------------
# Visualization on common ROC/PR axes
# ---------------------------------------------------------------------------

def plot_combined_roc_pr(labels, series: list, output_dir: Path):
    """Общие ROC и PR кривые. series: [{'name', 'probs', 'ls'}]. Все кривые строятся по реальным скорингам."""
    labels = np.asarray(labels)
    fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(16, 7))
    ax_roc.plot([0, 1], [0, 1], 'k--', alpha=0.3, label='Random')
    for s in series:
        fpr, tpr, _ = roc_curve(labels, s['probs'])
        prec, rec, _ = precision_recall_curve(labels, s['probs'])
        ax_roc.plot(fpr, tpr, linestyle=s.get('ls', '-'), linewidth=2, label=s['name'])
        ax_pr.plot(rec, prec, linestyle=s.get('ls', '-'), linewidth=2, label=s['name'])
    ax_roc.set_xlabel('False Positive Rate'); ax_roc.set_ylabel('True Positive Rate')
    ax_roc.set_title('ROC: ML vs OWASP CRS (пункт 2.5), один тестовый набор')
    ax_pr.set_xlabel('Recall'); ax_pr.set_ylabel('Precision')
    ax_pr.set_title('PR: ML vs OWASP CRS (пункт 2.5), один тестовый набор')
    for ax, loc in ((ax_roc, 'lower right'), (ax_pr, 'lower left')):
        ax.legend(loc=loc, fontsize=8); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / 'crs_vs_ml_roc_pr.png', dpi=150)
    plt.close()
    print(f"Графики сохранены: {output_dir / 'crs_vs_ml_roc_pr.png'}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='OWASP CRS vs ML comparison (пункт 2.5)')
    parser.add_argument('--dataset', default=str(TEST_DATASET), help='Единый тестовый набор для CRS и ML (text,label)')
    parser.add_argument('--models', nargs='*', default=None, help='Какие модели реестра оценивать (по умолчанию все)')
    parser.add_argument('--ml-source', choices=['predict', 'runs'], default='predict',
                        help="predict: прогнать модели на --dataset (сопоставимо с CRS); "
                             "runs: взять метрики из artifacts/runs (на других выборках, НЕ сопоставимо)")
    parser.add_argument('--artifacts-dir', default=str(ARTIFACTS_DIR), help='Для --ml-source runs')
    parser.add_argument('--max-samples', type=int, default=0, help='Стратифицированная подвыборка (0 = весь набор)')
    args = parser.parse_args(argv)

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"Ошибка: датасет не найден: {dataset_path}")
        return 1
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    test_df = pd.read_csv(dataset_path).dropna(subset=['text', 'label'])
    
    if args.max_samples and len(test_df) > args.max_samples:
        sampled_dfs = []
        for _, group in test_df.groupby('label'):
            n_samples = max(1, int(args.max_samples * len(group) / len(test_df)))
            sampled_dfs.append(group.sample(n=min(n_samples, len(group)), random_state=42))
        test_df = pd.concat(sampled_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
        
    texts_raw = test_df['text'].astype(str).tolist()
    labels = test_df['label'].astype(int).values
    texts_decoded = [decode_recursive(t) for t in texts_raw]
    eval_set = dataset_path.name
    print(f'Набор {eval_set}: {len(labels)} примеров, XSS={int(labels.sum())}, Normal={int(len(labels) - labels.sum())}')

    # 1. CRS (на декодированном тексте: CRS применяет t:urlDecodeUni/htmlEntityDecode)
    crs_results, series = [], []
    for pl in (1, 2, 3, 4):
        scores = crs_scores(texts_decoded, pl)
        res = evaluate_crs_on_dataset(texts_decoded, labels, pl, scores=scores)
        res['eval_set'] = eval_set
        crs_results.append(res)
        series.append({'name': f"CRS PL{pl} (AUC={res['roc_auc']:.3f})", 'probs': scores[0], 'ls': '--'})
        print(f"CRS PL{pl}: TPR={res['recall_xss']:.4f} FPR={res['fpr']:.4f} "
              f"TPR@1%FPR={res['tpr_at_1pct_fpr']:.4f} ROC-AUC={res['roc_auc']:.4f}")
    pd.DataFrame([{k: v for k, v in r.items() if k != 'confusion_matrix'} for r in crs_results]) \
        .to_csv(OUTPUT_DIR / 'crs_evaluation.csv', index=False)

    # 2. ML
    ml_rows = []
    if args.ml_source == 'predict':
        from ml.evaluation.scoring import score_texts
        if args.models:
            names = args.models
        else:
            from ml.registry.loader import ModelRegistry
            names = list(ModelRegistry().manifest.get('active_models', {}).keys())
        for name in names:
            try:
                probs = score_texts(name, texts_raw)
            except Exception as exc:  # модель не загрузилась / не хватает зависимостей
                print(f'  {name}: ошибка оценки: {exc}')
                probs = None
            if probs is None or len(probs) != len(labels):
                ml_rows.append({'model': name, 'type': 'ML', 'eval_set': eval_set, 'status': 'missing'})
                continue
            row = summarize_scores(name, 'ML', labels, probs)
            row['eval_set'] = eval_set
            ml_rows.append(row)
            series.append({'name': f"{name} (AUC={row['roc_auc']:.3f})", 'probs': probs, 'ls': '-'})
    else:
        ml_df = load_all_metrics(args.artifacts_dir)
        for _, r in ml_df.iterrows():
            ml_rows.append({
                'model': r['model'], 'type': 'ML', 'eval_set': 'own holdout (NOT comparable)',
                'n_test': r.get('n_test'), 'roc_auc': r.get('roc_auc'), 'pr_auc': r.get('pr_auc'),
                'tpr_at_1pct_fpr': r.get('tpr_at_1pct_fpr'), 'fpr': r.get('fpr'),
                'accuracy': r.get('accuracy'), 'f1_xss': r.get('f1_score'),
            })

    comp = pd.DataFrame([{k: v for k, v in r.items() if k != 'confusion_matrix'} for r in crs_results + ml_rows])
    comp.to_csv(OUTPUT_DIR / 'crs_vs_ml_comparison.csv', index=False)
    show = [c for c in ['model', 'type', 'eval_set', 'n_test', 'roc_auc', 'pr_auc', 'tpr_at_1pct_fpr', 'fpr', 'accuracy'] if c in comp.columns]
    print('\n' + '=' * 70 + '\nML vs OWASP CRS (пункт 2.5)\n' + '=' * 70)
    print(comp[show].round(4).fillna('missing').to_string(index=False))

    if len(series) > 4:
        plot_combined_roc_pr(labels, series, OUTPUT_DIR)
    elif args.ml_source == 'runs':
        print('\nГрафик не строится: при --ml-source runs нет скорингов моделей на общем наборе.')

    # 3. Вывод считается из данных, а не зашит текстом
    print('\n' + '=' * 70 + '\nВЫВОД (по данным выше)\n' + '=' * 70)
    if args.ml_source == 'runs':
        print('ML-метрики взяты из artifacts/runs: это другие выборки, сравнивать их с CRS нельзя.')
    ml_ok = comp[(comp['type'] == 'ML') & comp.get('pr_auc', pd.Series(dtype=float)).notna()] if 'pr_auc' in comp else comp.iloc[0:0]
    crs_df = comp[comp['type'] == 'Rule-based']
    if not ml_ok.empty and args.ml_source == 'predict':
        bm = ml_ok.sort_values('pr_auc', ascending=False).iloc[0]
        bc = crs_df.sort_values('pr_auc', ascending=False).iloc[0]
        print(f"Лучшая ML-модель по PR-AUC: {bm['model']} (PR-AUC={bm['pr_auc']:.4f}, TPR@1%FPR={bm['tpr_at_1pct_fpr']:.4f}, FPR={bm['fpr']:.4f})")
        print(f"Лучший уровень CRS по PR-AUC: {bc['model']} (PR-AUC={bc['pr_auc']:.4f}, TPR@1%FPR={bc['tpr_at_1pct_fpr']:.4f}, FPR={bc['fpr']:.4f})")
    missing = [r['model'] for r in ml_rows if r.get('status') == 'missing']
    if missing:
        print(f"Не удалось оценить (missing): {', '.join(missing)}")
    print('Из литературы (не из этого прогона): на состязательном тесте TPR сигнатурного ModSecurity падает почти до случайного '
          'уровня (AdvModSec, arXiv:2308.04964); это мотивация Раздела 3.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
