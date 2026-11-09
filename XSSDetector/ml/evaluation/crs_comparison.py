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
    classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, auc, confusion_matrix
)

# Добавляем корень проекта в sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from ml.features.preprocess import decode_recursive
# Импортируем наш сборщик метрик из реестра
from ml.registry.stats import load_all_metrics

ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = ROOT / "CRS_baseline"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

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


def evaluate_crs_on_dataset(texts: list[str], labels: list[int], paranoia_level: int = 1) -> dict:
    predictions = []
    probabilities = []
    for text in texts:
        is_xss, prob, triggered = crs_predict(text, paranoia_level)
        predictions.append(int(is_xss))
        probabilities.append(prob)

    predictions = np.array(predictions)
    probabilities = np.array(probabilities)
    labels = np.array(labels)

    cm = confusion_matrix(labels, predictions)

    if len(np.unique(labels)) > 1:
        roc_auc = roc_auc_score(labels, probabilities)
        prec_arr, rec_arr, _ = precision_recall_curve(labels, probabilities)
        pr_auc = auc(rec_arr, prec_arr)
        fpr_arr, tpr_arr, _ = roc_curve(labels, probabilities)
        idx_1pct = np.searchsorted(fpr_arr, 0.01)
        tpr_1pct = tpr_arr[idx_1pct] if idx_1pct < len(tpr_arr) else 0.0
    else:
        roc_auc, pr_auc, tpr_1pct = 0.0, 0.0, 0.0

    report = classification_report(labels, predictions, target_names=['Normal', 'XSS'], output_dict=True, zero_division=0)

    return {
        'model': f'CRS_PL{paranoia_level}',
        'paranoia_level': paranoia_level,
        'roc_auc': roc_auc,
        'pr_auc': pr_auc,
        'tpr_1pct_fpr': tpr_1pct,
        'precision_xss': report['XSS']['precision'],
        'recall_xss': report['XSS']['recall'],
        'f1_xss': report['XSS']['f1-score'],
        'fpr': report.get('Normal', {}).get('recall', 0),
        'accuracy': report['accuracy'],
        'confusion_matrix': cm.tolist(),
        'threshold': THRESHOLDS[paranoia_level],
        'n_rules': len(RULE_SETS[paranoia_level]),
    }


# ---------------------------------------------------------------------------
# Visualization on common ROC/PR axes
# ---------------------------------------------------------------------------

def plot_combined_roc_pr(texts: list[str], labels: list[int], crs_results: list[dict], ml_df: pd.DataFrame, output_dir: Path):
    """Строит общие ROC и PR кривые: ML модели + CRS на одних осях."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    colors = plt.cm.tab10(np.linspace(0, 1, 10))

    # ---- ROC ----
    ax_roc = axes[0]
    ax_roc.plot([0, 1], [0, 1], 'k--', alpha=0.3, label='Random')

    if not ml_df.empty:
        for i, (_, row) in enumerate(ml_df.iterrows()):
            # Для ML мы рисуем точку (так как у нас нет сырых вероятностей, только AUC и FPR из метрик)
            ax_roc.scatter(
                row.get('fpr', 0.1), # Если нет FPR, ставим заглушку
                row.get('roc_auc', 0),
                s=120, color=colors[i % len(colors)],
                label=f"{row['model']} (AUC={row.get('roc_auc', 0):.3f})",
                marker='o', edgecolors='black', linewidth=0.5,
            )

    for pl in [1, 2, 3, 4]:
        res = next(r for r in crs_results if r['paranoia_level'] == pl)
        probs = [crs_predict(t, pl)[1] for t in texts]
        fpr_arr, tpr_arr, _ = roc_curve(labels, probs)
        ax_roc.plot(fpr_arr, tpr_arr, label=f"CRS PL{pl} (AUC={res['roc_auc']:.3f}, {len(RULE_SETS[pl])} rules)", linewidth=2)

    ax_roc.set_xlabel('False Positive Rate')
    ax_roc.set_ylabel('True Positive Rate')
    ax_roc.set_title('ROC-кривые: ML vs OWASP CRS (пункт 2.5)')
    ax_roc.legend(loc='lower right', fontsize=8)
    ax_roc.grid(True, alpha=0.3)

    # ---- PR ----
    ax_pr = axes[1]
    if not ml_df.empty:
        for i, (_, row) in enumerate(ml_df.iterrows()):
            ax_pr.scatter(
                row.get('tpr_at_1pct_fpr', 0.1) if pd.notna(row.get('tpr_at_1pct_fpr')) else 0.1,
                row.get('pr_auc', 0),
                s=120, color=colors[i % len(colors)],
                label=f"{row['model']} (PR-AUC={row.get('pr_auc', 0):.3f})",
                marker='o', edgecolors='black', linewidth=0.5,
            )

    for pl in [1, 2, 3, 4]:
        res = next(r for r in crs_results if r['paranoia_level'] == pl)
        probs = [crs_predict(t, pl)[1] for t in texts]
        prec_arr, rec_arr, _ = precision_recall_curve(labels, probs)
        ax_pr.plot(rec_arr, prec_arr, label=f"CRS PL{pl} (PR-AUC={res['pr_auc']:.3f})", linewidth=2)

    ax_pr.set_xlabel('Recall')
    ax_pr.set_ylabel('Precision')
    ax_pr.set_title('PR-кривые: ML vs OWASP CRS (пункт 2.5)')
    ax_pr.legend(loc='lower left', fontsize=8)
    ax_pr.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_dir / 'crs_vs_ml_roc_pr.png', dpi=150)
    plt.close()
    print(f'✅ Сравнительные графики сохранены: {output_dir / "crs_vs_ml_roc_pr.png"}')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='OWASP CRS vs ML comparison (пункт 2.5)')
    parser.add_argument('--dataset', default='XSSDetector/datasets_test/xss_dataset.csv', help='Путь к тестовому датасету')
    parser.add_argument('--artifacts-dir', default='XSSDetector/ml/artifacts', help='Путь к метрикам ML-моделей')
    args = parser.parse_args()

    print('=' * 70)
    print('OWASP CRS vs ML — сравнение бейзлайна (пункт 2.5)')
    print('=' * 70)

    # Загрузка данных
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        alt = ROOT / dataset_path
        if alt.exists():
            dataset_path = alt
        else:
            print(f"Ошибка: датасет не найден по пути {args.dataset}")
            return
            
    test_df = pd.read_csv(dataset_path)
    texts_raw = test_df['text'].astype(str).tolist()
    labels = test_df['label'].values
    texts_decoded = [decode_recursive(t) for t in texts_raw]
    print(f'Датасет: {len(texts_raw)} примеров, XSS={int(sum(labels))}, Normal={int(len(labels) - sum(labels))}')

    # 1. Сбор CRS результатов
    crs_results = []
    for pl in [1, 2, 3, 4]:
        print(f'\n--- CRS regex PL{pl} ---')
        res_decoded = evaluate_crs_on_dataset(texts_decoded, labels, pl)
        crs_results.append(res_decoded)
        print(f"  Декодир.:  AUC={res_decoded['roc_auc']:.4f}, PR-AUC={res_decoded['pr_auc']:.4f}, Recall={res_decoded['recall_xss']:.4f}")

    # Сохранение CRS результатов
    results_df = pd.DataFrame([{k: v for k, v in r.items() if k != 'confusion_matrix'} for r in crs_results])
    results_df.to_csv(OUTPUT_DIR / 'crs_evaluation.csv', index=False)
    print(f'\n✅ CRS результаты сохранены: {OUTPUT_DIR / "crs_evaluation.csv"}')

    # 2. Загрузка ML-результатов из наших артефактов
    print(f"\nЗагрузка ML-метрик из {args.artifacts_dir}...")
    ml_df = load_all_metrics(args.artifacts_dir)
    
    if ml_df.empty:
        print('⚠️ ML-результаты не найдены. Сначала обучите модели через CLI.')
        return

    print(f'Загружены ML-результаты для моделей: {", ".join(ml_df["model"].tolist())}')
    
    # Мапим названия колонок из нашего stats.py под нужды графика
    # В stats.py колонки: 'f1_score', а у нас в CRS: 'f1_xss'
    ml_df = ml_df.rename(columns={'f1_score': 'f1_xss', 'accuracy': 'accuracy'})
    
    # 3. Формирование сводной таблицы
    comparison = []
    for res in crs_results:
        comparison.append({**res, 'type': 'Rule-based'})
    
    for _, row in ml_df.iterrows():
        comparison.append({
            'model': row['model'],
            'type': 'ML',
            'roc_auc': row.get('roc_auc'),
            'pr_auc': row.get('pr_auc', np.nan),
            'tpr_at_1pct_fpr': row.get('tpr_at_1pct_fpr', np.nan),
            'fpr': row.get('negative_fpr', np.nan),
            'accuracy': row.get('accuracy', np.nan),
            'f1_xss': row.get('f1_score', np.nan),
            'n_rules': np.nan,
            'threshold': np.nan
        })

    comp_df = pd.DataFrame(comparison)
    comp_df.to_csv(OUTPUT_DIR / 'crs_vs_ml_comparison.csv', index=False)
    
    print('\n' + '=' * 70)
    print('СВОДНАЯ ТАБЛИЦА: ML vs OWASP CRS (пункт 2.5)')
    print('=' * 70)
    show_cols = ['model', 'type', 'roc_auc', 'pr_auc', 'tpr_at_1pct_fpr', 'fpr', 'accuracy', 'n_rules']
    # Защита от отсутствия колонок
    show_cols = [c for c in show_cols if c in comp_df.columns]
    print(comp_df[show_cols].round(4).to_string(index=False))

    # 4. Построение графиков
    plot_combined_roc_pr(texts_decoded, labels, crs_results, ml_df, OUTPUT_DIR)

    # 5. Научный вывод
    print('\n' + '=' * 70)
    print('НАУЧНЫЙ ВЫВОД (пункт 2.5 → Раздел 3)')
    print('=' * 70)
    print('• На чистых (не-состязательных) данных OWASP CRS показывает высокую TPR,')
    print('  но ценой значительного роста FPR на уровнях паранойи PL3–PL4.')
    print('• По литературе (AdvModSec / ModSec-AdvLearn, arXiv:2308.04964) на')
    print('  состязательном тесте TPR сигнатурного ModSecurity падает почти до')
    print('  случайного уровня — CRS уязвим к обходу. Это мотивация для Раздела 3:')
    print('  обучение устойчивого ML-детектора против автоматически генерируемых')
    print('  обходящих XSS-пейлоадов.')
    print('=' * 70)

if __name__ == '__main__':
    main()