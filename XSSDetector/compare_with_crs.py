"""
Сравнение ML-детекторов с OWASP Core Rule Set (CRS).

Развертывает тестовые правила CRS и измеряет TPR/FPR
на тех же данных, что и ML-модели. Результаты наносятся
на общие ROC/PR-оси.

Реализация: симуляция CRS-правил на уровне строк (regex-based),
т.к. реальный ModSecurity требует HTTP-сервера.

Семейство правил: 941xxx (XSS Detection) из OWASP CRS.
"""

import re
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, auc, confusion_matrix
)
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from utils.preprocess import decode_recursive

OUTPUT_DIR = "./CRS_baseline"
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================================
# Правила OWASP CRS 941xxx (XSS Detection) — упрощённые regex-аналоги
# Каждое правило = regex + score. Anomaly score threshold = 5 (PL1)
# ============================================================================

CRS_XSS_RULES_PL1 = [
    # 941100 - XSS Attack Detected via libinjection
    (r'libinjection', 5, '941100'),
    # 941110 - XSS Attack Detected via libinjection (HTML context)
    (r'<\s*script[^>]*>', 5, '941110'),
    # 941120 - XSS Attack Detected (IE XSS Filter Evasion)
    (r'<!--.*?-->', 3, '941120'),
    # 941130 - XSS Attack Detected (IE XSS Filter Evasion)
    (r'<\s*img[^>]+onerror\s*=', 5, '941130'),
    # 941140 - XSS Attack Detected (IE XSS Filter Evasion)
    (r'<\s*img[^>]+onload\s*=', 5, '941140'),
    # 941150 - XSS Attack Detected (IE XSS Filter Evasion)
    (r'<\s*iframe[^>]*>', 5, '941150'),
    # 941160 - NoScript XSS InjectionChecker: HTML Injection
    (r'<\s*object[^>]*>', 5, '941160'),
    # 941170 - NoScript XSS InjectionChecker: Attribute Injection
    (r'<\s*embed[^>]*>', 5, '941170'),
    # 941180 - Node-Validator Blacklist Regex Match 1/5
    (r'on[a-z]+\s*=', 4, '941180'),
    # 941190 - XSS using style attribute
    (r'<\s*style[^>]*>', 4, '941190'),
    # 941200 - XSS using style attribute with expression
    (r'expression\s*\(', 5, '941200'),
    # 941210 - Possible XSS Attack Using Javascript Directive
    (r'javascript\s*:', 5, '941210'),
    # 941220 - IE XSS Filter Evasion - CSS
    (r'vbscript\s*:', 5, '941220'),
    # 941230 - IE XSS Filter Evasion - CSS
    (r'<\s*base[^>]+href', 5, '941230'),
    # 941240 - XSS Attack Detected (IE XSS Filter Evasion)
    (r'<\s*svg[^>]*>', 3, '941240'),
    # 941250 - XSS Attack Detected (IE XSS Filter Evasion)
    (r'<\s*body[^>]+on[a-z]+\s*=', 5, '941250'),
    # 941260 - XSS Attack Detected (IE XSS Filter Evasion)
    (r'<!--#', 5, '941260'),
    # 941270 - IE XSS Filter Evasion - HTML Entity
    (r'&#\d+;', 3, '941270'),
    # 941280 - IE XSS Filter Evasion - HTML Entity
    (r'&#x[0-9a-fA-F]+;', 3, '941280'),
    # 941290 - IE XSS Filter Evasion - HTML Entity
    (r'<\s*meta[^>]+http-equiv', 3, '941290'),
    # 941300 - Possible XSS Attack Detected - HTML Encoding
    (r'<\s*link[^>]+rel\s*=\s*["\']?import', 5, '941300'),
    # 941310 - IE XSS Filter Evasion
    (r'data\s*:\s*text/html', 5, '941310'),
    # 941320 - IE XSS Filter Evasion
    (r'<\s*a[^>]+href\s*=\s*["\']?\s*javascript', 5, '941320'),
    # 941330 - IE XSS Filter Evasion
    (r'\balert\s*\(', 3, '941330'),
    # 941340 - IE XSS Filter Evasion
    (r'\bconfirm\s*\(', 3, '941340'),
    # 941350 - IE XSS Filter Evasion
    (r'\bprompt\s*\(', 3, '941350'),
    # 941360 - IE XSS Filter Evasion
    (r'\bdocument\.\s*cookie', 5, '941360'),
    # 941370 - IE XSS Filter Evasion
    (r'\bdocument\.\s*write', 4, '941370'),
    # 941380 - IE XSS Filter Evasion
    (r'\bwindow\.\s*location', 4, '941380'),
    # 941390 - IE XSS Filter Evasion
    (r'\beval\s*\(', 5, '941390'),
    # 941400 - IE XSS Filter Evasion
    (r'fromCharCode', 5, '941400'),
]

CRS_XSS_RULES_PL2 = CRS_XSS_RULES_PL1 + [
    # Дополнительные правила для PL2
    (r'<\s*[a-z]+\s+[^>]*\bon\w+\s*=', 3, '941180_pl2'),
    (r'\\u[0-9a-fA-F]{4}', 3, '941410'),
    (r'\\x[0-9a-fA-F]{2}', 3, '941420'),
    (r'\.innerHTML\s*=', 3, '941430'),
    (r'String\.fromCharCode', 4, '941440'),
]

CRS_XSS_RULES_PL3 = CRS_XSS_RULES_PL2 + [
    # Ещё более агрессивные правила
    (r'<\s*[a-z]+', 2, '941900'),
    (r'\bcookie\b', 2, '941910'),
    (r'\bdocument\b', 2, '941920'),
]

CRS_XSS_RULES_PL4 = CRS_XSS_RULES_PL3 + [
    # Максимальная паранойя
    (r'=', 1, '941990'),
    (r';', 1, '941991'),
]


# Пороги anomaly score для каждого PL
THRESHOLDS = {
    1: 5,   # PL1: стандартный
    2: 4,   # PL2: чуть ниже
    3: 3,   # PL3: ещё ниже
    4: 2,   # PL4: минимальный порог
}

RULE_SETS = {
    1: CRS_XSS_RULES_PL1,
    2: CRS_XSS_RULES_PL2,
    3: CRS_XSS_RULES_PL3,
    4: CRS_XSS_RULES_PL4,
}


def crs_score(text: str, paranoia_level: int = 1) -> tuple[int, list[str]]:
    """
    Подсчёт anomaly score по правилам CRS для строки.
    
    Returns: (total_score, list_of_triggered_rule_ids)
    """
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
    """
    Предсказание CRS: blocked (XSS) или passed.
    
    Returns: (is_xss, anomaly_score_normalized, triggered_rules)
    """
    score, triggered = crs_score(text, paranoia_level)
    threshold = THRESHOLDS[paranoia_level]
    is_xss = score >= threshold
    # Нормализуем score в [0, 1] для совместимости с ML-метриками
    max_possible = sum(s for _, s, _ in RULE_SETS[paranoia_level])
    normalized = min(score / max_possible, 1.0) if max_possible > 0 else 0.0
    
    return is_xss, normalized, triggered


def evaluate_crs_on_dataset(texts: list[str], labels: list[int], 
                             paranoia_level: int = 1) -> dict:
    """Оценка CRS на датасете."""
    predictions = []
    probabilities = []
    
    for text in texts:
        is_xss, prob, triggered = crs_predict(text, paranoia_level)
        predictions.append(int(is_xss))
        probabilities.append(prob)
    
    predictions = np.array(predictions)
    probabilities = np.array(probabilities)
    labels = np.array(labels)
    
    # Метрики
    cm = confusion_matrix(labels, predictions)
    
    if len(np.unique(labels)) > 1:
        roc_auc = roc_auc_score(labels, probabilities)
        prec_arr, rec_arr, _ = precision_recall_curve(labels, probabilities)
        pr_auc = auc(rec_arr, prec_arr)
        fpr_arr, tpr_arr, _ = roc_curve(labels, probabilities)
        
        idx_1pct = np.searchsorted(fpr_arr, 0.01)
        tpr_1pct = tpr_arr[idx_1pct] if idx_1pct < len(tpr_arr) else 0.0
    else:
        roc_auc = 0.0
        pr_auc = 0.0
        tpr_1pct = 0.0
    
    report = classification_report(labels, predictions, 
                                    target_names=['Normal', 'XSS'],
                                    output_dict=True)
    
    return {
        'paranoia_level': paranoia_level,
        'roc_auc': roc_auc,
        'pr_auc': pr_auc,
        'tpr_1pct_fpr': tpr_1pct,
        'precision_xss': report['XSS']['precision'],
        'recall_xss': report['XSS']['recall'],
        'f1_xss': report['XSS']['f1-score'],
        'fpr': report.get('Normal', {}).get('recall', 0),
        'accuracy': report['accuracy'],
        'confusion_matrix': cm,
        'threshold': THRESHOLDS[paranoia_level],
        'n_rules': len(RULE_SETS[paranoia_level]),
    }


def main():
    print("=" * 60)
    print("OWASP CRS — Оценка XSS-правил на датасете")
    print("=" * 60)
    
    # Загрузка данных
    test_df = pd.read_csv("./datasets_test/xss_dataset.csv")
    texts_raw = test_df['text'].astype(str).tolist()
    labels = test_df['label'].values
    
    # Декодированные тексты (для честного сравнения с ML)
    texts_decoded = [decode_recursive(t) for t in texts_raw]
    
    print(f"Датасет: {len(texts_raw)} примеров, XSS={sum(labels)}, Normal={len(labels)-sum(labels)}")
    
    # Оценка для каждого PL
    results = []
    for pl in [1, 2, 3, 4]:
        print(f"\n--- Paranoia Level {pl} ({len(RULE_SETS[pl])} правил, threshold={THRESHOLDS[pl]}) ---")
        # На сырых данных
        res_raw = evaluate_crs_on_dataset(texts_raw, labels, pl)
        # На декодированных данных
        res_decoded = evaluate_crs_on_dataset(texts_decoded, labels, pl)
        
        res_raw['data'] = 'raw'
        res_decoded['data'] = 'decoded'
        results.append(res_raw)
        results.append(res_decoded)
        
        print(f"  Сырые:     AUC={res_raw['roc_auc']:.4f}, PR-AUC={res_raw['pr_auc']:.4f}, "
              f"Recall={res_raw['recall_xss']:.4f}, Precision={res_raw['precision_xss']:.4f}")
        print(f"  Декодир.:  AUC={res_decoded['roc_auc']:.4f}, PR-AUC={res_decoded['pr_auc']:.4f}, "
              f"Recall={res_decoded['recall_xss']:.4f}, Precision={res_decoded['precision_xss']:.4f}")
    
    # Сохранение результатов
    results_df = pd.DataFrame([{k: v for k, v in r.items() if k != 'confusion_matrix'} for r in results])
    results_df.to_csv(os.path.join(OUTPUT_DIR, 'crs_evaluation.csv'), index=False)
    print(f"\n✅ Результаты сохранены в {OUTPUT_DIR}/crs_evaluation.csv")
    
    # График: ROC-кривые CRS vs ML (если есть)
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    
    for pl in [1, 2, 3, 4]:
        # Используем декодированные данные (честнее)
        res = [r for r in results if r['paranoia_level'] == pl and r['data'] == 'decoded'][0]
        
        # ROC
        fpr_arr, tpr_arr, _ = roc_curve(labels, 
            [crs_predict(t, pl)[1] for t in texts_decoded])
        axes[0].plot(fpr_arr, tpr_arr, label=f'CRS PL{pl} (AUC={res["roc_auc"]:.3f})')
        
        # PR
        prec_arr, rec_arr, _ = precision_recall_curve(labels,
            [crs_predict(t, pl)[1] for t in texts_decoded])
        axes[1].plot(rec_arr, prec_arr, label=f'CRS PL{pl} (PR-AUC={res["pr_auc"]:.3f})')
    
    axes[0].plot([0, 1], [0, 1], 'k--', alpha=0.3)
    axes[0].set_xlabel('FPR')
    axes[0].set_ylabel('TPR')
    axes[0].set_title('ROC-кривая — OWASP CRS (decoded data)')
    axes[0].legend()
    
    axes[1].set_xlabel('Recall')
    axes[1].set_ylabel('Precision')
    axes[1].set_title('PR-кривая — OWASP CRS (decoded data)')
    axes[1].legend()
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'crs_roc_pr_curves.png'), dpi=150)
    plt.close()
    print(f"✅ Графики сохранены в {OUTPUT_DIR}/crs_roc_pr_curves.png")
    
    # Сводная таблица
    print("\n" + "=" * 70)
    print("СВОДНАЯ ТАБЛИЦА: CRS по уровням паранойи")
    print("=" * 70)
    summary = results_df[results_df['data'] == 'decoded'][
        ['paranoia_level', 'n_rules', 'threshold', 'roc_auc', 'pr_auc', 
         'tpr_1pct_fpr', 'recall_xss', 'precision_xss', 'accuracy']
    ]
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
