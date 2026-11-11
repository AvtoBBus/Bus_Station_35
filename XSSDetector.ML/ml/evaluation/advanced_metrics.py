import numpy as np
import pandas as pd
from ml.features.preprocess import classify_injection_context, INJECTION_CONTEXTS

def tpr_at_fpr(y_true, scores, max_fpr: float = 0.01) -> float:
    """Максимальная TPR при FPR <= max_fpr (строго по ROC-кривой, без «перелёта» через порог).

    Для дискретных скоринговых функций (например, regex-эмуляция CRS) это важно:
    ближайшая ROC-точка с FPR >= 1% может иметь FPR 30-50%, и её TPR нельзя
    выдавать за «TPR при 1% FPR».
    """
    from sklearn.metrics import roc_curve
    y = np.asarray(y_true)
    s = np.asarray(scores, dtype=float)
    if len(np.unique(y)) < 2:
        return float('nan')
    fpr, tpr, _ = roc_curve(y, s)
    return float(tpr[fpr <= max_fpr].max())


HARD_NEGATIVE_SOURCES = {'modsecurity', 'capec', 'fwaf', 'ecmlpkdd2007', 'csic2010', 'httpparams'}

def compute_negative_fpr(y_true, y_proba, threshold=0.5):
    negative_mask = y_true == 0
    if not negative_mask.any(): return float('nan')
    return float(np.mean(y_proba[negative_mask] >= threshold))

def compute_source_metrics(source_name: str, y_true, y_proba, texts):
    """Рассчитывает специфичные для SecOps метрики для одного источника."""
    negative_mask = y_true == 0
    hard_neg_mask = negative_mask & (source_name in HARD_NEGATIVE_SOURCES)
    hard_benign_mask = negative_mask & (source_name == 'hard_benign')
    
    # Анализ контекстов (где именно была инъекция)
    contexts = pd.Series([classify_injection_context(str(t)) for t in texts])
    context_counts = contexts.value_counts().to_dict()
    
    return {
        'negative_fpr': compute_negative_fpr(y_true, y_proba),
        'hard_negative_rows': int(hard_neg_mask.sum()),
        'hard_negative_fpr': float(np.mean(y_proba[hard_neg_mask] >= 0.5)) if hard_neg_mask.any() else float('nan'),
        'hard_benign_rows': int(hard_benign_mask.sum()),
        'hard_benign_fpr': float(np.mean(y_proba[hard_benign_mask] >= 0.5)) if hard_benign_mask.any() else float('nan'),
        **{f'context_{k}': int(v) for k, v in context_counts.items() if k in INJECTION_CONTEXTS}
    }