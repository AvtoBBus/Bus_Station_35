import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix, roc_curve
)

def tpr_at_1pct_fpr(y_true, y_pred_proba):
    """Максимальная доля обнаруженных атак (TPR) при FPR <= 1%, по ROC-кривой.

    None, если в y_true один класс (метрика не определена).
    Если нормальных примеров меньше 100, условие FPR <= 1% означает FPR = 0 (метрика грубая).
    Прежняя реализация при числе нормальных < 100 останавливалась на первом же примере и давала ~0.
    """
    y = np.asarray(y_true)
    if len(np.unique(y)) < 2:
        return None
    fpr, tpr, _ = roc_curve(y, np.asarray(y_pred_proba, dtype=float))
    return float(tpr[fpr <= 0.01].max())


def calculate_metrics(y_true, y_pred, y_proba) -> dict:
    """Вычисляет стандартный набор метрик."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else float('nan'),
        "pr_auc": float(average_precision_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else None,
        "tpr_at_1pct_fpr": tpr_at_1pct_fpr(y_true, y_proba),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist()
    }

def save_metrics_json(metrics: dict, run_dir: Path):
    with open(run_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4, ensure_ascii=False)

def save_standard_plots(y_true, y_pred, y_proba, run_dir: Path, history=None, model_name="Model"):
    # 1. Матрица ошибок
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Benign', 'XSS'], yticklabels=['Benign', 'XSS'])
    plt.title(f'Матрица ошибок ({model_name})')
    plt.tight_layout()
    plt.savefig(run_dir / "confusion_matrix.png", dpi=150)
    plt.close()

    # 2. ROC-кривая
    if len(np.unique(y_true)) > 1:
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        auc_val = roc_auc_score(y_true, y_proba)
        plt.figure(figsize=(6, 5))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {auc_val:.4f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'ROC-кривая ({model_name})')
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(run_dir / "roc_curve.png", dpi=150)
        plt.close()

    # 3. Кривые обучения (для нейросетей)
    if history is not None:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        hist_dict = history.history if hasattr(history, "history") else history
        if 'accuracy' in hist_dict:
            axes[0].plot(hist_dict['accuracy'], label='Train acc')
            axes[0].plot(hist_dict.get('val_accuracy', []), label='Val acc')
        axes[0].legend(); axes[0].set_title('Accuracy')
        if 'loss' in hist_dict:
            axes[1].plot(hist_dict['loss'], label='Train loss')
            axes[1].plot(hist_dict.get('val_loss', []), label='Val loss')
        axes[1].legend(); axes[1].set_title('Loss')
        plt.tight_layout()
        plt.savefig(run_dir / "training_curves.png", dpi=150)
        plt.close()