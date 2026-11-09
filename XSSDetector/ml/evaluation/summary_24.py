"""
Итоговое сравнение моделей по пункту 2.4 «Более сложная модель».

Запускает LODO-оценку для всех моделей (классические + сложные),
сводит результаты в таблицу и отвечает на научный вопрос:
даёт ли усложнение модели реальный прирост обобщаемости (LODO),
или только in-distribution метрики.

Запуск: python summary_24.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS_DIR = ROOT / 'results'


def load_csv(name: str) -> pd.DataFrame:
    path = RESULTS_DIR / name
    if path.is_file():
        return pd.read_csv(path)
    return pd.DataFrame()


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Загружаем существующие результаты (если уже были запущены оценки)
    lodo_charcnn = load_csv('lodo_charcnn.csv')
    lodo_transformer = load_csv('lodo_transformer.csv')
    lodo_classical = load_csv('lodo_classical.csv')
    lodo_baseline = load_csv('lodo_baseline_metrics.csv')

    all_dfs = []
    for df, model_name in [
        (lodo_charcnn, 'charcnn'),
        (lodo_transformer, 'transformer'),
        (lodo_classical, None),  # already has model column
        (lodo_baseline, 'tfidf_lr_baseline'),
    ]:
        if df.empty:
            continue
        if model_name is not None:
            df = df.copy()
            df['model'] = model_name
        all_dfs.append(df)

    if not all_dfs:
        print("❌ Нет результатов LODO-оценок. Сначала запустите:")
        print("   python evaluate_lodo_classical.py --model all")
        print("   python evaluate_lodo_complex.py --model charcnn")
        print("   python evaluate_lodo_complex.py --model transformer")
        print("   python -m data.scripts.normalize_datasets  # или evaluate_lodo_baseline")
        return

    combined = pd.concat(all_dfs, ignore_index=True)

    # === Сводная таблица ===
    print("\n" + "=" * 80)
    print("СВОДНАЯ ТАБЛИЦА: LODO-оценка всех моделей (punkt 2.4)")
    print("=" * 80)

    agg = combined.groupby('model')[['pr_auc', 'roc_auc', 'tpr_at_1pct_fpr', 'negative_fpr']].agg(['mean', 'std']).round(4)
    print(agg.to_string())

    # === По источникам ===
    print("\n" + "=" * 80)
    print("ПО ИСТОЧНИКАм (LODO held-out): PR-AUC / TPR@1%FPR / neg_FPR")
    print("=" * 80)
    pivot = combined.pivot_table(
        index='source', columns='model',
        values='pr_auc', aggfunc='mean'
    ).round(4)
    print(pivot.to_string())

    # === Hard-negative / hard-benign FPR ===
    print("\n" + "=" * 80)
    print("HARD-NEGATIVE / HARD-BENIGN FPR (среднее по источникам)")
    print("=" * 80)
    hn = combined.groupby('model')[['hard_negative_fpr', 'hard_benign_fpr', 'negative_fpr']].mean().round(4)
    print(hn.to_string())

    # === Научный вывод ===
    print("\n" + "=" * 80)
    print("НАУЧНЫЙ ВЫВОД (punkt 2.4)")
    print("=" * 80)

    # Сравниваем средние PR-AUC между классическими и сложными моделями
    classical_models = ['catboost', 'rf', 'lr', 'svm', 'tfidf_lr_baseline']
    complex_models = ['charcnn', 'transformer', 'bilstm']

    classical_auc = {}
    complex_auc = {}
    for m in classical_models:
        sub = combined[combined['model'] == m]
        if not sub.empty:
            classical_auc[m] = sub['pr_auc'].mean()
    for m in complex_models:
        sub = combined[combined['model'] == m]
        if not sub.empty:
            complex_auc[m] = sub['pr_auc'].mean()

    if classical_auc and complex_auc:
        best_classical = max(classical_auc, key=classical_auc.get)
        best_complex = max(complex_auc, key=complex_auc.get)
        print(f"\nЛучшая классическая модель: {best_classical} (PR-AUC={classical_auc[best_classical]:.4f})")
        print(f"Лучшая сложная модель: {best_complex} (PR-AUC={complex_auc[best_complex]:.4f})")

        delta = complex_auc[best_complex] - classical_auc[best_classical]
        print(f"\nРазница (сложная − классическая): {delta:+.4f} PR-AUC")

        if delta > 0.02:
            print("✅ Усложнение модели даёт заметный прирост обобщаемости на LODO.")
        elif delta > -0.02:
            print("⚠️  Прирост обобщаемости отсутствует — сложные модели не превосходят классические на кросс-датасетном протоколе.")
        else:
            print("❌ Сложные модели хуже классических на LODO — возможна переобучаемость под исходные распределения.")

    # === Сохраняем итоговую таблицу ===
    out_path = RESULTS_DIR / 'summary_24.csv'
    combined.to_csv(out_path, index=False)
    print(f"\n✅ Итоговая таблица сохранена: {out_path}")


if __name__ == '__main__':
    main()