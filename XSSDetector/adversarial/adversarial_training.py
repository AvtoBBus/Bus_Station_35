"""
Цикл состязательного обучения (co-training: генератор обходов ↔ детектор).

Схема (plan_VKR_XSS.md, Раздел 3):
1. Раунд 0: обучить детектор на данных Раздела 2, зафиксировать метрики
2. Итерация: G атакует текущий D → оракул оставляет исполняемые →
   метим как XSS → добавляем в обучение → дообучаем D →
   перемеряем evasion rate и метрики на чистых данных (FPR не растёт)
3. Повторяем до плато

Результат:
- Упрочнённый детектор, устойчивый к автоматическим обходам
- Кривая устойчивости: TPR на состязательном тесте по раундам
- Сравнение: упрочнённый vs базовый vs OWASP CRS

Запуск: python adversarial_training.py
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, auc
)
import matplotlib.pyplot as plt
import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.preprocess import decode_recursive
from utils.load_models import predict_catboost, _ensure_catboost
from utils.extract_features import extract_features
from catboost import CatBoostClassifier
from adversarial.xss_mutator import XSSMutator, SEED_PAYLOADS
from adversarial.xss_oracle import validate_payload_heuristic

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Adversarial")
os.makedirs(OUTPUT_DIR, exist_ok=True)
DETECTOR_THRESHOLD = 0.5


def detector_fn(payload: str) -> tuple[bool, float]:
    """Обёртка детектора для мутатора: (payload) → (is_xss, probability)."""
    decoded = decode_recursive(payload)
    is_xss, prob = predict_catboost(decoded, threshold=DETECTOR_THRESHOLD)
    return is_xss, prob


def validate_mutant(payload: str) -> bool:
    """Проверяет, что мутант остаётся исполняемым XSS (эвристический оракул)."""
    result = validate_payload_heuristic(payload)
    return result['is_executable']


def load_clean_dataset(path: str) -> tuple[list[str], np.ndarray]:
    """Загружает чистый датасет с декодированием."""
    df = pd.read_csv(path)
    texts = [decode_recursive(str(t)) for t in df['text'].values]
    labels = df['label'].values
    return texts, labels


def evaluate_detector_on_texts(texts: list[str], labels, name: str = "") -> dict:
    """Оценка детектора на списке текстов."""
    predictions = []
    probabilities = []
    
    for text in texts:
        is_xss, prob = predict_catboost(text, threshold=DETECTOR_THRESHOLD)
        predictions.append(int(is_xss))
        probabilities.append(prob)
    
    predictions = np.array(predictions)
    probabilities = np.array(probabilities)
    labels = np.array(labels)
    
    report = classification_report(labels, predictions,
                                    target_names=['Normal', 'XSS'],
                                    output_dict=True)
    
    roc_auc = roc_auc_score(labels, probabilities) if len(np.unique(labels)) > 1 else 0.0
    
    prec_arr, rec_arr, _ = precision_recall_curve(labels, probabilities)
    pr_auc = auc(rec_arr, prec_arr) if len(np.unique(labels)) > 1 else 0.0
    
    fpr_arr, tpr_arr, _ = roc_curve(labels, probabilities)
    idx_1pct = np.searchsorted(fpr_arr, 0.01)
    tpr_1pct = tpr_arr[idx_1pct] if idx_1pct < len(tpr_arr) else 0.0
    
    metrics = {
        'name': name,
        'roc_auc': float(roc_auc),
        'pr_auc': float(pr_auc),
        'tpr_1pct_fpr': float(tpr_1pct),
        'precision_xss': float(report['XSS']['precision']),
        'recall_xss': float(report['XSS']['recall']),
        'f1_xss': float(report['XSS']['f1-score']),
        'fpr': float(1 - report['Normal']['recall']),
        'accuracy': float(report['accuracy']),
        'n_samples': len(labels),
    }
    
    print(f"  {name}: AUC={roc_auc:.4f}, PR-AUC={pr_auc:.4f}, "
          f"Recall={report['XSS']['recall']:.4f}, FPR={metrics['fpr']:.4f}")
    
    return metrics


def run_adversarial_round(round_num: int, seeds: list[str],
                           n_samples: int = 20) -> list[dict]:
    """
    Один раунд состязательной атаки.
    
    Returns: список обходящих пейлоадов [{'text': ..., 'label': 1, 'source': 'adv_rN'}]
    """
    print(f"\n{'='*60}")
    print(f"РАУНД {round_num}: Генерация мутантов")
    print(f"{'='*60}")
    
    mutator = XSSMutator(
        detector_fn=detector_fn,
        population_size=15,
        n_iterations=30,
        n_mutations_per_payload=3,
    )
    
    attack_results = mutator.attack_from_seeds(seeds)
    
    # Фильтруем: только обходящие + исполняемые
    evasion_payloads = []
    for result in attack_results:
        if result['evasion_success']:
            # Проверяем оракулом
            is_executable = validate_mutant(result['best_payload'])
            if is_executable:
                evasion_payloads.append({
                    'text': result['best_payload'],
                    'label': 1,
                    'source': f'adversarial_r{round_num}',
                })
    
    # Статистика
    n_attacks = len(attack_results)
    n_evasions = sum(1 for r in attack_results if r['evasion_success'])
    n_executable = len(evasion_payloads)
    
    print(f"\n  Атак: {n_attacks}, Обходов: {n_evasions} ({100*n_evasions/n_attacks:.1f}%), "
          f"Исполняемых: {n_executable} ({100*n_executable/max(n_attacks,1):.1f}%)")
    
    return evasion_payloads


def retrain_with_adversarial(base_train_path: str, adversarial_payloads: list[dict],
                              output_path: str):
    """
    Добавляет обходящие пейлоады в обучающую выборку.
    (В реальном сценарии — переобучение CatBoost. Здесь — расширение датасета.)
    """
    base_df = pd.read_csv(base_train_path)
    
    if adversarial_payloads:
        adv_df = pd.DataFrame(adversarial_payloads)
        combined = pd.concat([base_df, adv_df], ignore_index=True)
    else:
        combined = base_df
    
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    combined.to_csv(output_path, index=False)
    
    print(f"\n  Датасет расширен: {len(base_df)} → {len(combined)} "
          f"(+{len(adversarial_payloads)} обходящих)")
    
    return output_path


def retrain_detector(train_path: str, model_path: str) -> None:
    """Переобучает CatBoost на расширенном датасете и обновляет модель в памяти."""
    _, metadata = _ensure_catboost()
    train_df = pd.read_csv(train_path)
    labels = train_df["label"].astype(int).to_numpy()
    features = pd.DataFrame(
        [extract_features(decode_recursive(str(text))) for text in train_df["text"]]
    )
    feature_names = metadata["feature_names"]
    for feature in feature_names:
        if feature not in features.columns:
            features[feature] = 0
    features = features[feature_names]
    for feature in metadata.get("cat_features", []):
        if feature in features.columns:
            features[feature] = features[feature].astype("category")

    model = CatBoostClassifier(
        iterations=300,
        depth=6,
        learning_rate=0.05,
        loss_function="Logloss",
        eval_metric="AUC",
        random_seed=42,
        verbose=False,
        allow_writing_files=False,
    )
    model.fit(
        features,
        labels,
        cat_features=metadata.get("cat_features", []),
        text_features=["text"],
    )
    model.save_model(model_path)

    import utils.load_models as load_models
    load_models._catboost_model = model
    load_models._catboost_metadata = metadata
    print(f"  Детектор переобучен и загружен: {model_path}")


def main():
    """Основной цикл состязательного обучения."""
    
    print("=" * 60)
    print("СОСТЯЗАТЕЛЬНОЕ ОБУЧЕНИЕ (Co-training)")
    print("Генератор обходов ↔ Детектор")
    print("=" * 60)
    
    # === Раунд 0: Базовая оценка ===
    print("\n" + "=" * 60)
    print("РАУНД 0: Базовая оценка детектора")
    print("=" * 60)
    
    test_texts, test_labels = load_clean_dataset(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                     "datasets_test", "xss_dataset.csv")
    )
    
    baseline_metrics = evaluate_detector_on_texts(test_texts, test_labels, "Baseline")
    
    # Базовый evasion rate
    print("\n--- Базовый evasion rate ---")
    baseline_seeds = SEED_PAYLOADS[:10]  # Берём 10 seeds для скорости
    baseline_evasions = run_adversarial_round(0, baseline_seeds)
    baseline_evasion_rate = len(baseline_evasions) / len(baseline_seeds) * 100
    print(f"  Базовый evasion rate: {baseline_evasion_rate:.1f}%")
    
    # === Итеративный цикл ===
    all_rounds = [{
        'round': 0,
        'clean_metrics': baseline_metrics,
        'evasion_rate': baseline_evasion_rate,
        'n_adversarial_samples': 0,
    }]
    
    train_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                               "datasets_train", "xss_dataset.csv")
    
    current_train_path = train_path
    MAX_ROUNDS = 5
    EVASION_THRESHOLD = 5.0  # Целевой evasion rate (%)
    
    for round_num in range(1, MAX_ROUNDS + 1):
        print(f"\n{'#'*60}")
        print(f"РАУНД {round_num}/{MAX_ROUNDS}")
        print(f"{'#'*60}")
        
        # 1. Атака текущего детектора
        evasion_payloads = run_adversarial_round(round_num, baseline_seeds)
        evasion_rate = len(evasion_payloads) / len(baseline_seeds) * 100
        
        if not evasion_payloads:
            print(f"\n  ✅ Нет обходящих пейлоадов! Детектор устойчив.")
            break
        
        # 2. Добавляем обходящие пейлоады в обучающую выборку
        adv_train_path = os.path.join(OUTPUT_DIR, f"train_adversarial_r{round_num}.csv")
        current_train_path = retrain_with_adversarial(
            current_train_path, evasion_payloads, adv_train_path
        )
        model_path = os.path.join(OUTPUT_DIR, f"catboost_adversarial_r{round_num}.cbm")
        retrain_detector(current_train_path, model_path)
        
        # 3. Оценка на чистых данных (FPR не должен вырасти)
        clean_metrics = evaluate_detector_on_texts(test_texts, test_labels,
                                                     f"Round {round_num}")
        
        all_rounds.append({
            'round': round_num,
            'clean_metrics': clean_metrics,
            'evasion_rate': evasion_rate,
            'n_adversarial_samples': len(evasion_payloads),
        })
        
        # 4. Проверяем, не вырос ли FPR
        if clean_metrics['fpr'] > baseline_metrics['fpr'] * 1.5:
            print(f"\n  ⚠️ FPR вырос значительно ({clean_metrics['fpr']:.4f} vs "
                  f"{baseline_metrics['fpr']:.4f}). Останавливаем.")
            break
        
        # 5. Проверяем плато
        if evasion_rate < EVASION_THRESHOLD:
            print(f"\n  ✅ Evasion rate ({evasion_rate:.1f}%) ниже порога ({EVASION_THRESHOLD}%). "
                  f"Детектор устойчив.")
            break
    
    # === Сохранение результатов ===
    results_path = os.path.join(OUTPUT_DIR, "adversarial_results.json")
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(all_rounds, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n✅ Результаты сохранены: {results_path}")
    
    # === Графики ===
    rounds = [r['round'] for r in all_rounds]
    evasion_rates = [r['evasion_rate'] for r in all_rounds]
    aucs = [r['clean_metrics']['roc_auc'] for r in all_rounds]
    fprs = [r['clean_metrics']['fpr'] for r in all_rounds]
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    
    # Evasion rate по раундам
    axes[0].plot(rounds, evasion_rates, 'o-', color='red', linewidth=2, markersize=8)
    axes[0].axhline(y=EVASION_THRESHOLD, color='green', linestyle='--', label=f'Цель ({EVASION_THRESHOLD}%)')
    axes[0].set_xlabel('Раунд')
    axes[0].set_ylabel('Evasion Rate (%)')
    axes[0].set_title('Кривая устойчивости')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)
    
    # AUC на чистых данных
    axes[1].plot(rounds, aucs, 's-', color='blue', linewidth=2, markersize=8)
    axes[1].set_xlabel('Раунд')
    axes[1].set_ylabel('ROC-AUC')
    axes[1].set_title('Качество на чистых данных')
    axes[1].grid(True, alpha=0.3)
    
    # FPR на чистых данных
    axes[2].plot(rounds, fprs, 'D-', color='orange', linewidth=2, markersize=8)
    axes[2].set_xlabel('Раунд')
    axes[2].set_ylabel('FPR')
    axes[2].set_title('False Positive Rate')
    axes[2].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "adversarial_training_curves.png"), dpi=150)
    plt.close()
    print(f"✅ Графики сохранены: {OUTPUT_DIR}/adversarial_training_curves.png")
    
    # === Сводка ===
    print(f"\n{'='*60}")
    print("СВОДКА СОСТЯЗАТЕЛЬНОГО ОБУЧЕНИЯ")
    print(f"{'='*60}")
    print(f"  Раундов: {len(all_rounds) - 1}")
    print(f"  Базовый evasion rate: {all_rounds[0]['evasion_rate']:.1f}%")
    if len(all_rounds) > 1:
        print(f"  Финальный evasion rate: {all_rounds[-1]['evasion_rate']:.1f}%")
    print(f"  Базовый AUC: {all_rounds[0]['clean_metrics']['roc_auc']:.4f}")
    print(f"  Финальный AUC: {all_rounds[-1]['clean_metrics']['roc_auc']:.4f}")
    print(f"  Базовый FPR: {all_rounds[0]['clean_metrics']['fpr']:.4f}")
    print(f"  Финальный FPR: {all_rounds[-1]['clean_metrics']['fpr']:.4f}")


if __name__ == "__main__":
    main()
