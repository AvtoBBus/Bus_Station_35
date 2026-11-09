import os
import sys
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, auc
)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from joblib import Parallel, delayed

# Добавляем корень проекта (XSSDetector) в sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from ml.features.preprocess import decode_recursive
from ml.features.extract_features import extract_features
from ml.serving.predictor import model_manager

# Импорты локальных модулей
from ml.training.adversarial.xss_mutator import XSSMutator, SEED_PAYLOADS
from ml.training.adversarial.xss_oracle import validate_payload_heuristic

from catboost import CatBoostClassifier

# Пути
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

ML_DIR = BASE_DIR.parent.parent
DATASET_PATH = ML_DIR / "datasets" / "processed" / "unified_dataset.csv"
CATBOOST_WEIGHTS_DIR = ML_DIR / "models" / "catboost" / "weights"

DETECTOR_THRESHOLD = 0.5

def detector_fn(payload: str) -> tuple[bool, float]:
    """Обёртка детектора для мутатора: (payload) -> (is_xss, probability)."""
    catboost_adapter = model_manager.get_model('catboost')
    if not catboost_adapter:
        raise RuntimeError("CatBoost adapter is not loaded in ModelManager")
    
    decoded = decode_recursive(payload)
    feats = pd.DataFrame([extract_features(decoded, False)])
    
    expected_features = [f for f in catboost_adapter.metadata['feature_names'] if f != 'text']
    prob = catboost_adapter.predict_proba(feats[expected_features])[0, 1]
    return prob >= DETECTOR_THRESHOLD, prob

def validate_mutant(payload: str) -> bool:
    """Проверяет, что мутант остаётся исполняемым XSS."""
    result = validate_payload_heuristic(payload)
    return result['is_executable']

def load_clean_dataset(path: Path) -> tuple[list[str], np.ndarray, list[str], np.ndarray]:
    if not path.exists():
        raise FileNotFoundError(f"Датасет не найден: {path}")
        
    df = pd.read_csv(path)
    # Ограничиваем для скорости состязательного цикла
    if len(df) > 50000:
        df = df.sample(n=50000, random_state=42)
        
    train_df = df.sample(frac=0.8, random_state=42)
    test_df = df.drop(train_df.index)
    
    train_texts = [decode_recursive(str(t)) for t in train_df['text'].values]
    train_labels = train_df['label'].values
    
    test_texts = [decode_recursive(str(t)) for t in test_df['text'].values]
    test_labels = test_df['label'].values
    
    return train_texts, train_labels, test_texts, test_labels

def evaluate_detector_on_texts(texts: list[str], labels, name: str = "") -> dict:
    predictions = []
    
    catboost_adapter = model_manager.get_model('catboost')
    
    print(f"  Извлечение признаков для {len(texts)} тестовых строк...")
    feats_list = Parallel(n_jobs=-1)(delayed(extract_features)(t, True) for t in texts)
    features_df = pd.DataFrame(feats_list)
    
    probs = catboost_adapter.predict_proba(features_df)[:, 1]
    predictions = (probs >= DETECTOR_THRESHOLD).astype(int)
    
    labels = np.array(labels)
    
    report = classification_report(labels, predictions, target_names=['Normal', 'XSS'], output_dict=True, zero_division=0)
    roc_auc = roc_auc_score(labels, probs) if len(np.unique(labels)) > 1 else 0.0
    
    prec_arr, rec_arr, _ = precision_recall_curve(labels, probs)
    pr_auc = auc(rec_arr, prec_arr) if len(np.unique(labels)) > 1 else 0.0
    
    fpr_arr, tpr_arr, _ = roc_curve(labels, probs)
    idx_1pct = np.searchsorted(fpr_arr, 0.01)
    tpr_1pct = tpr_arr[idx_1pct] if idx_1pct < len(tpr_arr) else 0.0
    
    metrics = {
        'name': name,
        'roc_auc': float(roc_auc),
        'pr_auc': float(pr_auc),
        'tpr_1pct_fpr': float(tpr_1pct),
        'recall_xss': float(report['XSS']['recall']),
        'fpr': float(1 - report['Normal']['recall']),
    }
    
    print(f"  {name}: AUC={roc_auc:.4f}, PR-AUC={pr_auc:.4f}, Recall={report['XSS']['recall']:.4f}, FPR={metrics['fpr']:.4f}")
    return metrics

def run_adversarial_round(round_num: int, seeds: list[str]) -> list[dict]:
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
    
    evasion_payloads = []
    for result in attack_results:
        if result['evasion_success']:
            is_executable = validate_mutant(result['best_payload'])
            if is_executable:
                evasion_payloads.append({
                    'text': result['best_payload'],
                    'label': 1,
                    'source': f'adversarial_r{round_num}',
                })
    
    n_attacks = len(attack_results)
    n_evasions = sum(1 for r in attack_results if r['evasion_success'])
    n_executable = len(evasion_payloads)
    
    print(f"\n  Атак: {n_attacks}, Обходов: {n_evasions} ({100*n_evasions/max(n_attacks,1):.1f}%), "
          f"Исполняемых: {n_executable} ({100*n_executable/max(n_attacks,1):.1f}%)")
    
    return evasion_payloads

def retrain_detector(clean_texts, clean_labels, adversarial_payloads, model_path: Path):
    if adversarial_payloads:
        adv_texts = [p['text'] for p in adversarial_payloads]
        adv_labels = [p['label'] for p in adversarial_payloads]
        all_texts = clean_texts + adv_texts
        all_labels = np.concatenate([clean_labels, adv_labels])
    else:
        all_texts = clean_texts
        all_labels = clean_labels
        
    print(f"  Извлечение признаков для дообучения ({len(all_texts)} строк)...")
    feats_list = Parallel(n_jobs=-1)(delayed(extract_features)(t, True) for t in all_texts)
    features = pd.DataFrame(feats_list)
    
    catboost_adapter = model_manager.get_model('catboost')
    metadata = catboost_adapter.metadata
    feature_names = metadata['feature_names'] # оставляем 'text'
    
    features = features[feature_names]
    
    catboost_adapter = model_manager.get_model('catboost')
    metadata = catboost_adapter.metadata
    feature_names = [f for f in metadata['feature_names'] if f != 'text']
    
    features = features[feature_names]
    
    for feature in metadata.get('cat_features', []):
        if feature in features.columns:
            features[feature] = features[feature].astype(str)

    model = CatBoostClassifier(
        iterations=300, depth=6, learning_rate=0.05, loss_function="Logloss",
        eval_metric="AUC", random_seed=42, verbose=False, allow_writing_files=False,
    )
    
    print("  Обучение CatBoost...")
    model.fit(features, all_labels, cat_features=[f for f in metadata.get('cat_features', []) if f != 'text'])
    
    CATBOOST_WEIGHTS_DIR.mkdir(parents=True, exist_ok=True)
    model.save_model(str(model_path))
    print(f"  Модель сохранена в {model_path}")

    # Обновляем модель в памяти, чтобы следующий раунд бил по новой модели
    catboost_adapter.model = model
    print("  ModelManager обновлен новой моделью.")

def main():
    print("=" * 60)
    print("СОСТЯЗАТЕЛЬНОЕ ОБУЧЕНИЕ (Co-training)")
    print("=" * 60)
    
    train_texts, train_labels, test_texts, test_labels = load_clean_dataset(DATASET_PATH)
    
    print("\nРАУНД 0: Базовая оценка детектора")
    baseline_metrics = evaluate_detector_on_texts(test_texts, test_labels, "Baseline")
    
    print("\n--- Базовый evasion rate ---")
    baseline_seeds = SEED_PAYLOADS[:10] # Берем 10 сидов для скорости
    baseline_evasions = run_adversarial_round(0, baseline_seeds)
    baseline_evasion_rate = len(baseline_evasions) / len(baseline_seeds) * 100
    print(f"  Базовый evasion rate: {baseline_evasion_rate:.1f}%")
    
    all_rounds = [{
        'round': 0, 'clean_metrics': baseline_metrics,
        'evasion_rate': baseline_evasion_rate, 'n_adversarial_samples': 0,
    }]
    
    MAX_ROUNDS = 3
    EVASION_THRESHOLD = 10.0 # Если evasion rate < 10%, считаем модель устойчивой
    
    for round_num in range(1, MAX_ROUNDS + 1):
        print(f"\n{'#'*60}\nРАУНД {round_num}/{MAX_ROUNDS}\n{'#'*60}")
        
        evasion_payloads = run_adversarial_round(round_num, baseline_seeds)
        evasion_rate = len(evasion_payloads) / len(baseline_seeds) * 100
        
        if not evasion_payloads:
            print(f"\n  ✅ Нет обходящих пейлоадов! Детектор устойчив.")
            break
        
        model_path = CATBOOST_WEIGHTS_DIR / f"catboost_adversarial_r{round_num}.cbm"
        retrain_detector(train_texts, train_labels, evasion_payloads, model_path)
        
        clean_metrics = evaluate_detector_on_texts(test_texts, test_labels, f"Round {round_num}")
        
        all_rounds.append({
            'round': round_num, 'clean_metrics': clean_metrics,
            'evasion_rate': evasion_rate, 'n_adversarial_samples': len(evasion_payloads),
        })
        
        if evasion_rate < EVASION_THRESHOLD:
            print(f"\n  ✅ Evasion rate ниже {EVASION_THRESHOLD}%. Детектор устойчив.")
            break
    
    # Сохранение результатов и графики
    results_path = OUTPUT_DIR / "adversarial_results.json"
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(all_rounds, f, indent=2, ensure_ascii=False, default=str)
    
    rounds = [r['round'] for r in all_rounds]
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    axes[0].plot(rounds, [r['evasion_rate'] for r in all_rounds], 'o-', color='red')
    axes[0].set_title('Evasion Rate (%)')
    axes[1].plot(rounds, [r['clean_metrics']['roc_auc'] for r in all_rounds], 's-', color='blue')
    axes[1].set_title('ROC-AUC (Clean)')
    axes[2].plot(rounds, [r['clean_metrics']['fpr'] for r in all_rounds], 'D-', color='orange')
    axes[2].set_title('FPR (Clean)')
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "adversarial_training_curves.png", dpi=150)
    plt.close()
    
    print(f"\n✅ Графики и результаты сохранены в {OUTPUT_DIR}")

if __name__ == "__main__":
    main()