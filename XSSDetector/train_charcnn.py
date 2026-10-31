"""
Char-CNN — обучение с нуля на декодированных данных.

Главная идея: перед подачей в модель рекурсивно декодируем вход (URL → HTML-entity
→ unicode → hex) и применяем DeepXSS-генерализацию токенов. Обучение ведётся
с нуля (свои веса Embedding), поэтому не зависит от скачанных энкодеров.

Референс: DeepXSS (Fang et al., 2018).

Запуск: python train_charcnn.py
Результат: CharCNN/charcnn_xss.keras, CharCNN/charcnn_config.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
    roc_curve,
)
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
from utils.preprocess import preprocess_for_sequence_model, classify_injection_context, context_one_hot, INJECTION_CONTEXTS
from utils.char_sequence import encode_texts, VOCAB_SIZE
from utils.char_cnn import build_char_cnn


OUTPUT_DIR = "./CharCNN"
MAX_LEN = 256
BATCH_SIZE = 64
EPOCHS = 20
VALIDATION_SPLIT = 0.1
RANDOM_SEED = 42


def load_and_decode(path: str) -> tuple[np.ndarray, np.ndarray]:
    """Загружает датасет и применяет preprocess_for_sequence_model."""
    df = pd.read_csv(path)
    texts = df['text'].astype(str).tolist()
    labels = df['label'].astype(int).to_numpy()

    print(f"Загружено {len(texts)} примеров из {path}")
    print(f"  XSS={int(labels.sum())}, Benign={int((labels == 0).sum())}")

    decoded = []
    n_changed = 0
    for text in texts:
        processed = preprocess_for_sequence_model(text)
        if processed != text:
            n_changed += 1
        decoded.append(processed)

    print(f"  Препроцессировано (изменено): {n_changed}/{len(texts)} ({100 * n_changed / len(texts):.1f}%)")
    return np.array(decoded), labels


def build_context_matrix(texts: np.ndarray) -> np.ndarray:
    """Создаёт матрицу one-hot контекстов инъекции."""
    return np.asarray(
        [context_one_hot(classify_injection_context(str(t))) for t in texts],
        dtype=np.float32,
    )


def plot_training_curves(history, output_dir: str):
    """Сохраняет графики обучения."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].plot(history.history['accuracy'], label='Train acc')
    axes[0].plot(history.history['val_accuracy'], label='Val acc')
    axes[0].legend()
    axes[0].set_title('Accuracy')
    axes[0].grid(True, alpha=0.3)

    axes[1].plot(history.history['loss'], label='Train loss')
    axes[1].plot(history.history['val_loss'], label='Val loss')
    axes[1].legend()
    axes[1].set_title('Loss')
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'charcnn_training_curves.png'), dpi=150)
    plt.close()
    print(f"Графики обучения сохранены в {output_dir}/charcnn_training_curves.png")


def plot_confusion_matrix(y_true, y_pred, output_dir: str):
    """Сохраняет матрицу ошибок."""
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(xticks=np.arange(2), yticks=np.arange(2),
           xticklabels=['Normal', 'XSS'], yticklabels=['Normal', 'XSS'],
           ylabel='Истинный класс', xlabel='Предсказанный класс',
           title='Матрица ошибок Char-CNN')

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha='center', va='center',
                    color='white' if cm[i, j] > thresh else 'black')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'charcnn_confusion.png'), dpi=150)
    plt.close()
    print(f"Матрица ошибок сохранена в {output_dir}/charcnn_confusion.png")
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # === Загрузка данных ===
    train_texts, train_labels = load_and_decode("./datasets_train/xss_dataset.csv")
    test_texts, test_labels = load_and_decode("./datasets_test/xss_dataset.csv")

    # === Препроцессинг для sequence-модели ===
    x_train = encode_texts(train_texts, max_len=MAX_LEN)
    x_test = encode_texts(test_texts, max_len=MAX_LEN)

    c_train = build_context_matrix(train_texts)
    c_test = build_context_matrix(test_texts)

    print(f"Форма обучающих данных: {x_train.shape}, контексты: {c_train.shape}")
    print(f"Форма тестовых данных: {x_test.shape}, контексты: {c_test.shape}")

    # === Модель ===
    model = build_char_cnn(
        max_len=MAX_LEN,
        embedding_dim=32,
        context_dim=len(INJECTION_CONTEXTS),
        dropout=0.3,
    )
    model.summary()

    # === Обучение ===
    early_stop = EarlyStopping(
        monitor='val_loss', patience=5, restore_best_weights=True, verbose=1
    )
    checkpoint = ModelCheckpoint(
        os.path.join(OUTPUT_DIR, 'charcnn_decoded_best.keras'),
        monitor='val_accuracy', save_best_only=True, verbose=1,
    )

    history = model.fit(
        [x_train, c_train],
        train_labels,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=VALIDATION_SPLIT,
        callbacks=[early_stop, checkpoint],
        verbose=1,
    )

    # === Оценка на тесте ===
    print("\n" + "=" * 60)
    print("ОЦЕНКА НА ТЕСТОВОМ ДАТАСЕТЕ")
    print("=" * 60)

    y_pred_prob = model.predict([x_test, c_test], batch_size=BATCH_SIZE, verbose=0).flatten()
    y_pred = (y_pred_prob >= 0.5).astype(int)

    print(classification_report(test_labels, y_pred, target_names=['Normal', 'XSS']))
    print(f"AUC: {roc_auc_score(test_labels, y_pred_prob):.4f}")

    precision_arr, recall_arr, _ = precision_recall_curve(test_labels, y_pred_prob)
    pr_auc = auc(recall_arr, precision_arr)
    print(f"PR-AUC: {pr_auc:.4f}")

    fpr, tpr, _ = roc_curve(test_labels, y_pred_prob)
    idx_1pct = np.searchsorted(fpr, 0.01)
    if idx_1pct < len(tpr):
        print(f"TPR@1%FPR: {tpr[idx_1pct]:.4f}")

    plot_training_curves(history, OUTPUT_DIR)
    plot_confusion_matrix(test_labels, y_pred, OUTPUT_DIR)

    # === Сохранение ===
    model.save(os.path.join(OUTPUT_DIR, 'charcnn_xss.keras'))
    config = {'max_len': MAX_LEN, 'context_dim': len(INJECTION_CONTEXTS), 'embedding_dim': 32, 'dropout': 0.3}
    (Path(OUTPUT_DIR) / 'charcnn_config.json').write_text(json.dumps(config, indent=2), encoding='utf-8')
    print(f"\n✅ Модель и конфиг сохранены в {OUTPUT_DIR}/")

    # === Тесты на обходах ===
    print("\n" + "=" * 60)
    print("ТЕСТЫ УСТОЙЧИВОСТИ К ОБХОДАМ")
    print("=" * 60)

    evasion_tests = [
        ("<script>alert('XSS')</script>", "Базовый script"),
        ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL-encoded"),
        ("%253Cscript%253Ealert('XSS')%253C/script%253E", "Double URL-encoded"),
        ("<ScRiPt>AlErT('XSS')</ScRiPt>", "Mixed case"),
        ("\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e", "Unicode escape"),
        ('<img src=x onerror="alert(1)">', "Event handler"),
        ("<div class='post'>Hello world</div>", "Benign HTML"),
        ("This is a normal comment about <script> tags", "Benign with keyword"),
        ("javascript:alert(document.cookie)", "JS pseudo-protocol"),
        ("<svg onload=alert(1)>", "SVG onload"),
        ("<body onload=alert(1)>", "Body onload"),
    ]

    for text, label in evasion_tests:
        processed = preprocess_for_sequence_model(text)
        tokens = encode_texts([processed], max_len=MAX_LEN)
        context = build_context_matrix(np.array([processed]))
        prob = float(model.predict([tokens, context], verbose=0)[0, 0])
        verdict = "XSS" if prob >= 0.5 else "NORMAL"
        print(f"  [{verdict:>6}] prob={prob:.3f} | {label}: {text[:60]}")


if __name__ == "__main__":
    main()