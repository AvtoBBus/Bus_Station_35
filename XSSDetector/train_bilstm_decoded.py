"""
BiLSTM — переобучение на декодированных данных.

Главная идея: перед токенизацией рекурсивно декодируем вход (URL → HTML-entity → unicode → hex).
Это закрывает обход через многослойное кодирование и позволяет LSTM учиться на реальном содержимом.

Референс: DeepXSS (Fang et al., 2018).

Запуск: python train_bilstm_decoded.py
Результат: BiLSTM/bilstm_decoded_model.h5, BiLSTM/bilstm_decoded_tokenizer.pkl
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve, auc

import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Bidirectional, GlobalMaxPooling1D
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
import sys

# Добавляем путь к utils
sys.path.insert(0, os.path.dirname(__file__))
from utils.preprocess import decode_recursive


OUTPUT_DIR = "./BiLSTM"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_and_decode_dataset(path: str) -> tuple[np.ndarray, np.ndarray]:
    """Загружает датасет и рекурсивно декодирует тексты."""
    df = pd.read_csv(path)
    texts = df['text'].values
    labels = df['label'].values

    print(f"Загружено {len(texts)} примеров из {path}")
    print(f"  XSS={sum(labels)}, Benign={len(labels) - sum(labels)}")

    # Рекурсивное декодирование
    decoded_texts = []
    n_decoded = 0
    for text in texts:
        decoded = decode_recursive(str(text))
        if decoded != str(text):
            n_decoded += 1
        decoded_texts.append(decoded)

    print(f"  Декодировано (изменено): {n_decoded}/{len(texts)} ({100*n_decoded/len(texts):.1f}%)")
    return np.array(decoded_texts), labels


def build_bilstm_model(vocab_size: int = 10000, max_len: int = 200, embedding_dim: int = 64) -> Sequential:
    """Строит BiLSTM модель с улучшенной архитектурой."""
    model = Sequential([
        Embedding(vocab_size, embedding_dim, input_length=max_len),
        Bidirectional(LSTM(128, dropout=0.3, recurrent_dropout=0.2, return_sequences=True)),
        Bidirectional(LSTM(64, dropout=0.3, recurrent_dropout=0.2)),
        Dense(64, activation='relu'),
        Dropout(0.4),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid'),
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model


def plot_metrics(history, y_test, y_pred_prob, y_pred, output_dir: str):
    """Сохраняет графики обучения и матрицу ошибок."""
    # Кривые обучения
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].plot(history.history['accuracy'], label='Train acc')
    axes[0].plot(history.history['val_accuracy'], label='Val acc')
    axes[0].legend()
    axes[0].set_title('Accuracy')

    axes[1].plot(history.history['loss'], label='Train loss')
    axes[1].plot(history.history['val_loss'], label='Val loss')
    axes[1].legend()
    axes[1].set_title('Loss')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'bilstm_training_curves.png'), dpi=150)
    plt.close()

    # Матрица ошибок
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'XSS'], yticklabels=['Normal', 'XSS'])
    plt.title('BiLSTM (decoded) — Матрица ошибок')
    plt.ylabel('Истинный класс')
    plt.xlabel('Предсказанный класс')
    plt.savefig(os.path.join(output_dir, 'bilstm_confusion.png'), dpi=150)
    plt.close()

    # PR-кривая (важнее ROC для несбалансированных данных)
    precision, recall, _ = precision_recall_curve(y_test, y_pred_prob)
    pr_auc = auc(recall, precision)
    plt.figure(figsize=(6, 5))
    plt.plot(recall, precision, label=f'PR-AUC = {pr_auc:.4f}')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall кривая — BiLSTM (decoded)')
    plt.legend()
    plt.savefig(os.path.join(output_dir, 'bilstm_pr_curve.png'), dpi=150)
    plt.close()


def main():
    # === Загрузка и декодирование ===
    print("=" * 60)
    print("BiLSTM — обучение на декодированных данных")
    print("=" * 60)

    train_texts, train_labels = load_and_decode_dataset("./datasets_train/xss_dataset.csv")
    test_texts, test_labels = load_and_decode_dataset("./datasets_test/xss_dataset.csv")

    # === Токенизация ===
    MAX_LEN = 200
    VOCAB_SIZE = 10000

    tokenizer = Tokenizer(num_words=VOCAB_SIZE, oov_token='<OOV>')
    tokenizer.fit_on_texts(train_texts)

    X_train_seq = tokenizer.texts_to_sequences(train_texts)
    X_test_seq = tokenizer.texts_to_sequences(test_texts)

    X_train_pad = pad_sequences(X_train_seq, maxlen=MAX_LEN, padding='post', truncating='post')
    X_test_pad = pad_sequences(X_test_seq, maxlen=MAX_LEN, padding='post', truncating='post')

    print(f"Форма обучающих данных: {X_train_pad.shape}")
    print(f"Форма тестовых данных: {X_test_pad.shape}")

    # === Модель ===
    model = build_bilstm_model(VOCAB_SIZE, MAX_LEN)
    model.summary()

    # === Обучение ===
    early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
    checkpoint = ModelCheckpoint(
        os.path.join(OUTPUT_DIR, 'bilstm_decoded_best.h5'),
        monitor='val_accuracy', save_best_only=True
    )

    history = model.fit(
        X_train_pad, train_labels,
        epochs=15,
        batch_size=64,
        validation_split=0.2,
        callbacks=[early_stop, checkpoint],
        verbose=1,
    )

    # === Оценка на тесте ===
    print("\n" + "=" * 60)
    print("ОЦЕНКА НА ТЕСТОВОМ ДАТАСЕТЕ")
    print("=" * 60)

    y_pred_prob = model.predict(X_test_pad).flatten()
    y_pred = (y_pred_prob >= 0.5).astype(int)

    print(classification_report(test_labels, y_pred, target_names=['Normal', 'XSS']))
    print(f"AUC: {roc_auc_score(test_labels, y_pred_prob):.4f}")

    # PR-AUC
    precision_arr, recall_arr, _ = precision_recall_curve(test_labels, y_pred_prob)
    pr_auc = auc(recall_arr, precision_arr)
    print(f"PR-AUC: {pr_auc:.4f}")

    # TPR@1% FPR
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(test_labels, y_pred_prob)
    idx_1pct = np.searchsorted(fpr, 0.01)
    if idx_1pct < len(tpr):
        print(f"TPR@1%FPR: {tpr[idx_1pct]:.4f}")

    # === Сохранение ===
    plot_metrics(history, test_labels, y_pred_prob, y_pred, OUTPUT_DIR)

    model.save(os.path.join(OUTPUT_DIR, 'bilstm_decoded_model.h5'))
    joblib.dump(tokenizer, os.path.join(OUTPUT_DIR, 'bilstm_decoded_tokenizer.pkl'))
    print(f"\n✅ Модель и токенизатор сохранены в {OUTPUT_DIR}/")

    # === Тесты на обходах ===
    print("\n" + "=" * 60)
    print("ТЕСТЫ УСТОЙЧИВОСТИ К ОБХОДАМ")
    print("=" * 60)

    evasion_tests = [
        # Базовый XSS
        ("<script>alert('XSS')</script>", "Базовый script"),
        # URL-encoded
        ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL-encoded"),
        # Double URL-encoded
        ("%253Cscript%253Ealert('XSS')%253C/script%253E", "Double URL-encoded"),
        # HTML entities
        ("<script>alert('XSS')</script>", "HTML entities"),
        # Mixed case
        ("<ScRiPt>AlErT('XSS')</ScRiPt>", "Mixed case"),
        # Unicode
        ("\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e", "Unicode escape"),
        # Event handler
        ('<img src=x onerror="alert(1)">', "Event handler"),
        # Benign
        ("<div class='post'>Hello world</div>", "Benign HTML"),
        ("This is a normal comment about <script> tags", "Benign with keyword"),
    ]

    for text, label in evasion_tests:
        decoded = decode_recursive(text)
        seq = tokenizer.texts_to_sequences([decoded])
        padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
        prob = model.predict(padded, verbose=0)[0][0]
        verdict = "XSS" if prob >= 0.5 else "NORMAL"
        print(f"  [{verdict:>6}] prob={prob:.3f} | {label}: {text[:60]}")


if __name__ == "__main__":
    main()
