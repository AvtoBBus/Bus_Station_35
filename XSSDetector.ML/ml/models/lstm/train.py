import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import sys
import argparse
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Bidirectional
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.model_selection import train_test_split

from config import ModelConfig, DataConfig
# Импортируем общие модули
from ml.paths import ARTIFACTS_DIR
from ml.training.metrics import calculate_metrics, save_metrics_json, save_standard_plots
from ml.training.artifacts import create_run_directory

tf.get_logger().setLevel('ERROR')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR))
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    print(f"Загрузка данных из {args.dataset}...")
    df = pd.read_csv(args.dataset)
    df = df.dropna(subset=[data_cfg.text_column, data_cfg.label_column])

    print("Балансировка датасета для ускорения обучения...")
    df_benign = df[df[data_cfg.label_column] == 0].sample(n=min(50000, len(df[df[data_cfg.label_column] == 0])), random_state=42)
    df_xss = df[df[data_cfg.label_column] == 1].sample(n=min(50000, len(df[df[data_cfg.label_column] == 1])), random_state=42)
    df = pd.concat([df_benign, df_xss]).sample(frac=1, random_state=42).reset_index(drop=True)

    texts = df[data_cfg.text_column].astype(str).tolist()
    labels = df[data_cfg.label_column].to_numpy(dtype=np.int32)

    X_train, X_val, y_train, y_val = train_test_split(
        texts, labels, test_size=model_cfg.test_size, random_state=42, stratify=labels
    )

    print("Токенизация текста...")
    tokenizer = Tokenizer(num_words=model_cfg.vocab_size, oov_token='<OOV>')
    tokenizer.fit_on_texts(X_train)

    X_train_seq = tokenizer.texts_to_sequences(X_train)
    X_val_seq = tokenizer.texts_to_sequences(X_val)

    X_train_pad = pad_sequences(X_train_seq, maxlen=model_cfg.max_len, padding='post', truncating='post')
    X_val_pad = pad_sequences(X_val_seq, maxlen=model_cfg.max_len, padding='post', truncating='post')

    print("Построение модели...")
    model = Sequential([
        Embedding(model_cfg.vocab_size, model_cfg.embedding_dim, input_length=model_cfg.max_len),
        Bidirectional(LSTM(model_cfg.lstm_units, dropout=model_cfg.dropout, recurrent_dropout=model_cfg.recurrent_dropout)),
        Dense(model_cfg.dense_units, activation='relu'),
        Dropout(model_cfg.dense_dropout),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    early_stop = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)
    checkpoint = ModelCheckpoint(str(model_cfg.model_path), monitor='val_accuracy', save_best_only=True)

    print("Начало обучения...")
    history = model.fit(
        X_train_pad, y_train,
        epochs=model_cfg.epochs,
        batch_size=model_cfg.batch_size,
        validation_data=(X_val_pad, y_val),
        callbacks=[early_stop, checkpoint],
        verbose=1
    )

    # Сохраняем токенизатор
    joblib.dump(tokenizer, model_cfg.tokenizer_path)
    print(f"💾 Модель сохранена в {model_cfg.model_path}")
    print(f"💾 Токенизатор сохранен в {model_cfg.tokenizer_path}")

    # --- ИСПОЛЬЗОВАНИЕ ОБЩИХ МОДУЛЕЙ ---
    y_proba = model.predict(X_val_pad, verbose=0).flatten()
    y_pred = (y_proba >= 0.5).astype(int)

    run_dir = create_run_directory(args.artifacts_dir, "lstm")
    
    # 1. Стандартные графики (матрица ошибок, ROC, кривые обучения)
    save_standard_plots(y_val, y_pred, y_proba, run_dir, history=history, model_name="LSTM")
    
    # 2. Метрики
    metrics = calculate_metrics(y_val, y_pred, y_proba)
    metrics.update({"model": "lstm", "dataset": args.dataset})
    save_metrics_json(metrics, run_dir)

    print(f"✅ Обучение завершено. Метрики сохранены в {run_dir}")

if __name__ == "__main__":
    main()