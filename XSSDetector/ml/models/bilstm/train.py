import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import sys
import argparse
import joblib
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Tuple

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

import tensorflow as tf
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.layers import Bidirectional, Dense, Dropout, Embedding, LSTM
from tensorflow.keras.models import Sequential
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer

from ml.paths import ARTIFACTS_DIR
from ml.features.preprocess import preprocess_for_sequence_model
from config import ModelConfig, DataConfig

# Импортируем общие модули
from ml.training.metrics import calculate_metrics, save_metrics_json, save_standard_plots
from ml.training.artifacts import create_run_directory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("XSSBiLSTMTrainer")

class DataPipeline:
    def __init__(self, config: ModelConfig):
        self.config = config
        self.tokenizer = Tokenizer(num_words=config.vocab_size, oov_token="<OOV>")

    @staticmethod
    def limit_samples(texts: List[str], labels: np.ndarray, limit: int, seed: int = 42) -> Tuple[List[str], np.ndarray]:
        if limit <= 0 or limit >= len(labels):
            return texts, labels
        rng = np.random.default_rng(seed)
        selected_indices = []
        unique_labels = np.unique(labels)
        per_class = max(1, limit // len(unique_labels))
        for label in unique_labels:
            indices = np.flatnonzero(labels == label)
            if len(indices) == 0: continue
            chosen = rng.choice(indices, size=min(per_class, len(indices)), replace=False)
            selected_indices.extend(chosen)
        selected_indices = np.asarray(selected_indices[:limit])
        rng.shuffle(selected_indices)
        return [texts[idx] for idx in selected_indices], labels[selected_indices]

    def _apply_recursive_decoding(self, texts: List[str]) -> List[str]:
        decoded_list = []
        n_changed = 0
        for text in texts:
            decoded = preprocess_for_sequence_model(str(text))
            if decoded != str(text): n_changed += 1
            decoded_list.append(decoded)
        logger.info(f"Рекурсивное декодирование: изменено {n_changed}/{len(texts)}")
        return decoded_list

    def prepare_data(self, unified_path: str):
        df = pd.read_csv(unified_path)
        train_df = df.sample(frac=0.8, random_state=self.config.seed)
        test_df = df.drop(train_df.index)

        train_texts = train_df["text"].astype(str).tolist()
        train_labels = train_df["label"].to_numpy(dtype=np.int32)
        test_texts = test_df["text"].astype(str).tolist()
        test_labels = test_df["label"].to_numpy(dtype=np.int32)

        train_texts, train_labels = self.limit_samples(train_texts, train_labels, self.config.max_train_samples, self.config.seed)
        test_texts, test_labels = self.limit_samples(test_texts, test_labels, self.config.max_test_samples, self.config.seed)

        train_texts = self._apply_recursive_decoding(train_texts)
        test_texts = self._apply_recursive_decoding(test_texts)

        self.tokenizer.fit_on_texts(train_texts)
        x_train_seq = self.tokenizer.texts_to_sequences(train_texts)
        x_test_seq = self.tokenizer.texts_to_sequences(test_texts)

        x_train_pad = pad_sequences(x_train_seq, maxlen=self.config.max_len, padding="post", truncating="post")
        x_test_pad = pad_sequences(x_test_seq, maxlen=self.config.max_len, padding="post", truncating="post")

        return x_train_pad, train_labels, x_test_pad, test_labels

class BiLSTMEngine:
    def __init__(self, config: ModelConfig):
        self.config = config
        self._init_hardware()
        self.model = self._build_architecture()

    def _init_hardware(self):
        gpus = tf.config.list_physical_devices('GPU')
        if gpus:
            try:
                for gpu in gpus: tf.config.experimental.set_memory_growth(gpu, True)
                logger.info(f"🖥️ Подключен GPU.")
            except RuntimeError as e:
                logger.error(f"Ошибка VRAM: {e}")

    def _build_architecture(self) -> Sequential:
        model = Sequential([
            Embedding(self.config.vocab_size, self.config.embedding_dim, input_length=self.config.max_len),
            Bidirectional(LSTM(128, dropout=0.3, return_sequences=True)),
            Bidirectional(LSTM(64, dropout=0.3)),
            Dense(64, activation="relu"), Dropout(0.4),
            Dense(32, activation="relu"), Dropout(0.3),
            Dense(1, activation="sigmoid"),
        ])
        model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
        return model

    def fit_and_evaluate(self, x_train, y_train, x_test, y_test, artifacts_dir: str):
        train_dataset = tf.data.Dataset.from_tensor_slices((x_train, y_train)).shuffle(1024).batch(self.config.batch_size).prefetch(tf.data.AUTOTUNE)
        validation_dataset = tf.data.Dataset.from_tensor_slices((x_test, y_test)).batch(self.config.batch_size).prefetch(tf.data.AUTOTUNE)

        callbacks = [
            EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True),
            ModelCheckpoint(filepath=str(self.config.model_path), monitor="val_accuracy", save_best_only=True)
        ]

        logger.info("Запуск обучения модели...")
        history = self.model.fit(train_dataset, epochs=self.config.epochs, validation_data=validation_dataset, callbacks=callbacks, verbose=1)

        # --- Использование общих модулей ---
        logger.info("Расчет предсказаний...")
        y_pred_prob = self.model.predict(x_test, batch_size=self.config.batch_size, verbose=0).flatten()
        y_pred = (y_pred_prob >= 0.5).astype(int)

        run_dir = create_run_directory(artifacts_dir, "bilstm")

        # Генерация всех графиков (включая кривые обучения благодаря history)
        save_standard_plots(y_test, y_pred, y_pred_prob, run_dir, history=history, model_name="BiLSTM")

        # Сохранение метрик
        metrics = calculate_metrics(y_test, y_pred, y_pred_prob)
        metrics.update({"model": "bilstm"})
        save_metrics_json(metrics, run_dir)

        logger.info(f"✅ Обучение завершено. Артефакты сохранены в {run_dir}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR))
    args = parser.parse_args()

    config = ModelConfig()
    pipeline = DataPipeline(config)
    engine = BiLSTMEngine(config)
    
    x_train, y_train, x_test, y_test = pipeline.prepare_data(args.dataset)
    engine.fit_and_evaluate(x_train, y_train, x_test, y_test, args.artifacts_dir)
    
    joblib.dump(pipeline.tokenizer, config.tokenizer_path)
    logger.info(f"Токенизатор сохранен в {config.tokenizer_path}")

if __name__ == "__main__":
    main()