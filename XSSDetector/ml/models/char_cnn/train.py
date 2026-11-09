import os
import sys
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import json
import logging
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Tuple

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

import tensorflow as tf
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

from ml.features.preprocess import preprocess_for_sequence_model, classify_injection_context, context_one_hot, INJECTION_CONTEXTS
from ml.models.char_cnn.sequence import encode_texts
from ml.models.char_cnn.architecture import build_char_cnn
from config import ModelConfig, DataConfig

# Импортируем общие модули
from ml.training.metrics import calculate_metrics, save_metrics_json, save_standard_plots
from ml.training.artifacts import create_run_directory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("XSSCharCNNTrainer")

class DataPipeline:
    def __init__(self, config: ModelConfig):
        self.config = config

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

    def _build_context_matrix(self, texts: List[str]) -> np.ndarray:
        return np.asarray([context_one_hot(classify_injection_context(str(t))) for t in texts], dtype=np.float32)

    def prepare_multimodal_data(self, unified_path: str):
        df = pd.read_csv(unified_path)
        train_df = df.sample(frac=0.8, random_state=self.config.seed)
        test_df = df.drop(train_df.index)

        train_texts = train_df["text"].astype(str).tolist()
        train_labels = train_df["label"].to_numpy(dtype=np.int32)
        test_texts = test_df["text"].astype(str).tolist()
        test_labels = test_df["drop_label" if "drop_label" in test_df else "label"].to_numpy(dtype=np.int32)

        train_texts, train_labels = self.limit_samples(train_texts, train_labels, self.config.max_train_samples, self.config.seed)
        test_texts, test_labels = self.limit_samples(test_texts, test_labels, self.config.max_test_samples, self.config.seed)

        x_train = encode_texts(train_texts, max_len=self.config.max_len)
        x_test = encode_texts(test_texts, max_len=self.config.max_len)

        c_train = self._build_context_matrix(train_texts)
        c_test = self._build_context_matrix(test_texts)

        return x_train, c_train, train_labels, x_test, c_test, test_labels

class CharCNNEngine:
    def __init__(self, config: ModelConfig):
        self.config = config
        self._init_hardware()
        self.model = build_char_cnn(
            max_len=self.config.max_len,
            embedding_dim=self.config.embedding_dim,
            context_dim=len(INJECTION_CONTEXTS),
            dropout=self.config.dropout,
        )

    def _init_hardware(self):
        gpus = tf.config.list_physical_devices('GPU')
        if gpus:
            try:
                for gpu in gpus: tf.config.experimental.set_memory_growth(gpu, True)
                logger.info(f"🖥️ GPU подключен.")
            except RuntimeError as e:
                logger.error(f"Сбой GPU: {e}")

    def fit_and_evaluate(self, x_train, c_train, y_train, x_test, c_test, y_test, artifacts_dir: str):
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True, verbose=1),
            ModelCheckpoint(filepath=str(self.config.model_path), monitor='val_accuracy', save_best_only=True, verbose=1)
        ]

        history = self.model.fit(
            x=[x_train, c_train], y=y_train,
            epochs=self.config.epochs, batch_size=self.config.batch_size,
            validation_split=self.config.validation_split,
            callbacks=callbacks, verbose=1,
        )

        # --- Использование общих модулей ---
        logger.info("Расчет предсказаний...")
        y_pred_prob = self.model.predict([x_test, c_test], batch_size=self.config.batch_size, verbose=0).flatten()
        y_pred = (y_pred_prob >= 0.5).astype(int)

        run_dir = create_run_directory(artifacts_dir, "char_cnn")

        # Графики
        save_standard_plots(y_test, y_pred, y_pred_prob, run_dir, history=history, model_name="CharCNN")

        # Метрики
        metrics = calculate_metrics(y_test, y_pred, y_pred_prob)
        metrics.update({"model": "char_cnn"})
        save_metrics_json(metrics, run_dir)

        logger.info(f"✅ Обучение завершено. Артефакты сохранены в {run_dir}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--artifacts-dir", default="XSSDetector/ml/artifacts")
    args = parser.parse_args()

    config = ModelConfig()
    pipeline = DataPipeline(config)
    engine = CharCNNEngine(config)
    
    x_train, c_train, y_train, x_test, c_test, y_test = pipeline.prepare_multimodal_data(args.dataset)
    engine.fit_and_evaluate(x_train, c_train, y_train, x_test, c_test, y_test, args.artifacts_dir)
    
    meta_config = {
        'max_len': config.max_len,
        'context_dim': len(INJECTION_CONTEXTS),
        'embedding_dim': config.embedding_dim,
        'dropout': config.dropout
    }
    config.meta_path.write_text(json.dumps(meta_config, indent=2), encoding='utf-8')
    logger.info(f"Модель сохранена в {config.model_path}")

if __name__ == "__main__":
    main()