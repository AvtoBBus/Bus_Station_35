# ==============================================================================
# СТРОГО ДО ВСЕХ ИМПОРТОВ: Отключаем спам и настраиваем девайсы
# ==============================================================================
import os
import sys
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple
import subprocess

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    auc, classification_report, confusion_matrix,
    precision_recall_curve, roc_auc_score, roc_curve,
)

import tensorflow as tf
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.layers import Bidirectional, Dense, Dropout, Embedding, LSTM
from tensorflow.keras.models import Sequential
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer

import matplotlib
matplotlib.use("Agg")  # Headless-режим для предотвращения зависания GUI
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.dirname(__file__))
from utils.preprocess import decode_recursive, preprocess_for_sequence_model

# Инициализация логгера уровня Enterprise
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("XSSBiLSTMTrainer")


@dataclass
class ModelConfig:
    """Конфигурация гиперпараметров модели и путей сборки пайплайна."""
    # Ограничения выборок под VRAM GTX 1650
    max_train_samples: int = 40000
    max_test_samples: int = 10000
    max_len: int = 64  # Сокращено с 200 до 64 (оптимально для XSS векторов)
    vocab_size: int = 10000
    embedding_dim: int = 64
    
    # Конфигурация обучения
    epochs: int = 10
    batch_size: int = 64
    seed: int = 42
    
    output_dir: Path = field(default_factory=lambda: Path("./BiLSTM"))

    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)


class DataPipeline:
    """Компонент ETL: отвечает за очистку, балансировку и векторизацию текстовых данных."""
    def __init__(self, config: ModelConfig):
        self.config = config
        self.tokenizer = Tokenizer(num_words=config.vocab_size, oov_token="<OOV>")

    @staticmethod
    def limit_samples(texts: List[str], labels: np.ndarray, limit: int, seed: int = 42) -> Tuple[List[str], np.ndarray]:
        """Обеспечивает сбалансированное распределение классов (50/50) внутри выборки."""
        if limit <= 0 or limit >= len(labels):
            return texts, labels

        rng = np.random.default_rng(seed)
        selected_indices = []
        unique_labels = np.unique(labels)
        per_class = max(1, limit // len(unique_labels))

        for label in unique_labels:
            indices = np.flatnonzero(labels == label)
            if len(indices) == 0:
                continue
            chosen = rng.choice(indices, size=min(per_class, len(indices)), replace=False)
            selected_indices.extend(chosen)

        selected_indices = np.asarray(selected_indices[:limit])
        rng.shuffle(selected_indices)
        
        return [texts[idx] for idx in selected_indices], labels[selected_indices]

    def _apply_recursive_decoding(self, texts: List[str]) -> List[str]:
        """Внутренний маппинг нормализации текстов."""
        decoded_list = []
        n_changed = 0
        for text in texts:
            decoded = preprocess_for_sequence_model(str(text))
            if decoded != str(text):
                n_changed += 1
            decoded_list.append(decoded)
        
        logger.info(f"Рекурсивное декодирование завершено. Изменено объектов: {n_changed}/{len(texts)}")
        return decoded_list

    def prepare_data(self, unified_path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Загрузка, балансировка и векторизация сырых данных в тензоры."""
        if not unified_path.exists():
            raise FileNotFoundError(f"Файл датасета не обнаружен по пути: {unified_path}")

        df = pd.read_csv(unified_path)
        logger.info(f"Загружено {len(df)} строк из исходного объединенного датасета.")

        # Разделение 80/20
        train_df = df.sample(frac=0.8, random_state=self.config.seed)
        test_df = df.drop(train_df.index)

        train_texts = train_df["text"].astype(str).tolist()
        train_labels = train_df["label"].to_numpy(dtype=np.int32)
        test_texts = test_df["text"].astype(str).tolist()
        test_labels = test_df["label"].to_numpy(dtype=np.int32)

        # Вызов сбалансированного сэмплирования
        train_texts, train_labels = self.limit_samples(train_texts, train_labels, self.config.max_train_samples, self.config.seed)
        test_texts, test_labels = self.limit_samples(test_texts, test_labels, self.config.max_test_samples, self.config.seed)

        # Декодирование
        logger.info("Старт декодирования Train выборки...")
        train_texts = self._apply_recursive_decoding(train_texts)
        logger.info("Старт декодирования Test выборки...")
        test_texts = self._apply_recursive_decoding(test_texts)

        # Обучение токенизатора
        self.tokenizer.fit_on_texts(train_texts)

        # Конвертация текстов в индексы токенов
        x_train_seq = self.tokenizer.texts_to_sequences(train_texts)
        x_test_seq = self.tokenizer.texts_to_sequences(test_texts)

        # Паддинг векторов до фиксированной длины
        x_train_pad = pad_sequences(x_train_seq, maxlen=self.config.max_len, padding="post", truncating="post")
        x_test_pad = pad_sequences(x_test_seq, maxlen=self.config.max_len, padding="post", truncating="post")

        return x_train_pad, train_labels, x_test_pad, test_labels


class BiLSTMEngine:
    """Архитектурный компонент нейросети: сборка графа, обучение и построение графиков."""
    def __init__(self, config: ModelConfig):
        self.config = config
        self._init_hardware()
        self.model = self._build_architecture()

    def _init_hardware(self):
        """Проверка доступности ядер CUDA."""
        gpus = tf.config.list_physical_devices('GPU')
        if gpus:
            try:
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
                logger.info(f"🖥️ TensorFlow успешно подключил GPU ускоритель. Доступно карт: {len(gpus)}")
            except RuntimeError as e:
                logger.error(f"Ошибка настройки VRAM: {e}")
        else:
            logger.warning("⚠️ Видеокарта не обнаружена. Обучение будет идти на CPU.")

    def _build_architecture(self) -> Sequential:
        """Инициализация слоев глубокой нейросети BiLSTM."""
        logger.info("Компиляция архитектурного графа BiLSTM...")
        model = Sequential([
            Embedding(self.config.vocab_size, self.config.embedding_dim, input_length=self.config.max_len),
            # Слой рекуррентного дропаута убран для утилизации CUDA ядер (cuDNN) на GTX 1650
            Bidirectional(LSTM(128, dropout=0.3, return_sequences=True)),
            Bidirectional(LSTM(64, dropout=0.3)),
            Dense(64, activation="relu"),
            Dropout(0.4),
            Dense(32, activation="relu"),
            Dropout(0.3),
            Dense(1, activation="sigmoid"),
        ])
        model.compile(
            optimizer="adam",
            loss="binary_crossentropy",
            metrics=["accuracy"]
        )
        return model

    def fit_and_evaluate(self, x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray):
        """Запуск высокопроизводительного пайплайна tf.data с последующим обучением графа."""
        # Создание оптимизированных датасетов для GPU инференса
        train_dataset = tf.data.Dataset.from_tensor_slices((x_train, y_train))
        train_dataset = train_dataset.shuffle(buffer_size=1024).batch(self.config.batch_size).prefetch(tf.data.AUTOTUNE)

        validation_dataset = tf.data.Dataset.from_tensor_slices((x_test, y_test))
        validation_dataset = validation_dataset.batch(self.config.batch_size).prefetch(tf.data.AUTOTUNE)

        callbacks = [
            EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True),
            ModelCheckpoint(
                filepath=str(self.config.output_dir / "bilstm_decoded_best.h5"),
                monitor="val_accuracy",
                save_best_only=True
            )
        ]

        logger.info("Запуск обучения модели (model.fit)...")
        history = self.model.fit(
            train_dataset,
            epochs=self.config.epochs,
            validation_data=validation_dataset,
            callbacks=callbacks,
            verbose=1
        )

        self._evaluate_performance(x_test, y_test, history)

    def _evaluate_performance(self, x_test: np.ndarray, y_test: np.ndarray, history):
        """Инференс и генерация продуктовых метрик ИБ."""
        logger.info("Расчет предсказаний на тестовом подмножестве...")
        y_pred_prob = self.model.predict(x_test, batch_size=self.config.batch_size, verbose=0).flatten()
        y_pred = (y_pred_prob >= 0.5).astype(int)

        print("\n" + "=" * 60)
        print("ОЦЕНКА НА ТЕСТОВОМ ДАТАСЕТЕ")
        print("=" * 60)
        print(classification_report(y_test, y_pred, target_names=["Normal", "XSS"]))
        
        # Расчет векторов метрик безопасности
        fpr, tpr, _ = roc_curve(y_test, y_pred_prob)
        precision, recall, _ = precision_recall_curve(y_test, y_pred_prob)
        pr_auc_score = auc(recall, precision)

        logger.info(f"Финальный ROC-AUC: {roc_auc_score(y_test, y_pred_prob):.4f}")
        logger.info(f"Финальный PR-AUC:  {pr_auc_score:.4f}")

        idx_1pct = np.searchsorted(fpr, 0.01)
        if idx_1pct < len(tpr):
            logger.info(f"Уровень обнаружения угроз при 1% FPR (TPR@1%FPR): {tpr[idx_1pct]:.4f}")
            # Отрисовка графиков
            self._generate_plots(history, y_test, y_pred_prob, y_pred, pr_auc_score)
        
    def _generate_plots(self, history, y_test, y_pred_prob, y_pred, pr_auc: float):
        """Сериализация графиков обучения."""
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        axes[0].plot(history.history["accuracy"], label="Train acc")
        axes[0].plot(history.history["val_accuracy"], label="Val acc")
        axes[0].legend()
        axes[0].set_title("Кривая Точности (Accuracy)")
        axes[1].plot(history.history["loss"], label="Train loss")
        axes[1].plot(history.history["val_loss"], label="Val loss")
        axes[1].legend()
        axes[1].set_title("Кривая Функции Потерь (Loss)")
        plt.tight_layout()
        plt.savefig(self.config.output_dir / "bilstm_training_curves.png", dpi=150)
        plt.close()
        # Матрица ошибок
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Normal", "XSS"], yticklabels=["Normal", "XSS"])
        plt.title("Матрица Ошибок классификации")
        plt.ylabel("Истинный класс")
        plt.xlabel("Предсказанный класс")
        plt.savefig(self.config.output_dir / "bilstm_confusion.png", dpi=150)
        plt.close()

    def run_evasion_tests(self, tokenizer: Tokenizer):
        """Интеграционные тесты на обход WAF обфусцированными нагрузками."""
        print("\n" + "=" * 60)
        print("ТЕСТЫ УСТОЙЧИВОСТИ К ОБХОДАМ")
        print("=" * 60)
        evasion_tests = [
            ("alert('XSS')", "Базовый script"),
            ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL-encoded"),
            ("%253Cscript%253Ealert('XSS')%253C/script%253E", "Double URL-encoded"),
            ("<script>alert('XSS')</script>", "HTML entities"),
            ("AlErT('XSS')", "Mixed case"),
            ("\u003cscript\u003ealert('XSS')\u003c/script\u003e", "Unicode escape"),
            ('', "Event handler"),
            ("Hello world", "Benign HTML"),
            ("This is a normal comment about  tags", "Benign with keyword"),
            ("javascript:alert(document.cookie)", "JS pseudo-protocol"),
        ]
        for text, label in evasion_tests:
            decoded = decode_recursive(text)
            seq = tokenizer.texts_to_sequences([decoded])
            padded = pad_sequences(seq, maxlen=self.config.max_len, padding="post", truncating="post")
            prob = self.model.predict(padded, verbose=0)[0][0]
            verdict = "XSS" if prob >= 0.5 else "NORMAL"
            print(f"  [{verdict:>6}] prob={prob:.3f} | {label}: {text[:60]}")

def main():
    config = ModelConfig()
    unified_dataset_path = Path(__file__).resolve().parent / "data" / "processed" / "unified_dataset.csv"
    try:
        # Инициализация пайплайнов обработки и моделирования
        pipeline = DataPipeline(config)
        engine = BiLSTMEngine(config)
        # Выполнение ETL
        x_train, y_train, x_test, y_test = pipeline.prepare_data(unified_dataset_path)
        # Обучение и финальный инференс
        engine.fit_and_evaluate(x_train, y_train, x_test, y_test)
        # Сериализация артефактов
        engine.model.save(config.output_dir / "bilstm_decoded_model.h5")
        joblib.dump(pipeline.tokenizer, config.output_dir / "bilstm_decoded_tokenizer.pkl")
        logger.info(f"Веса модели и файлы токенизатора экспортированы в папку {config.output_dir}")
        # Интеграционный тест устойчивости
        engine.run_evasion_tests(pipeline.tokenizer)
    except FileNotFoundError as e:
        logger.error(e)
        print("   Сделайте препроцессинг данных: python xssdetector/data/scripts/normalize_datasets.py")
    except Exception as e:
        logger.critical(f"Критический сбой пайплайна: {e}", exc_info=True)

if __name__ == "__main__":
    subprocess.run(["cls" if os.name == "nt" else "clear"], shell=True)
    main()