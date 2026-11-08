# ==============================================================================
# СТРОГО ДО ВСЕХ ИМПОРТОВ: Блокируем предупреждения TensorFlow и oneDNN
# ==============================================================================
import os
import sys
import subprocess
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    auc, classification_report, confusion_matrix,
    precision_recall_curve, roc_auc_score, roc_curve,
)

import tensorflow as tf
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

import matplotlib
matplotlib.use("Agg")  # Headless-режим для защиты от зависания графического интерфейса
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
from utils.preprocess import preprocess_for_sequence_model, classify_injection_context, context_one_hot, INJECTION_CONTEXTS
from utils.char_sequence import encode_texts, VOCAB_SIZE
from utils.char_cnn import build_char_cnn

# Инициализация логирования промышленного стандарта
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("XSSCharCNNTrainer")


@dataclass
class ModelConfig:
    """Конфигурация гиперпараметров сверточной нейросети и путей экспорта."""
    # Ограничения под аппаратные ресурсы GTX 1650
    max_train_samples: int = 40000
    max_test_samples: int = 10000
    max_len: int = 64  # Оптимизировано с 256 до 64 (снижает вычислительную сложность)
    
    # Параметры архитектуры нейросети
    embedding_dim: int = 32
    dropout: float = 0.3
    
    # Настройки обучения графа
    epochs: int = 20
    batch_size: int = 64
    validation_split: float = 0.1
    seed: int = 42
    
    output_dir: Path = field(default_factory=lambda: Path("./CharCNN"))

    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)


class DataPipeline:
    """Компонент ETL: отвечает за очистку, сбалансированное сэмплирование и векторизацию контекстов."""
    def __init__(self, config: ModelConfig):
        self.config = config

    @staticmethod
    def limit_samples(texts: List[str], labels: np.ndarray, limit: int, seed: int = 42) -> Tuple[List[str], np.ndarray]:
        """Формирует сбалансированное подмножество данных (50/50) для защиты от смещения градиента."""
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

    def _build_context_matrix(self, texts: List[str]) -> np.ndarray:
        """Создает матрицу контекстов инъекции в формате One-Hot Encoding."""
        return np.asarray(
            [context_one_hot(classify_injection_context(str(t))) for t in texts],
            dtype=np.float32,
        )

    def prepare_multimodal_data(self, unified_path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Полный цикл подготовки текстовых последовательностей и матриц контекста."""
        if not unified_path.exists():
            raise FileNotFoundError(f"Критическая ошибка: Исходный файл не найден по пути {unified_path}")

        df = pd.read_csv(unified_path)
        logger.info(f"Успешно загружено {len(df)} строк датасета.")

        # Разделение выборки на Train / Test (80 / 20)
        train_df = df.sample(frac=0.8, random_state=self.config.seed)
        test_df = df.drop(train_df.index)

        train_texts = train_df["text"].astype(str).tolist()
        train_labels = train_df["label"].to_numpy(dtype=np.int32)
        test_texts = test_df["text"].astype(str).tolist()
        test_labels = test_df["drop_label" if "drop_label" in test_df else "label"].to_numpy(dtype=np.int32)

        # Выравнивание дисбаланса классов
        train_texts, train_labels = self.limit_samples(train_texts, train_labels, self.config.max_train_samples, self.config.seed)
        test_texts, test_labels = self.limit_samples(test_texts, test_labels, self.config.max_test_samples, self.config.seed)

        logger.info(f"Размер сбалансированной Train выборки: {len(train_texts)} объектов")
        logger.info(f"Размер сбалансированной Test выборки:  {len(test_texts)} объектов")

        # Векторизация текстового канала (символьный уровень)
        x_train = encode_texts(train_texts, max_len=self.config.max_len)
        x_test = encode_texts(test_texts, max_len=self.config.max_len)

        # Векторизация контекстного канала
        c_train = self._build_context_matrix(train_texts)
        c_test = self._build_context_matrix(test_texts)

        return x_train, c_train, train_labels, x_test, c_test, test_labels


class CharCNNEngine:
    """Вычислительный движок: инициализация GPU, сборка мультимодальной сети и генерация SecOps метрик."""
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
        """Динамическое распределение памяти видеокарты ноутбука."""
        gpus = tf.config.list_physical_devices('GPU')
        if gpus:
            try:
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
                logger.info(f"🖥️ Аппаратный ускоритель GPU подключен. Доступно ядер CUDA: {len(gpus)}")
            except RuntimeError as e:
                logger.error(f"Сбой конфигурации памяти GPU: {e}")
        else:
            logger.warning("⚠️ CUDA-ускорители не обнаружены. Расчеты переведены на CPU.")

    def fit_and_evaluate(self, x_train: np.ndarray, c_train: np.ndarray, y_train: np.ndarray, 
                         x_test: np.ndarray, c_test: np.ndarray, y_test: np.ndarray):
        """Запуск цикла оптимизации весов сверточной сети с коллбеками."""
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True, verbose=1),
            ModelCheckpoint(
                filepath=str(self.config.output_dir / 'charcnn_decoded_best.keras'),
                monitor='val_accuracy',
                save_best_only=True,
                verbose=1
            )
        ]

        logger.info("Компиляция графа и запуск обучения Char-CNN (model.fit)...")
        history = self.model.fit(
            x=[x_train, c_train],
            y=y_train,
            epochs=self.config.epochs,
            batch_size=self.config.batch_size,
            validation_split=self.config.validation_split,
            callbacks=callbacks,
            verbose=1,
        )

        self._evaluate_performance(x_test, c_test, y_test, history)

    def _evaluate_performance(self, x_test: np.ndarray, c_test: np.ndarray, y_test: np.ndarray, history):
        """Комплексная оценка качества и расчет уровня TPR@1%FPR."""
        logger.info("Расчет вероятностей на тестовом множестве...")
        y_pred_prob = self.model.predict([x_test, c_test], batch_size=self.config.batch_size, verbose=0).flatten()
        y_pred = (y_pred_prob >= 0.5).astype(int)

        print("\n" + "=" * 60)
        print("ОЦЕНКА НА ТЕСТОВОМ ДАТАСЕТЕ")
        print("=" * 60)
        print(classification_report(y_test, y_pred, target_names=['Normal', 'XSS']))
        
        fpr, tpr, _ = roc_curve(y_test, y_pred_prob)
        precision_arr, recall_arr, _ = precision_recall_curve(y_test, y_pred_prob)
        pr_auc_score = auc(recall_arr, precision_arr)

        logger.info(f"Финальный ROC-AUC Score: {roc_auc_score(y_test, y_pred_prob):.4f}")
        logger.info(f"Финальный PR-AUC Score:  {pr_auc_score:.4f}")

        idx_1pct = np.searchsorted(fpr, 0.01)
        if idx_1pct < len(tpr):
            logger.info(f"Уровень обнаружения атак при 1% ложных срабатываний (TPR@1%FPR): {tpr[idx_1pct]:.4f}")

        # Генерация отчетных графиков для дипломной работы
        self._generate_plots(history, y_test, y_pred)

    def _generate_plots(self, history, y_true, y_pred):
        """Сохранение графиков метрик в каталог артефактов."""
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        axes[0].plot(history.history['accuracy'], label='Train acc')
        axes[0].plot(history.history['val_accuracy'], label='Val acc')
        axes[0].legend()
        axes[0].set_title('Кривая Точности (Accuracy)')
        axes[0].grid(True, alpha=0.3)

        axes[1].plot(history.history['loss'], label='Train loss')
        axes[1].plot(history.history['val_loss'], label='Val loss')
        axes[1].legend()
        axes[1].set_title('Кривая Функции Потерь (Loss)')
        axes[1].grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.config.output_dir / 'charcnn_training_curves.png', dpi=150)
        plt.close()

        # Матрица ошибок (Confusion Matrix)
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
                plt.savefig(self.config.output_dir / 'charcnn_confusion.png', dpi=150)
                plt.close()
                logger.info(f"Визуализация метрик успешно сохранена в папку {self.config.output_dir}")
    def run_evasion_tests(self):
        """Интеграционное тестирование устойчивости сверточных фильтров к обфускации."""
        print("\n" + "=" * 60)
        print("ТЕСТЫ УСТОЙЧИВОСТИ К ОБХОДАМ (EVASION ATTACKS)")
        print("=" * 60)
        evasion_tests = [
            ("alert('XSS')", "Базовый script"),
            ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL-encoded"),
            ("%253Cscript%253Ealert('XSS')%253C/script%253E", "Double URL-encoded"),
            ("AlErT('XSS')", "Mixed case"),
            ("\u003cscript\u003ealert('XSS')\u003c/script\u003e", "Unicode escape"),
            ('', "Event handler"),
            ("Hello world", "Benign HTML"),
            ("This is a normal comment about  tags", "Benign with keyword"),
            ("javascript:alert(document.cookie)", "JS pseudo-protocol"),
            ("", "SVG onload"),
            ("", "Body onload"),
        ]
        for text, label in evasion_tests:
            processed = preprocess_for_sequence_model(text)
            tokens = encode_texts([processed], max_len=self.config.max_len)
            # Генерация точечной строки для извлечения One-Hot матрицы контекста
            context = np.asarray(
            [context_one_hot(classify_injection_context(processed))],
            dtype=np.float32
            )
            prob = float(self.model.predict([tokens, context], verbose=0)[0, 0])
            verdict = "XSS" if prob >= 0.5 else "NORMAL"
            print(f"  [{verdict:>6}] prob={prob:.3f} | {label}: {text[:60]}")

def main():
    subprocess.run(["cls" if os.name == "nt" else "clear"], shell=True)
    config = ModelConfig()
    unified_dataset_path = Path(__file__).resolve().parent / "data" / "processed" / "unified_dataset.csv"
    try:
        # Инициализация модулей
        pipeline = DataPipeline(config)
        engine = CharCNNEngine(config)
        # Выполнение препроцессинга мультимодальных признаков
        x_train, c_train, y_train, x_test, c_test, y_test = pipeline.prepare_multimodal_data(unified_dataset_path)
        # Обучение и расчет финальных метрик
        engine.fit_and_evaluate(x_train, c_train, y_train, x_test, c_test, y_test)
        # Сохранение весов и метаданных конфигурации
        engine.model.save(config.output_dir / 'charcnn_xss.keras')
        meta_config = {
            'max_len': config.max_len,
            'context_dim': len(INJECTION_CONTEXTS),
            'embedding_dim': config.embedding_dim,
            'dropout': config.dropout
        }
        (config.output_dir / 'charcnn_config.json').write_text(json.dumps(meta_config, indent=2), encoding='utf-8')
        logger.info(f"Сериализация артефактов Char-CNN успешно завершена.")
        # Тестирование на устойчивость
        engine.run_evasion_tests()
    except FileNotFoundError as e:
        logger.error(e)
        print("   Сделайте препроцессинг данных: python xssdetector/data/scripts/normalize_datasets.py")
    except Exception as e:
        logger.critical(f"Критический сбой пайплайна моделирования: {e}", exc_info=True)

if __name__ == "__main__":
    main()