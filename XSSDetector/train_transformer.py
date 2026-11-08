import logging
import os
import sys
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

import datasets
import numpy as np
import pandas as pd
from datasets import Dataset
from sklearn.metrics import auc, classification_report, precision_recall_curve, roc_auc_score, roc_curve
import torch
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    Trainer,
    TrainingArguments,
)
from transformers.trainer_utils import EvalPrediction

# Отключаем попытки использовать torchvision
datasets.config.TORCHVISION_AVAILABLE = False

sys.path.insert(0, os.path.dirname(__file__))
from utils.preprocess import preprocess_for_sequence_model

# Настройка логирования уровня Enterprise
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("XSSDistilBertTrainer")


@dataclass
class ModelConfig:
    """Конфигурация гиперпараметров и путей для обучения."""
    # Ограничения выборок для GTX 1650
    max_train_samples: int = 40000
    max_test_samples: int = 10000
    max_len: int = 64
    
    # Гиперпараметры обучения
    num_epochs: float = 3.0
    train_batch_size: int = 16
    eval_batch_size: int = 64
    gradient_accumulation_steps: int = 2
    seed: int = 42
    
    # Пути
    output_dir: Path = field(default_factory=lambda: Path("./Transformer"))

    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)


class DataProcessor:
    """Отвечает за загрузку, балансировку и токенизацию датасета."""
    def __init__(self, config: ModelConfig, tokenizer: DistilBertTokenizerFast):
        self.config = config
        self.tokenizer = tokenizer

    @staticmethod
    def limit_samples(texts: List[str], labels: np.ndarray, limit: int, seed: int = 42) -> Tuple[List[str], np.ndarray]:
        """Сбалансированное сэмплирование данных по классам (50/50)."""
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

    def _tokenize_fn(self, examples: Dict) -> Dict:
        return self.tokenizer(
            examples["text"], 
            truncation=True, 
            padding="max_length", 
            max_length=self.config.max_len
        )

    def prepare_datasets(self, unified_path: Path) -> Tuple[Dataset, Dataset, np.ndarray]:
        """Полный пайплайн подготовки данных."""
        if not unified_path.exists():
            raise FileNotFoundError(f"Критическая ошибка: Файл датасета не найден по пути {unified_path}")

        df = pd.read_csv(unified_path)
        logger.info(f"Загружено {len(df)} строк из исходного датасета.")

        # Разделение выборки (80 / 20)
        train_df = df.sample(frac=0.8, random_state=self.config.seed)
        test_df = df.drop(train_df.index)

        train_texts = train_df["text"].astype(str).tolist()
        train_labels = train_df["label"].to_numpy(dtype=np.int32)
        test_texts = test_df["text"].astype(str).tolist()
        test_labels = test_df["label"].to_numpy(dtype=np.int32)

        # Применение сбалансированного сэмплирования
        train_texts, train_labels = self.limit_samples(train_texts, train_labels, self.config.max_train_samples, self.config.seed)
        test_texts, test_labels = self.limit_samples(test_texts, test_labels, self.config.max_test_samples, self.config.seed)

        logger.info(f"Train выборка после балансировки: {len(train_texts)} объектов")
        logger.info(f"Test выборка после балансировки: {len(test_texts)} объектов")

        train_ds = Dataset.from_dict({"text": train_texts, "label": train_labels.tolist()})
        test_ds = Dataset.from_dict({"text": test_texts, "label": test_labels.tolist()})

        # Токенизация данных
        train_ds = train_ds.map(self._tokenize_fn, batched=True, batch_size=256, desc="Токенизация Train")
        test_ds = test_ds.map(self._tokenize_fn, batched=True, batch_size=256, desc="Токенизация Test")

        columns = ["input_ids", "attention_mask", "label"]
        train_ds.set_format("torch", columns=columns)
        test_ds.set_format("torch", columns=columns)

        return train_ds, test_ds, test_labels


class TransformerTrainer:
    """Основной оркестратор процессов инициализации, обучения и валидации модели."""
    def __init__(self, config: ModelConfig):
        self.config = config
        self._init_environment()
        
        self.local_tokenizer_path = Path(__file__).resolve().parent / "Transformer" / "tokenizer"
        self.local_model_path = Path(__file__).resolve().parent / "Transformer" / "best_model"

        self.tokenizer = DistilBertTokenizerFast.from_pretrained(str(self.local_tokenizer_path), local_files_only=True)
        self.model = DistilBertForSequenceClassification.from_pretrained(
            str(self.local_model_path),
            local_files_only=True,
            num_labels=2,
            id2label={0: "NORMAL", 1: "XSS"},
            label2id={"NORMAL": 0, "XSS": 1},
        )

    def _init_environment(self):
        """Логирование конфигурации железа и очистка памяти."""
        if torch.cuda.is_available():
            p = torch.cuda.get_device_properties(0)
            logger.info(f"🖥️ Обнаружено CUDA устройство: {p.name} ({p.total_memory/1e9:.1f} GB VRAM)")
            torch.cuda.empty_cache()
        else:
            logger.warning("⚠️ CUDA недоступна. Выполнение будет переведено на CPU (Крайне медленно!)")

    @staticmethod
    def compute_metrics(eval_pred: EvalPrediction) -> Dict[str, float]:
        """Расчет расширенных метрик классификации."""
        logits, labels = eval_pred
        probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()[:, 1]
        preds = (probs >= 0.5).astype(int)
        
        return {
            "accuracy": float((preds == labels).mean()),
            "auc": float(roc_auc_score(labels, probs))
        }

    def train_and_evaluate(self, train_ds: Dataset, test_ds: Dataset, test_labels: np.ndarray):
        """Запуск цикла обучения Hugging Face Trainer."""
        # Отключаем fp16 для видеокарт уровня GTX 1650 (ускорения не дает, но жрет память / может баговать)
        use_fp16 = torch.cuda.is_available() and not ("1650" in torch.cuda.get_device_name(0) if torch.cuda.is_available() else False)

        training_args = TrainingArguments(
            output_dir=str(self.config.output_dir / "checkpoints"),
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.train_batch_size,
            per_device_eval_batch_size=self.config.eval_batch_size,
            gradient_accumulation_steps=self.config.gradient_accumulation_steps,
            warmup_steps=500,
            weight_decay=0.01,
            logging_strategy="steps",
            logging_steps=100,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            report_to="none",
            fp16=use_fp16,
            dataloader_num_workers=0,  # Защита от дедлоков в Windows
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=test_ds,
            compute_metrics=self.compute_metrics,
        )

        logger.info("Запуск процедуры циклического обучения (trainer.train())...")
        trainer.train()

        self._run_final_evaluation(trainer, test_ds, test_labels)
        self._save_artifacts()

    def _run_final_evaluation(self, trainer: Trainer, test_ds: Dataset, test_labels: np.ndarray):
        """Инференс на тестовом подмножестве с расчетом SecOps метрик."""
        logger.info("Расчет финальных метрик на отложенной выборке...")
        predictions = trainer.predict(test_ds)
        probs = torch.softmax(torch.tensor(predictions.predictions), dim=-1).numpy()[:, 1]
        preds = (probs >= 0.5).astype(int)

        print("\n" + "=" * 60)
        print("ОЦЕНКА НА ТЕСТОВОМ ДАТАСЕТЕ")
        print("=" * 60)
        print(classification_report(test_labels, preds, target_names=["Normal", "XSS"]))
        
        fpr, tpr, _ = roc_curve(test_labels, probs)
        precision_arr, recall_arr, _ = precision_recall_curve(test_labels, probs)
        
        logger.info(f"Финальный ROC-AUC Score: {roc_auc_score(test_labels, probs):.4f}")
        logger.info(f"Финальный PR-AUC Score:  {auc(recall_arr, precision_arr):.4f}")

        idx_1pct = np.searchsorted(fpr, 0.01)
        if idx_1pct < len(tpr):
            logger.info(f"Уровень детекции при 1% False Positive Rate (TPR@1%FPR): {tpr[idx_1pct]:.4f}")

    def _save_artifacts(self):
        """Сохранение обученных весов и конфигурации токенизатора."""
        best_model_dir = self.config.output_dir / "best_model"
        tokenizer_dir = self.config.output_dir / "tokenizer"

        self.model.save_pretrained(str(best_model_dir))
        self.tokenizer.save_pretrained(str(tokenizer_dir))
        logger.info(f"Компоненты модели успешно сериализованы в {self.config.output_dir}")

    def run_evasion_tests(self):
        """Интеграционное стресс-тестирование модели на устойчивость к обфускации."""
        print("\n" + "=" * 60)
        print("ТЕСТ УСТОЙЧИВОСТИ К ОБХОДАМ (EVASION ATTACKS)")
        print("=" * 60)
        evasion_tests = [
            ("alert('XSS')", "Базовый script"),
            ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL-encoded"),
            ("%253Cscript%253Ealert('XSS')%253C/script%253E", "Double URL-encoded"),
            ("alert('XSS')", "HTML entities"),
            ("AlErT('XSS')", "Mixed case"),
            ("\u003cscript\u003ealert('XSS')\u003c/script\u003e", "Unicode escape"),
            ('', "Event handler"),
            ("Hello world", "Benign HTML"),
            ("This is a normal comment about  tags", "Benign with keyword"),
            ("javascript:alert(document.cookie)", "JS pseudo-protocol"),
        ]
        self.model.eval()

        for text, label in evasion_tests:
            decoded = preprocess_for_sequence_model(text)
            inputs = self.tokenizer(decoded, return_tensors="pt", truncation=True, max_length=self.config.max_len)
            # Перенос тензоров на активный девайс модели
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}
            with torch.no_grad():
                logits = self.model(**inputs).logits
                prob = torch.softmax(logits, dim=-1)[0][1].item()
                verdict = "XSS" if prob >= 0.5 else "NORMAL"
                print(f"  [{verdict:>6}] prob={prob:.3f} | {label}: {text[:60]}")

def main():
    config = ModelConfig()
    unified_dataset_path = Path(__file__).resolve().parent / 'data' / 'processed' / 'unified_dataset.csv'
    try:
    # Инициализация пайплайна
        trainer_orchestrator = TransformerTrainer(config)
        data_processor = DataProcessor(config, trainer_orchestrator.tokenizer)
        # Обработка данных
        train_ds, test_ds, test_labels = data_processor.prepare_datasets(unified_dataset_path)
        # Обучение и валидация
        trainer_orchestrator.train_and_evaluate(train_ds, test_ds, test_labels)
        # Интеграционный тест безопасности
        trainer_orchestrator.run_evasion_tests()
    except FileNotFoundError as e:
        logger.error(e)
        print("   Убедитесь, что запущен скрипт нормализации данных:")
        print("   python xssdetector/data/scripts/normalize_datasets.py")
    except Exception as e:
        logger.critical(f"Непредвиденный сбой выполнения пайплайна: {str(e)}", exc_info=True)

if __name__ == "__main__":
    subprocess.run(["cls" if os.name == "nt" else "clear"], shell=True)
    os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    main()