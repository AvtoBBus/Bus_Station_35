import os
import sys
import logging
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

import datasets
datasets.config.TORCHVISION_AVAILABLE = False

import torch
from datasets import Dataset
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    Trainer,
    TrainingArguments,
)
from transformers.trainer_utils import EvalPrediction
from sklearn.metrics import roc_auc_score

from ml.paths import ARTIFACTS_DIR
from ml.features.preprocess import preprocess_for_sequence_model
from config import ModelConfig, DataConfig

# Импортируем общие модули
from ml.training.metrics import calculate_metrics, save_metrics_json, save_standard_plots
from ml.training.artifacts import create_run_directory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("XSSDistilBertTrainer")

class DataProcessor:
    def __init__(self, config: ModelConfig, tokenizer: DistilBertTokenizerFast):
        self.config = config
        self.tokenizer = tokenizer

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

    def _tokenize_fn(self, examples: Dict) -> Dict:
        return self.tokenizer(examples["text"], truncation=True, padding="max_length", max_length=self.config.max_len)

    def prepare_datasets(self, unified_path: str):
        df = pd.read_csv(unified_path)
        train_df = df.sample(frac=0.8, random_state=self.config.seed)
        test_df = df.drop(train_df.index)

        train_texts = train_df["text"].astype(str).tolist()
        train_labels = train_df["label"].to_numpy(dtype=np.int32)
        test_texts = test_df["text"].astype(str).tolist()
        test_labels = test_df["label"].to_numpy(dtype=np.int32)

        train_texts, train_labels = self.limit_samples(train_texts, train_labels, self.config.max_train_samples, self.config.seed)
        test_texts, test_labels = self.limit_samples(test_texts, test_labels, self.config.max_test_samples, self.config.seed)

        train_texts = [preprocess_for_sequence_model(t) for t in train_texts]
        test_texts = [preprocess_for_sequence_model(t) for t in test_texts]

        train_ds = Dataset.from_dict({"text": train_texts, "label": train_labels.tolist()})
        test_ds = Dataset.from_dict({"text": test_texts, "label": test_labels.tolist()})

        train_ds = train_ds.map(self._tokenize_fn, batched=True, batch_size=256, desc="Токенизация Train")
        test_ds = test_ds.map(self._tokenize_fn, batched=True, batch_size=256, desc="Токенизация Test")

        columns = ["input_ids", "attention_mask", "label"]
        train_ds.set_format("torch", columns=columns)
        test_ds.set_format("torch", columns=columns)

        return train_ds, test_ds, test_labels

def compute_metrics(eval_pred: EvalPrediction) -> Dict[str, float]:
    logits, labels = eval_pred
    probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()[:, 1]
    preds = (probs >= 0.5).astype(int)
    return {"accuracy": float((preds == labels).mean()), "auc": float(roc_auc_score(labels, probs))}

def extract_hf_history(log_history):
    """Адаптер для преобразования логов HF Trainer в формат, понятный save_standard_plots."""
    history = {'loss': [], 'val_loss': [], 'accuracy': [], 'val_accuracy': []}
    for log in log_history:
        if 'loss' in log: history['loss'].append(log['loss'])
        if 'eval_loss' in log: history['val_loss'].append(log['eval_loss'])
        if 'eval_accuracy' in log: history['val_accuracy'].append(log['eval_accuracy'])
    return history

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR))
    args = parser.parse_args()

    config = ModelConfig()
    
    use_fp16 = torch.cuda.is_available() and not ("1650" in torch.cuda.get_device_name(0) if torch.cuda.is_available() else False)
    
    # Загрузка токенизатора и модели
    model_path = str(config.model_dir) if config.model_dir.exists() and any(config.model_dir.iterdir()) else "distilbert-base-uncased"
    tokenizer_path = str(config.tokenizer_dir) if config.tokenizer_dir.exists() and any(config.tokenizer_dir.iterdir()) else "distilbert-base-uncased"
    
    tokenizer = DistilBertTokenizerFast.from_pretrained(tokenizer_path)
    model = DistilBertForSequenceClassification.from_pretrained(
        model_path, num_labels=2, id2label={0: "NORMAL", 1: "XSS"}, label2id={"NORMAL": 0, "XSS": 1}
    )

    processor = DataProcessor(config, tokenizer)
    train_ds, test_ds, test_labels = processor.prepare_datasets(args.dataset)

    run_dir = create_run_directory(args.artifacts_dir, "transformer")
    
    training_args = TrainingArguments(
        output_dir=str(run_dir / "checkpoints"),
        num_train_epochs=config.num_epochs,
        per_device_train_batch_size=config.train_batch_size,
        per_device_eval_batch_size=config.eval_batch_size,
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        warmup_steps=500, weight_decay=0.01, logging_strategy="steps", logging_steps=100,
        eval_strategy="epoch", save_strategy="epoch", load_best_model_at_end=True,
        metric_for_best_model="eval_loss", greater_is_better=False, report_to="none",
        fp16=use_fp16, dataloader_num_workers=0,
    )

    trainer = Trainer(model=model, args=training_args, train_dataset=train_ds, eval_dataset=test_ds, compute_metrics=compute_metrics)

    logger.info("Запуск обучения...")
    trainer.train()

    # Финальная оценка
    predictions = trainer.predict(test_ds)
    probs = torch.softmax(torch.tensor(predictions.predictions), dim=-1).numpy()[:, 1]
    preds = (probs >= 0.5).astype(int)

    # --- ИСПОЛЬЗОВАНИЕ ОБЩИХ МОДУЛЕЙ ---
    history = extract_hf_history(trainer.state.log_history)
    
    # Графики
    save_standard_plots(test_labels, preds, probs, run_dir, history=history, model_name="Transformer")
    
    # Метрики
    metrics = calculate_metrics(test_labels, preds, probs)
    metrics.update({"model": "transformer", "dataset": args.dataset})
    save_metrics_json(metrics, run_dir)

    # Сохранение модели и токенизатора для serving
    model.save_pretrained(str(config.model_dir))
    tokenizer.save_pretrained(str(config.tokenizer_dir))
    logger.info(f"✅ Обучение завершено. Модель в {config.model_dir}, артефакты в {run_dir}")

if __name__ == "__main__":
    main()