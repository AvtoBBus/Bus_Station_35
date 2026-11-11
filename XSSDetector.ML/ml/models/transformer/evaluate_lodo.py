import os
import sys
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

import datasets
datasets.config.TORCHVISION_AVAILABLE = False

import torch
from datasets import Dataset
from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast, Trainer, TrainingArguments

from ml.paths import RESULTS_DIR
from ml.features.preprocess import preprocess_for_sequence_model
from config import ModelConfig, DataConfig
# Импорт единого калькулятора
from ml.training.metrics import calculate_metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default=str(RESULTS_DIR))
    args = parser.parse_args()

    config = ModelConfig()
    df = pd.read_csv(args.dataset)
    
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    
    source_names = ['fwaf', 'csic2010', 'kaggle', 'vulnxss', 'httpparams']
    results = {}
    
    for test_source in source_names:
        if test_source not in df['source'].unique(): continue
        print(f"\n===== Тестируем на {test_source} =====")
        
        test_mask = (df['source'] == test_source)
        train_df = df.drop(df[test_mask].index)
        test_df = df[test_mask]
        
        train_df = train_df.sample(n=min(len(train_df), config.max_train_samples), random_state=config.seed)
        test_df = test_df.sample(n=min(len(test_df), config.max_test_samples), random_state=config.seed)
        
        train_texts = [preprocess_for_sequence_model(str(t)) for t in train_df['text']]
        test_texts = [preprocess_for_sequence_model(str(t)) for t in test_df['text']]
        y_train = train_df['label'].values
        y_test = test_df['label'].values
        
        train_ds = Dataset.from_dict({"text": train_texts, "label": y_train.tolist()})
        test_ds = Dataset.from_dict({"text": test_texts, "label": y_test.tolist()})
        
        def tokenize_fn(examples):
            return tokenizer(examples["text"], truncation=True, padding="max_length", max_length=config.max_len)
            
        train_ds = train_ds.map(tokenize_fn, batched=True, batch_size=256)
        test_ds = test_ds.map(tokenize_fn, batched=True, batch_size=256)
        train_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
        test_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
        
        model = DistilBertForSequenceClassification.from_pretrained("distilbert-base-uncased", num_labels=2)
        
        training_args = TrainingArguments(
            output_dir=str(Path(args.output_dir) / f"tmp_{test_source}"),
            num_train_epochs=1.0, 
            per_device_train_batch_size=config.train_batch_size,
            per_device_eval_batch_size=config.eval_batch_size,
            report_to="none", fp16=torch.cuda.is_available(), dataloader_num_workers=0
        )
        
        trainer = Trainer(model=model, args=training_args, train_dataset=train_ds, eval_dataset=test_ds)
        trainer.train()
        
        predictions = trainer.predict(test_ds)
        probs = torch.softmax(torch.tensor(predictions.predictions), dim=-1).numpy()[:, 1]
        preds = (probs >= 0.5).astype(int)
        
        # Использование единого калькулятора метрик
        metrics = calculate_metrics(y_test, preds, probs)
        
        results[test_source] = {
            'roc_auc': metrics['roc_auc'],
            'pr_auc': metrics['pr_auc'],
            'f1': metrics['f1_score'],
            'accuracy': metrics['accuracy'],
            'tpr@1%fpr': metrics['tpr_at_1pct_fpr']
        }
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}")

    result_df = pd.DataFrame(results).T
    print("\n=== Итоговая таблица LODO (Transformer) ===")
    print(result_df.round(4))
    
    output_path = Path(args.output_dir) / "lodo_results_transformer.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path)
    print(f"\nРезультаты сохранены в {output_path}")

if __name__ == "__main__":
    main()