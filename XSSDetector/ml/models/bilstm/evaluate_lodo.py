import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Bidirectional, LSTM, Dense, Dropout, Embedding
from tensorflow.keras.callbacks import EarlyStopping

from ml.features.preprocess import preprocess_for_sequence_model
from config import ModelConfig, DataConfig
# Импорт единого калькулятора
from ml.training.metrics import calculate_metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default="XSSDetector/results")
    args = parser.parse_args()

    config = ModelConfig()
    df = pd.read_csv(args.dataset)
    
    source_names = ['fwaf', 'csic2010', 'kaggle', 'vulnxss', 'httpparams']
    results = {}
    
    for test_source in source_names:
        if test_source not in df['source'].unique(): continue
        print(f"\n===== Тестируем на {test_source} =====")
        
        test_mask = (df['source'] == test_source)
        train_df = df[~test_mask]
        test_df = df[test_mask]
        
        train_texts = [preprocess_for_sequence_model(str(t)) for t in train_df['text']]
        test_texts = [preprocess_for_sequence_model(str(t)) for t in test_df['text']]
        y_train = train_df['label'].values
        y_test = test_df['label'].values
        
        tokenizer = Tokenizer(num_words=config.vocab_size, oov_token='<OOV>')
        tokenizer.fit_on_texts(train_texts)
        
        x_train_pad = pad_sequences(tokenizer.texts_to_sequences(train_texts), maxlen=config.max_len, padding='post', truncating='post')
        x_test_pad = pad_sequences(tokenizer.texts_to_sequences(test_texts), maxlen=config.max_len, padding='post', truncating='post')
        
        model = Sequential([
            Embedding(config.vocab_size, config.embedding_dim, input_length=config.max_len),
            Bidirectional(LSTM(128, dropout=0.3, return_sequences=True)),
            Bidirectional(LSTM(64, dropout=0.3)),
            Dense(64, activation="relu"), Dropout(0.4),
            Dense(32, activation="relu"), Dropout(0.3),
            Dense(1, activation="sigmoid"),
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        
        model.fit(
            x_train_pad, y_train, 
            epochs=3, 
            batch_size=config.batch_size,
            validation_split=0.2,
            callbacks=[EarlyStopping(monitor='val_loss', patience=2, restore_best_weights=True)],
            verbose=0
        )
        
        y_proba = model.predict(x_test_pad, verbose=0).flatten()
        y_pred = (y_proba >= 0.5).astype(int)
        
        # Использование единого калькулятора метрик
        metrics = calculate_metrics(y_test, y_pred, y_proba)
        
        results[test_source] = {
            'roc_auc': metrics['roc_auc'],
            'pr_auc': metrics['pr_auc'],
            'f1': metrics['f1_score'],
            'accuracy': metrics['accuracy'],
            'tpr@1%fpr': metrics['tpr_at_1pct_fpr']
        }
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}")

    result_df = pd.DataFrame(results).T
    print("\n=== Итоговая таблица LODO (BiLSTM) ===")
    print(result_df.round(4))
    
    output_path = Path(args.output_dir) / "lodo_results_bilstm.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path)
    print(f"\nРезультаты сохранены в {output_path}")

if __name__ == "__main__":
    main()