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
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Bidirectional
from tensorflow.keras.callbacks import EarlyStopping

from config import ModelConfig, DataConfig
# Импорт единого калькулятора
from ml.training.metrics import calculate_metrics

tf.get_logger().setLevel('ERROR')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DataConfig().dataset_path)
    parser.add_argument("--output-dir", default="XSSDetector/results")
    args = parser.parse_args()

    model_cfg = ModelConfig()
    data_cfg = DataConfig()

    print(f"Загрузка {args.dataset}...")
    df = pd.read_csv(args.dataset)
    
    source_names = ['fwaf', 'csic2010', 'kaggle', 'vulnxss', 'httpparams']
    results = {}
    
    for test_source in source_names:
        if test_source not in df['source'].unique(): continue
        print(f"\n===== Тестируем на {test_source} =====")
        
        test_mask = (df['source'] == test_source)
        if not test_mask.any(): continue

        texts_train = df.loc[~test_mask, data_cfg.text_column].values
        texts_test = df.loc[test_mask, data_cfg.text_column].values
        y_train = df.loc[~test_mask, data_cfg.label_column].values
        y_test = df.loc[test_mask, data_cfg.label_column].values
        
        tokenizer = Tokenizer(num_words=model_cfg.vocab_size, oov_token='<OOV>')
        tokenizer.fit_on_texts(texts_train)
        
        X_train_seq = tokenizer.texts_to_sequences(texts_train)
        X_test_seq = tokenizer.texts_to_sequences(texts_test)
        
        X_train_pad = pad_sequences(X_train_seq, maxlen=model_cfg.max_len, padding='post', truncating='post')
        X_test_pad = pad_sequences(X_test_seq, maxlen=model_cfg.max_len, padding='post', truncating='post')
        
        model = Sequential([
            Embedding(model_cfg.vocab_size, model_cfg.embedding_dim, input_length=model_cfg.max_len),
            Bidirectional(LSTM(model_cfg.lstm_units, dropout=model_cfg.dropout, recurrent_dropout=model_cfg.recurrent_dropout)),
            Dense(model_cfg.dense_units, activation='relu'),
            Dropout(model_cfg.dense_dropout),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        early_stop = EarlyStopping(monitor='val_loss', patience=2, restore_best_weights=True)
        
        # В LODO ноутбуке epochs=3
        model.fit(
            X_train_pad, y_train,
            epochs=3, 
            batch_size=model_cfg.batch_size,
            validation_split=0.2,
            callbacks=[early_stop],
            verbose=0
        )
        
        y_proba = model.predict(X_test_pad, verbose=0).flatten()
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
        print(f"ROC-AUC: {metrics['roc_auc']:.4f}, F1: {metrics['f1_score']:.4f}")

    result_df = pd.DataFrame(results).T
    print("\n=== Итоговая таблица LODO (LSTM) ===")
    print(result_df.round(4))
    
    output_path = Path(args.output_dir) / "lodo_results_lstm.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path)
    print(f"\nРезультаты сохранены в {output_path}")

if __name__ == "__main__":
    main()