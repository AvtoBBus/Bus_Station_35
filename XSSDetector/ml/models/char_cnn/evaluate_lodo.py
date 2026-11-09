import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import sys
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent.parent))

from tensorflow.keras.callbacks import EarlyStopping

from ml.features.preprocess import classify_injection_context, context_one_hot, INJECTION_CONTEXTS
from ml.models.char_cnn.sequence import encode_texts
from ml.models.char_cnn.architecture import build_char_cnn
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
        
        train_texts = train_df['text'].astype(str).tolist()
        test_texts = test_df['text'].astype(str).tolist()
        y_train = train_df['label'].values
        y_test = test_df['label'].values
        
        x_train = encode_texts(train_texts, max_len=config.max_len)
        x_test = encode_texts(test_texts, max_len=config.max_len)
        
        c_train = np.asarray([context_one_hot(classify_injection_context(t)) for t in train_texts], dtype=np.float32)
        c_test = np.asarray([context_one_hot(classify_injection_context(t)) for t in test_texts], dtype=np.float32)
        
        model = build_char_cnn(
            max_len=config.max_len, embedding_dim=config.embedding_dim,
            context_dim=len(INJECTION_CONTEXTS), dropout=config.dropout
        )
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        
        model.fit(
            x=[x_train, c_train], y=y_train,
            epochs=5,
            batch_size=config.batch_size,
            validation_split=0.1,
            callbacks=[EarlyStopping(monitor='val_loss', patience=2, restore_best_weights=True)],
            verbose=0
        )
        
        y_proba = model.predict([x_test, c_test], verbose=0).flatten()
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
    print("\n=== Итоговая таблица LODO (CharCNN) ===")
    print(result_df.round(4))
    
    output_path = Path(args.output_dir) / "lodo_results_charcnn.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path)
    print(f"\nРезультаты сохранены в {output_path}")

if __name__ == "__main__":
    main()