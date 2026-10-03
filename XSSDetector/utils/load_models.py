from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from tensorflow import keras
from .extract_features import extract_features
from .preprocess import decode_recursive
from catboost import CatBoostClassifier, Pool

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = {
    'catboost': BASE_DIR / 'CatBoost',
    'rf': BASE_DIR / 'RandomForest',
    'lr': BASE_DIR / 'LogisticRegression',
    'svm': BASE_DIR / 'SVM',
    'lstm': BASE_DIR / 'LSTM',
    'transformer': BASE_DIR / 'Transformer',
}

THRESHOLD_DEFAULT = 0.35

#######################################################
############# ешированные модели (загрузка 1 раз) ####
#######################################################

_catboost_model = None
_catboost_metadata = None
_rf_model = None
_lr_model = None
_lr_scaler = None
_svm_model = None
_svm_scaler = None
_lstm_model = None
_lstm_tokenizer = None
_lstm_max_len = 200
_transformer_model = None
_transformer_tokenizer = None
_transformer_max_len = 256


def _ensure_catboost():
    global _catboost_model, _catboost_metadata
    if _catboost_model is None:
        _catboost_model = CatBoostClassifier()
        cb_dir = MODEL_DIR['catboost']
        _catboost_model.load_model(str(cb_dir / 'catboost_xss_model.cbm'))
        _catboost_metadata = joblib.load(str(cb_dir / 'model_metadata.pkl'))
    return _catboost_model, _catboost_metadata


def _ensure_rf():
    global _rf_model
    if _rf_model is None:
        rf_dir = MODEL_DIR['rf']
        _rf_model = joblib.load(str(rf_dir / 'random_forest_xss.pkl'))
    return _rf_model


def _ensure_lr():
    global _lr_model, _lr_scaler
    if _lr_model is None:
        lr_dir = MODEL_DIR['lr']
        _lr_model = joblib.load(str(lr_dir / 'logistic_regression_xss.pkl'))
        _lr_scaler = joblib.load(str(lr_dir / 'lr_scaler.pkl'))
    return _lr_model, _lr_scaler


def _ensure_svm():
    global _svm_model, _svm_scaler
    if _svm_model is None:
        svm_dir = MODEL_DIR['svm']
        _svm_model = joblib.load(str(svm_dir / 'svm_rbf_xss.pkl'))
        _svm_scaler = joblib.load(str(svm_dir / 'svm_scaler.pkl'))
    return _svm_model, _svm_scaler


def _ensure_lstm():
    global _lstm_model, _lstm_tokenizer
    if _lstm_model is None:
        lstm_dir = MODEL_DIR['lstm']
        _lstm_model = keras.models.load_model(str(lstm_dir / 'lstm_xss_model.h5'))
        _lstm_tokenizer = joblib.load(str(lstm_dir / 'lstm_tokenizer.pkl'))
    return _lstm_model, _lstm_tokenizer


def _ensure_transformer():
    global _transformer_model, _transformer_tokenizer, _transformer_max_len
    if _transformer_model is None:
        transformer_dir = MODEL_DIR['transformer']
        model_dir = transformer_dir / 'best_model'
        weights_path = model_dir / 'model.safetensors'
        if not weights_path.is_file():
            raise FileNotFoundError(f'Local Transformer weights not found: {weights_path}')
        with weights_path.open('rb') as weights_file:
            if weights_file.read(80).startswith(b'version https://git-lfs.github.com/spec/v1'):
                raise RuntimeError(
                    'Local Transformer weights are a Git LFS pointer, not the model file.'
                )

        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        _transformer_model = AutoModelForSequenceClassification.from_pretrained(
            str(model_dir), local_files_only=True
        )
        _transformer_tokenizer = AutoTokenizer.from_pretrained(
            str(transformer_dir / 'tokenizer'), local_files_only=True
        )
        _transformer_model.to('cpu')
        _transformer_model.eval()
        max_positions = getattr(_transformer_model.config, 'max_position_embeddings', 512)
        _transformer_max_len = min(256, int(max_positions))
    return _transformer_model, _transformer_tokenizer


def load_transformer():
    return _ensure_transformer(), _transformer_max_len


def load_catboost():
    return _ensure_catboost()


def predict_catboost(code, threshold=THRESHOLD_DEFAULT):
    model, metadata = _ensure_catboost()
    decoded = decode_recursive(code)
    features_df = pd.DataFrame([extract_features(decoded)])

    expected_features = metadata['feature_names']
    for feature in expected_features:
        if feature not in features_df.columns:
            features_df[feature] = 0

    features_df = features_df[expected_features]

    cat_features = metadata.get('cat_features', [])
    for col in cat_features:
        if col in features_df.columns:
            features_df[col] = features_df[col].astype('category')

    text_features = ['text'] if 'text' in features_df.columns else None
    cat_feature_names = metadata.get('cat_features', [])
    pool = Pool(
        features_df,
        feature_names=list(features_df.columns),
        cat_features=cat_feature_names,
        text_features=text_features,
    )
    proba = model.predict_proba(pool)[0][1]
    pred = proba >= threshold
    return bool(pred), float(proba)

def load_random_forest():
    return _ensure_rf()


def predict_rf(code, threshold=THRESHOLD_DEFAULT):
    model = _ensure_rf()
    decoded = decode_recursive(code)
    features = extract_features(decoded, False)
    features_df = pd.DataFrame([features])
    proba = model.predict_proba(features_df)[0, 1]
    pred = proba >= threshold
    return pred, proba


def load_logistic_regression():
    return _ensure_lr()


def predict_lr(code, threshold=THRESHOLD_DEFAULT):
    lr, scaler = _ensure_lr()
    decoded = decode_recursive(code)
    features = extract_features(decoded, False)
    features_df = pd.DataFrame([features])
    features_scaled = scaler.transform(features_df)
    proba = lr.predict_proba(features_scaled)[0, 1]
    pred = proba >= threshold
    return pred, proba


def load_svm():
    return _ensure_svm()


def predict_svm(code, threshold=THRESHOLD_DEFAULT):
    svm, scaler = _ensure_svm()
    decoded = decode_recursive(code)
    features = extract_features(decoded, False)
    features_df = pd.DataFrame([features])
    features_scaled = scaler.transform(features_df)
    proba = svm.predict_proba(features_scaled)[0, 1]
    pred = proba >= threshold
    return pred, proba


def load_lstm():
    return _ensure_lstm(), _lstm_max_len


def predict_lstm(code, max_len=None, threshold=THRESHOLD_DEFAULT):
    if max_len is None:
        max_len = _lstm_max_len
    lstm_model, tokenizer = _ensure_lstm()
    seq = tokenizer.texts_to_sequences([code])
    padded = keras.preprocessing.sequence.pad_sequences(
        seq, maxlen=max_len, padding='post', truncating='post'
    )
    proba = lstm_model.predict(padded, verbose=0)[0, 0]
    pred = proba >= threshold
    return pred, float(proba)


def predict_transformer(code, threshold=THRESHOLD_DEFAULT):
    model, tokenizer = _ensure_transformer()
    try:
        import torch
    except ImportError as error:
        raise RuntimeError(
            'Transformer inference requires the project torch and transformers dependencies.'
        ) from error

    decoded = decode_recursive(code)
    inputs = tokenizer(
        decoded,
        return_tensors='pt',
        truncation=True,
        max_length=_transformer_max_len,
        padding='max_length',
    )
    with torch.no_grad():
        logits = model(**inputs).logits
        probability = torch.softmax(logits, dim=-1)[0, 1].item()
    return probability >= threshold, float(probability)


def warm_up_models():
    """редзагрузка всех моделей при старте приложения."""
    print('⏳ агрузка моделей...')
    _ensure_catboost()
    print('  ✅ CatBoost')
    _ensure_rf()
    print('  ✅ Random Forest')
    _ensure_lr()
    print('  ✅ Logistic Regression')
    _ensure_svm()
    print('  ✅ SVM')
    _ensure_lstm()
    print('  ✅ LSTM')
    try:
        _ensure_transformer()
        print('  Transformer ready')
    except Exception as error:
        print(f'  Transformer unavailable: {error}')
    print('✅ се модели загружены')
