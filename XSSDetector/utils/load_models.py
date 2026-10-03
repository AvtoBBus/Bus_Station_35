import joblib
import numpy as np
import pandas as pd
from tensorflow import keras
from .extract_features import extract_features
from .preprocess import decode_recursive
from catboost import CatBoostClassifier, Pool

THRESHLOD_DEFAULT = 0.35

#######################################################
############# Кешированные модели (загрузка 1 раз) ####
#######################################################

# Загружаем все модели при старте приложения (один раз)
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


def _ensure_catboost():
    global _catboost_model, _catboost_metadata
    if _catboost_model is None:
        _catboost_model = CatBoostClassifier()
        _catboost_model.load_model("./CatBoost/catboost_xss_model.cbm")
        _catboost_metadata = joblib.load("./CatBoost/model_metadata.pkl")
    return _catboost_model, _catboost_metadata


def _ensure_rf():
    global _rf_model
    if _rf_model is None:
        _rf_model = joblib.load("./RandomForest/random_forest_xss.pkl")
    return _rf_model


def _ensure_lr():
    global _lr_model, _lr_scaler
    if _lr_model is None:
        _lr_model = joblib.load("./LogisticRegression/logistic_regression_xss.pkl")
        _lr_scaler = joblib.load("./LogisticRegression/lr_scaler.pkl")
    return _lr_model, _lr_scaler


def _ensure_svm():
    global _svm_model, _svm_scaler
    if _svm_model is None:
        _svm_model = joblib.load("./SVM/svm_rbf_xss.pkl")
        _svm_scaler = joblib.load("./SVM/svm_scaler.pkl")
    return _svm_model, _svm_scaler


def _ensure_lstm():
    global _lstm_model, _lstm_tokenizer
    if _lstm_model is None:
        _lstm_model = keras.models.load_model("./LSTM/lstm_xss_model.h5")
        _lstm_tokenizer = joblib.load("./LSTM/lstm_tokenizer.pkl")
    return _lstm_model, _lstm_tokenizer


#######################################################
#################### CatBoost #########################
#######################################################

def load_catboost():
    return _ensure_catboost()

def predict_catboost(code, threshold=THRESHLOD_DEFAULT):
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

    proba = model.predict_proba(features_df)[0][1]
    pred = proba >= threshold
    return bool(pred), float(proba)


#######################################################
################# Random Forest #######################
#######################################################

def load_random_forest():
    return _ensure_rf()

def predict_rf(code, threshold=THRESHLOD_DEFAULT):
    model = _ensure_rf()
    decoded = decode_recursive(code)
    features = extract_features(decoded, False)
    features_df = pd.DataFrame([features])
    proba = model.predict_proba(features_df)[0, 1]
    pred = proba >= threshold
    return pred, proba


#######################################################
############## Logistic Regression ####################
#######################################################

def load_logistic_regression():
    return _ensure_lr()

def predict_lr(code, threshold=THRESHLOD_DEFAULT):
    lr, scaler = _ensure_lr()
    decoded = decode_recursive(code)
    features = extract_features(decoded, False)
    features_df = pd.DataFrame([features])
    features_scaled = scaler.transform(features_df)
    proba = lr.predict_proba(features_scaled)[0, 1]
    pred = proba >= threshold
    return pred, proba


#######################################################
###################### SVM ############################
#######################################################

def load_svm():
    return _ensure_svm()

def predict_svm(code, threshold=THRESHLOD_DEFAULT):
    svm, scaler = _ensure_svm()
    decoded = decode_recursive(code)
    features = extract_features(decoded, False)
    features_df = pd.DataFrame([features])
    features_scaled = scaler.transform(features_df)
    proba = svm.predict_proba(features_scaled)[0, 1]
    pred = proba >= threshold
    return pred, proba


#######################################################
##################### LSTM ############################
#######################################################

def load_lstm():
    return _ensure_lstm(), _lstm_max_len

def predict_lstm(code, max_len=None, threshold=THRESHLOD_DEFAULT):
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


def warm_up_models():
    """Предзагрузка всех моделей при старте приложения."""
    print("⏳ Загрузка моделей...")
    _ensure_catboost()
    print("  ✅ CatBoost")
    _ensure_rf()
    print("  ✅ Random Forest")
    _ensure_lr()
    print("  ✅ Logistic Regression")
    _ensure_svm()
    print("  ✅ SVM")
    _ensure_lstm()
    print("  ✅ LSTM")
    print("✅ Все модели загружены")
