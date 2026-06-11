import joblib
import numpy as np
import pandas as pd
from tensorflow import keras
from .extract_features import extract_features
from catboost import CatBoostClassifier, Pool

THRESHLOD_DEFAULT = 0.35

#######################################################
#################### CatBoost #########################
#######################################################

def load_catboost(
        model_path="./CatBoost/catboost_xss_model.cbm",
        metadata_path="./CatBoost/model_metadata.pkl"
):
    model = CatBoostClassifier()
    model.load_model(model_path)
    metadata = joblib.load(metadata_path)
    return model, metadata

def predict_catboost(code):
    model, metadata = load_catboost()
    features_df = pd.DataFrame([extract_features(code)])

    expected_features = metadata['feature_names']
    for feature in expected_features:
        if feature not in features_df.columns:
            features_df[feature] = 0  # Заполняем недостающие нулями

    features_df = features_df[expected_features]

    cat_features = metadata.get('cat_features', [])
    for col in cat_features:
        if col in features_df.columns:
            features_df[col] = features_df[col].astype('category')

    return bool(model.predict(features_df)[0]), model.predict_proba(features_df)[0][1]
    

#######################################################
################# Random Forest #######################
#######################################################

def load_random_forest(model_path="./RandomForest/random_forest_xss.pkl"):
    """Загружает модель Random Forest"""
    rf = joblib.load(model_path)
    return rf

def predict_rf(code, threshold=THRESHLOD_DEFAULT):
    """Предсказание для одной строки кода"""
    features = extract_features(code, False)
    features_df = pd.DataFrame([features])
    proba = load_random_forest().predict_proba(features_df)[0, 1]
    pred = proba >= threshold
    return pred, proba

#######################################################
############## Logistic Regression ####################
#######################################################

def load_logistic_regression(model_path="./LogisticRegression/logistic_regression_xss.pkl", 
                              scaler_path="./LogisticRegression/lr_scaler.pkl"):
    """Загружает модель LR и scaler"""
    lr = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    return lr, scaler

def predict_lr(code, threshold=THRESHLOD_DEFAULT):
    """Предсказание с масштабированием"""
    features = extract_features(code, False)
    features_df = pd.DataFrame([features])
    lr, scaler = load_logistic_regression()
    features_scaled = scaler.transform(features_df)
    proba = lr.predict_proba(features_scaled)[0, 1]
    pred = proba >= threshold
    return pred, proba

#######################################################
###################### SVM ############################
#######################################################

def load_svm(model_path="./SVM/svm_rbf_xss.pkl", scaler_path="./SVM/svm_scaler.pkl"):
    """Загружает модель SVM и scaler"""
    svm = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    return svm, scaler

def predict_svm(code, threshold=THRESHLOD_DEFAULT):
    """Предсказание SVM"""
    features = extract_features(code, False)
    features_df = pd.DataFrame([features])
    svm, scaler = load_svm()
    features_scaled = scaler.transform(features_df)
    proba = svm.predict_proba(features_scaled)[0, 1]
    pred = proba >= threshold
    return pred, proba

#######################################################
##################### LSTM ############################
#######################################################

def load_lstm(model_path="./LSTM/lstm_xss_model.h5", tokenizer_path="./LSTM/lstm_tokenizer.pkl", max_len=200):
    """Загружает модель LSTM и токенизатор"""
    model = keras.models.load_model(model_path)
    tokenizer = joblib.load(tokenizer_path)
    return model, tokenizer, max_len

def predict_lstm(code, max_len=200, threshold=THRESHLOD_DEFAULT):
    """Предсказание LSTM (работает с сырым текстом)"""
    
    lstm_model, tokenizer, _ = load_lstm()
    seq = tokenizer.texts_to_sequences([code])
    padded = keras.preprocessing.sequence.pad_sequences(seq, maxlen=max_len, padding='post', truncating='post')
    proba = lstm_model.predict(padded, verbose=0)[0, 0]
    pred = proba >= threshold
    return pred, proba
