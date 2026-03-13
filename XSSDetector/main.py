from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from catboost import CatBoostClassifier
import joblib
import pandas as pd
import numpy as np

from utils.extract_features import extract_features
from pydantic import BaseModel
from typing import Literal, Any, List

app = FastAPI(
    swagger_ui_parameters={"syntaxHighlight": True}
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = CatBoostClassifier()
model.load_model("./model/catboost_xss_model.cbm")
metadata = joblib.load('./model/model_metadata.pkl')

THRESHOLD = 0.35


class PredictionResult(BaseModel):
    is_xss: bool
    probability: float
    prediction: int
    threshold: float
    code_sample: str
    risk_level: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']
    features: List[Any]


def prepare_features(features_dict):
    """Подготовка признаков для модели"""
    features_df = pd.DataFrame([features_dict])

    expected_features = metadata['feature_names']
    for feature in expected_features:
        if feature not in features_df.columns:
            features_df[feature] = 0  # Заполняем недостающие нулями

    features_df = features_df[expected_features]

    cat_features = metadata.get('cat_features', [])
    for col in cat_features:
        if col in features_df.columns:
            features_df[col] = features_df[col].astype('category')

    return features_df


def get_risk_level(probability):
    """Определяет уровень риска"""
    if probability >= 0.8:
        return "CRITICAL"
    elif probability >= 0.6:
        return "HIGH"
    elif probability >= 0.4:
        return "MEDIUM"
    elif probability >= 0.2:
        return "LOW"
    else:
        return "SAFE"


def get_top_features(features_df, original_features):
    """Возвращает топ признаков, повлиявших на решение"""
    try:
        # Получаем важность признаков для этого конкретного предсказания
        shap_values = model.get_feature_importance(
            data=features_df,
            type='ShapValues'
        )

        # Сортируем по важности
        feature_names = metadata['feature_names']
        important = []

        for idx in np.argsort(shap_values)[-5:][::-1]:
            if shap_values[idx] > 0:
                feature_name = feature_names[idx]
                feature_value = original_features.get(feature_name, 0)
                important.append(f"{feature_name}={feature_value}")

        return important
    except:
        return []


@app.post("/predict", response_model=PredictionResult)
async def predict(text: str):
    features = extract_features(text)
    features_df = prepare_features(features)

    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0][1]

    return PredictionResult(
        is_xss=bool(probability >= THRESHOLD),
        probability=float(probability),
        prediction=int(prediction),
        threshold=THRESHOLD,
        code_sample=text,
        risk_level=get_risk_level(probability),
        features=get_top_features(features_df, features)
    )
