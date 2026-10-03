from fastapi import FastAPI, HTTPException, status
from fastapi.concurrency import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel
from typing import Literal, Any, List

from utils.load_models import (
    predict_catboost,
    predict_rf,
    predict_lr,
    predict_svm,
    predict_lstm,
    warm_up_models,
    _ensure_catboost,
    _ensure_rf,
    _ensure_lr,
    _ensure_svm,
    THRESHLOD_DEFAULT,
)
from utils.preprocess import decode_recursive
from utils.extract_features import extract_features
from utils.shap_explainer import explain_catboost, explain_tree_model, diagnose_bias
import pandas as pd

import logging
logger = logging.getLogger("uvicorn")


@asynccontextmanager
async def lifespan(app: FastAPI):
    warm_up_models()
    yield


app = FastAPI(
    swagger_ui_parameters={"syntaxHighlight": True},
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://fastapi:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models_functions = {
    'catboost': predict_catboost,
    'rf': predict_rf,
    'lr': predict_lr,
    'svm': predict_svm,
    'lstm': predict_lstm,
}


class PredictionResult(BaseModel):
    is_xss: bool
    probability: float
    threshold: float
    code_sample: str
    risk_level: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']


AllowedModels = Literal['catboost', 'rf', 'lr', 'svm', 'lstm']


class XSSBody(BaseModel):
    text: str
    models: list[AllowedModels] | None = None


RiskLevel = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']


def get_risk_level(probability: float) -> RiskLevel:
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


class ExplanationResult(BaseModel):
    is_xss: bool
    probability: float
    risk_level: RiskLevel
    decoded_text: str
    was_decoded: bool
    top_features: list[dict]
    bias_warning: str | None = None


@app.post("/explain", response_model=ExplanationResult)
async def explain(body: XSSBody):
    """
    Предсказание + SHAP-объяснение: какие признаки повлияли на решение.
    Для диагностики смещения и отладки.
    """
    decoded = decode_recursive(body.text)
    model_keys = body.models if body.models else list(models_functions.keys())
    
    # Предсказание
    all_probabilities = []
    for key in model_keys:
        _pred, proba = models_functions[key](body.text)
        all_probabilities.append(proba)
    probability = sum(all_probabilities) / len(all_probabilities)
    
    # SHAP-объяснение на CatBoost (самая быстрая TreeSHAP)
    model, metadata = _ensure_catboost()
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
    
    top_features = explain_catboost(model, metadata, features_df, top_n=5)
    
    return ExplanationResult(
        is_xss=bool(probability >= THRESHLOD_DEFAULT),
        probability=float(probability),
        risk_level=get_risk_level(probability),
        decoded_text=decoded,
        was_decoded=(body.text != decoded),
        top_features=top_features,
        bias_warning=None,
    )


@app.post("/predict", response_model=PredictionResult)
async def predict(body: XSSBody):
    model_keys = body.models if body.models else list(models_functions.keys())
    if len(model_keys) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Необходимо указать хотя бы одну модель',
        )

    all_probabilities = []

    for key in model_keys:
        _pred, proba = models_functions[key](body.text)
        all_probabilities.append(proba)

    probability = sum(all_probabilities) / len(all_probabilities)

    return PredictionResult(
        is_xss=bool(probability >= THRESHLOD_DEFAULT),
        probability=float(probability),
        threshold=THRESHLOD_DEFAULT,
        code_sample=body.text,
        risk_level=get_risk_level(probability),
    )
