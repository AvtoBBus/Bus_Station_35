from fastapi import FastAPI, HTTPException, status
from fastapi.concurrency import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel
from typing import Literal

try:
    from xssdetector.utils.load_models import (
        predict_catboost,
        predict_rf,
        predict_lr,
        predict_svm,
        predict_lstm,
        predict_transformer,
        load_transformer,
        load_random_forest,
        load_logistic_regression,
        load_svm,
        load_lstm,
        warm_up_models,
        _ensure_catboost,
        THRESHOLD_DEFAULT,
    )
    from xssdetector.utils.preprocess import decode_recursive
    from xssdetector.utils.extract_features import extract_features
    from xssdetector.utils.shap_explainer import (
        explain_catboost,
        diagnose_bias,
        global_feature_importance,
        load_global_reference_features,
        explain_tree_model,
        explain_lstm,
        explain_transformer,
    )
except ImportError:  # pragma: no cover
    from utils.load_models import (
        predict_catboost,
        predict_rf,
        predict_lr,
        predict_svm,
        predict_lstm,
        predict_transformer,
        load_transformer,
        load_random_forest,
        load_logistic_regression,
        load_svm,
        load_lstm,
        warm_up_models,
        _ensure_catboost,
        THRESHOLD_DEFAULT,
    )
    from utils.preprocess import decode_recursive
    from utils.extract_features import extract_features
    from utils.shap_explainer import (
        explain_catboost,
        diagnose_bias,
        global_feature_importance,
        load_global_reference_features,
        explain_tree_model,
        explain_lstm,
        explain_transformer,
    )

import pandas as pd
import logging

logger = logging.getLogger('uvicorn')


@asynccontextmanager
async def lifespan(app: FastAPI):
    warm_up_models()
    yield


app = FastAPI(
    swagger_ui_parameters={'syntaxHighlight': True},
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:8000', 'http://fastapi:8000'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

models_functions = {
    'catboost': predict_catboost,
    'rf': predict_rf,
    'lr': predict_lr,
    'svm': predict_svm,
    'lstm': predict_lstm,
    'transformer': predict_transformer,
}


class PredictionResult(BaseModel):
    is_xss: bool
    probability: float
    threshold: float
    code_sample: str
    risk_level: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']


AllowedModels = Literal['catboost', 'rf', 'lr', 'svm', 'lstm', 'transformer']


class XSSBody(BaseModel):
    text: str
    models: list[AllowedModels] | None = None


RiskLevel = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']


def predict_model_probability(model_name: str, text: str) -> float:
    try:
        return float(models_functions[model_name](text)[1])
    except (ImportError, RuntimeError, OSError) as error:
        if model_name != 'transformer':
            raise
        logger.exception('Local Transformer model is unavailable')
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Transformer is unavailable locally. Install the declared dependencies and verify its checkpoint files.',
        ) from error


def get_risk_level(probability: float) -> RiskLevel:
    if probability >= 0.8:
        return 'CRITICAL'
    elif probability >= 0.6:
        return 'HIGH'
    elif probability >= 0.4:
        return 'MEDIUM'
    elif probability >= 0.2:
        return 'LOW'
    else:
        return 'SAFE'


class ExplanationResult(BaseModel):
    is_xss: bool
    probability: float
    risk_level: RiskLevel
    decoded_text: str
    was_decoded: bool
    explanation_model: str
    explanation_method: str
    global_diagnostic_model: str
    top_features: list[dict]
    global_top_features: list[dict]
    global_sample_size: int
    bias_warning: str | None = None


@app.post('/explain', response_model=ExplanationResult)
async def explain(body: XSSBody):
    decoded = decode_recursive(body.text)
    model_keys = body.models if body.models else [
        'catboost', 'rf', 'lr', 'svm', 'lstm'
    ]

    all_probabilities = []
    for key in model_keys:
        proba = predict_model_probability(key, body.text)
        all_probabilities.append(proba)
    probability = sum(all_probabilities) / len(all_probabilities)

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

    reference_features = None
    try:
        reference_features = load_global_reference_features(metadata, n_samples=512)
        global_importance = global_feature_importance(
            model,
            metadata,
            reference_features,
            n_samples=512,
            top_n=10,
        )
        bias_warning = diagnose_bias(global_importance)['warning']
        global_sample_size = len(reference_features)
    except Exception:
        logger.exception('Global CatBoost SHAP diagnostics failed')
        global_importance = []
        bias_warning = 'Global SHAP bias diagnostics are unavailable for the local reference dataset.'
        global_sample_size = 0

    explanation_model = body.models[0] if body.models and len(body.models) == 1 else 'catboost'
    explanation_method = 'CatBoost TreeSHAP'
    if explanation_model == 'catboost':
        top_features = explain_catboost(model, metadata, features_df, top_n=5)
    elif explanation_model == 'lstm':
        (lstm_model, tokenizer), max_len = load_lstm()
        top_features = explain_lstm(lstm_model, tokenizer, decoded, max_len, top_n=5)
        explanation_method = 'Integrated Gradients'
    elif explanation_model == 'transformer':
        (transformer_model, tokenizer), max_len = load_transformer()
        top_features = explain_transformer(
            transformer_model, tokenizer, decoded, max_len, top_n=5
        )
        explanation_method = 'Integrated Gradients'
    else:
        feature_names = [name for name in metadata['feature_names'] if name != 'text']
        numeric_features = pd.DataFrame([extract_features(decoded, False)]).reindex(
            columns=feature_names, fill_value=0
        )
        background_features = (
            reference_features.drop(columns=['text'], errors='ignore').reindex(
                columns=feature_names, fill_value=0
            )
            if reference_features is not None
            else numeric_features
        )
        if explanation_model == 'rf':
            selected_model = load_random_forest()
            top_features = explain_tree_model(
                selected_model, numeric_features, background_df=background_features
            )
            explanation_method = 'TreeSHAP'
        elif explanation_model == 'lr':
            selected_model, scaler = load_logistic_regression()
            numeric_features = pd.DataFrame(
                scaler.transform(numeric_features), columns=feature_names
            )
            background_features = pd.DataFrame(
                scaler.transform(background_features), columns=feature_names
            )
            top_features = explain_tree_model(
                selected_model, numeric_features, background_df=background_features
            )
            explanation_method = 'LinearSHAP'
        elif explanation_model == 'svm':
            selected_model, scaler = load_svm()
            numeric_features = pd.DataFrame(
                scaler.transform(numeric_features), columns=feature_names
            )
            background_features = pd.DataFrame(
                scaler.transform(background_features), columns=feature_names
            )
            top_features = explain_tree_model(
                selected_model, numeric_features, background_df=background_features
            )
            explanation_method = 'KernelSHAP'

    return ExplanationResult(
        is_xss=bool(probability >= THRESHOLD_DEFAULT),
        probability=float(probability),
        risk_level=get_risk_level(probability),
        decoded_text=decoded,
        was_decoded=(body.text != decoded),
        explanation_model=explanation_model,
        explanation_method=explanation_method,
        global_diagnostic_model='catboost',
        top_features=top_features,
        global_top_features=global_importance,
        global_sample_size=global_sample_size,
        bias_warning=bias_warning,
    )


@app.post('/predict', response_model=PredictionResult)
async def predict(body: XSSBody):
    model_keys = body.models if body.models else [
        'catboost', 'rf', 'lr', 'svm', 'lstm'
    ]
    if len(model_keys) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='еобходимо указать хотя бы одну модель',
        )

    all_probabilities = []
    for key in model_keys:
        proba = predict_model_probability(key, body.text)
        all_probabilities.append(proba)

    probability = sum(all_probabilities) / len(all_probabilities)

    return PredictionResult(
        is_xss=bool(probability >= THRESHOLD_DEFAULT),
        probability=float(probability),
        threshold=THRESHOLD_DEFAULT,
        code_sample=body.text,
        risk_level=get_risk_level(probability),
    )
