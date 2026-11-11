import logging
import sys
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Literal

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

sys.path.append(str(Path(__file__).resolve().parent))

from ml.serving.predictor import model_manager
from ml.registry.loader import ModelRegistry
from ml.features.preprocess import decode_recursive
from ml.features.extract_features import extract_features
from ml.explainers.explainer import (
    explain_catboost,
    diagnose_bias,
    global_feature_importance,
    load_global_reference_features,
    explain_tree_model,
    explain_lstm,
    explain_transformer,
)

logger = logging.getLogger('uvicorn')
THRESHOLD_DEFAULT = 0.5

try:
    registry = ModelRegistry()
    # Только модели, чьи артефакты реально есть на диске: сервис должен
    # подниматься, даже если часть моделей не обучена или не попала в образ
    available_models = registry.available_models
    if not available_models:
        logger.warning("Не найдено ни одного файла моделей — /predict вернёт ошибку")
except Exception as e:
    logger.error(f"Не удалось загрузить manifest.json: {e}")
    available_models = ["catboost", "random_forest", "logistic_regression", "svm", "lstm", "bilstm", "transformer", "char_cnn"]

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Прогрев моделей...")
    # Греем только те модели, которые есть в образе; отсутствие части моделей
    # не должно мешать запуску сервиса
    for model_name in ('catboost', 'random_forest'):
        if model_name not in available_models:
            logger.warning("Модель %s отсутствует — прогрев пропущен", model_name)
            continue
        try:
            model_manager.get_model(model_name)
        except Exception as e:
            logger.warning(f"Ошибка при прогреве {model_name}: {e}")
    logger.info("Сервер готов. Доступные модели: %s", available_models)
    yield


app = FastAPI(
    swagger_ui_parameters={'syntaxHighlight': True},
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:8000', 'http://fastapi:8000', 'http://localhost:3000'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.get('/health')
async def health():
    """Лёгкая проверка живости: не загружает модели и не читает датасеты."""
    return {
        'status': 'ok',
        'available_models': available_models,
        'loaded_models': sorted(model_manager.loaded_models),
    }


class PredictionResult(BaseModel):
    is_xss: bool
    probability: float
    threshold: float
    code_sample: str
    risk_level: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']


class XSSBody(BaseModel):
    text: str
    models: list[str] | None = None

    @field_validator('models')
    @classmethod
    def validate_models(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            invalid_models = [m for m in v if m not in available_models]
            if invalid_models:
                raise ValueError(
                    f"Неизвестные модели: {invalid_models}. "
                    f"Доступные: {available_models}"
                )
        return v


def _require_adapter(name: str):
    adapter = model_manager.get_model(name)
    if adapter is None:
        raise HTTPException(status_code=503, detail=f"Model {name} not available")
    return adapter


def _pick_explanation_model(preferred: str) -> str:
    """Выбирает модель для локального объяснения, пропуская недоступные."""
    for name in (preferred, 'catboost', 'random_forest', 'logistic_regression', 'svm'):
        if model_manager.get_model(name) is not None:
            return name
    return preferred


RiskLevel = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']


def get_risk_level(probability: float) -> RiskLevel:
    if probability >= 0.8: return 'CRITICAL'
    elif probability >= 0.6: return 'HIGH'
    elif probability >= 0.4: return 'MEDIUM'
    elif probability >= 0.2: return 'LOW'
    else: return 'SAFE'


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


@app.post('/predict', response_model=PredictionResult)
async def predict(body: XSSBody):
    model_names = body.models or None
    
    result = model_manager.predict_ensemble(body.text, model_names=model_names)
    
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])

    prob = result["probability"]
    
    return PredictionResult(
        is_xss=result["is_xss"],
        probability=prob,
        threshold=THRESHOLD_DEFAULT,
        code_sample=body.text,
        risk_level=get_risk_level(prob),
    )


@app.post('/explain', response_model=ExplanationResult)
async def explain(body: XSSBody):
    decoded = decode_recursive(body.text)
    
    model_names = body.models or None
    
    # 2. Предсказание
    result = model_manager.predict_ensemble(body.text, model_names=model_names)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    
    probability = result["probability"]
    
    # 3. Определяем, какую модель объяснять (недоступные пропускаем)
    requested_model = model_names[0] if model_names and len(model_names) == 1 else 'catboost'
    explanation_model = _pick_explanation_model(requested_model)
    
    # 4. CatBoost нужен для глобального объяснения и части локальных
    catboost_adapter = model_manager.get_model('catboost')
    metadata = catboost_adapter.metadata if catboost_adapter is not None else None
    
    features_df = None
    if metadata is not None:
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
    
    # Референсная выборка нужна и глобальному, и локальному SHAP.
    # В образе сервиса датасетов нет — тогда объяснения считаются без фона.
    reference_features = None
    if metadata is not None:
        try:
            reference_features = load_global_reference_features(metadata, n_samples=512)
        except Exception:
            logger.warning('Референсная выборка для SHAP недоступна, объяснения без фона')

    # 5. Глобальный SHAP (всегда на CatBoost, если он доступен)
    global_importance = []
    global_sample_size = 0
    bias_warning = None
    if catboost_adapter is not None and reference_features is not None:
        try:
            global_importance = global_feature_importance(
                catboost_adapter.model, metadata, reference_features, n_samples=512, top_n=10
            )
            bias_warning = diagnose_bias(global_importance)['warning']
            global_sample_size = len(reference_features)
        except Exception:
            logger.exception('Global CatBoost SHAP diagnostics failed')
            bias_warning = 'Global SHAP bias diagnostics are unavailable for the local reference dataset.'
    else:
        bias_warning = (
            'Глобальная SHAP-диагностика недоступна: '
            'нет модели CatBoost или референсной выборки.'
        )

    # 6. Локальное объяснение — деградируем, если модель недоступна
    top_features: list[dict] = []
    explanation_method = 'unavailable'
    try:
        if explanation_model == 'catboost' and catboost_adapter is not None and features_df is not None:
            top_features = explain_catboost(catboost_adapter.model, metadata, features_df, top_n=5)
            explanation_method = 'CatBoost TreeSHAP'

        elif explanation_model in ('lstm', 'bilstm'):
            adapter = _require_adapter(explanation_model)
            top_features = explain_lstm(adapter.model, adapter.tokenizer, decoded, adapter.max_len, top_n=5)
            explanation_method = 'Integrated Gradients'

        elif explanation_model == 'transformer':
            adapter = _require_adapter('transformer')
            top_features = explain_transformer(adapter.model, adapter.tokenizer, decoded, adapter.max_len, top_n=5)
            explanation_method = 'Integrated Gradients'

        elif explanation_model == 'char_cnn':
            explanation_method = 'Char-CNN (no local attributions yet)'

        else:  # random_forest, logistic_regression, svm
            adapter = _require_adapter(explanation_model)

            if metadata is not None:
                feature_names = [name for name in metadata['feature_names'] if name != 'text']
            else:
                feature_names = list(extract_features(decoded, False).keys())

            numeric_features = pd.DataFrame([extract_features(decoded, False)]).reindex(columns=feature_names, fill_value=0)

            background_features = (
                reference_features.drop(columns=['text'], errors='ignore').reindex(columns=feature_names, fill_value=0)
                if reference_features is not None else numeric_features
            )

            if explanation_model in ('logistic_regression', 'svm'):
                numeric_features = pd.DataFrame(adapter.scaler.transform(numeric_features), columns=feature_names)
                background_features = pd.DataFrame(adapter.scaler.transform(background_features), columns=feature_names)
                explanation_method = 'LinearSHAP' if explanation_model == 'logistic_regression' else 'KernelSHAP'
            else:
                explanation_method = 'TreeSHAP'

            top_features = explain_tree_model(adapter.model, numeric_features, background_df=background_features)
    except Exception:
        logger.exception('Локальное объяснение модели %s не удалось', explanation_model)
        top_features = []
        explanation_method = f'{explanation_model}: explanation unavailable'

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