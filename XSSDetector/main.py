from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import HTTPException, status

from pydantic import BaseModel
from typing import Literal, Any, List

from utils.load_models import *

import logging
logger = logging.getLogger("uvicorn")

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

models_functions = {
    'catboost': {
        'load': load_catboost,
        'predict': predict_catboost
    },
    'rf': {
        'load': load_random_forest,
        'predict': predict_rf
    },
    'lr': {
        'load': load_logistic_regression,
        'predict': predict_lr
    },
    'svm': {
        'load': load_svm,
        'predict': predict_svm
    },
    'lstm': {
        'load': load_lstm,
        'predict': predict_lstm
    }
}
THRESHLOD_DEFAULT = 0.35

class PredictionResult(BaseModel):
    is_xss: bool
    probability: float
    threshold: float
    code_sample: str
    risk_level: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']
    # features: List[Any]

AllowedModels = Literal['catboost', 'rf', 'lr', 'svm', 'lstm']

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

# def get_top_features(features_df, original_features):
#     """Возвращает топ признаков, повлиявших на решение"""
#     shap_values = model.get_feature_importance(
#         data=Pool(features_df, cat_features=metadata.get('cat_features'), text_features=['text']),
#         type='ShapValues',
#     )
#     contributions = shap_values[0, :-1]

#     important = []

#     for idx in np.argsort(np.abs(contributions))[-3:][::-1]:
#         if abs(contributions[idx]) > 1e-6:
#             important.append(
#                 f"{metadata['feature_names'][idx]}: {features_df.iloc[0, idx]} (вклад {contributions[idx]:.4f})"
#             )

#     return important

@app.post("/predict", response_model=PredictionResult)
async def predict(text: str, models: list[AllowedModels] = ['catboost', 'rf', 'lr', 'svm', 'lstm']):
    if len(models) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Необходимо указать хотя бы одну модель',
            )
    
    all_results = []

    for key in models:
        res = models_functions[key]['predict'](text)
        all_results.append(res[1])

    probability = sum(all_results) / len(models)

    return PredictionResult(
        is_xss=bool(probability >= THRESHLOD_DEFAULT),
        probability=float(probability),
        threshold=THRESHLOD_DEFAULT,
        code_sample=text,
        risk_level=get_risk_level(probability),
    )
