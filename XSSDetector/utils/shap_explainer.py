"""
SHAP-интерпретируемость для моделей обнаружения XSS.

Две задачи:
1. Диагностика смещения — если в глобальной важности доминируют length/entropy,
   модель выучила длину, а не семантику.
2. Объяснение вердиктов — топ-признаков на каждый запрос.
"""

import numpy as np
import pandas as pd
import joblib
from typing import Optional

# SHAP импортируется лениво, т.к. это тяжёлая библиотека
_shap = None


def _get_shap():
    global _shap
    if _shap is None:
        import shap
        _shap = shap
    return _shap


def explain_catboost(model, metadata, features_df: pd.DataFrame, top_n: int = 5) -> list[dict]:
    """
    TreeSHAP для CatBoost — точный и быстрый.
    
    Returns: список dicts {feature, value, contribution} отсортированный по |contribution|
    """
    shap = _get_shap()
    
    cat_features = metadata.get('cat_features', [])
    pool = features_df.copy()
    for col in cat_features:
        if col in pool.columns:
            pool[col] = pool[col].astype('category')
    
    # TreeSHAP
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(pool)
    
    # shap_values может быть массивом [n_samples, n_features] или списком классов
    if isinstance(shap_values, list):
        values = shap_values[1]  # класс XSS
    else:
        values = shap_values
    
    contributions = values[0]  # первый (и единственный) sample
    
    results = []
    feature_names = list(features_df.columns)
    
    # Сортируем по абсолютному вкладу
    indices = np.argsort(np.abs(contributions))[::-1][:top_n]
    
    for idx in indices:
        if abs(contributions[idx]) > 1e-6:
            results.append({
                'feature': feature_names[idx],
                'value': float(features_df.iloc[0, idx]) if isinstance(features_df.iloc[0, idx], (int, float, np.integer, np.floating)) else str(features_df.iloc[0, idx]),
                'contribution': float(contributions[idx]),
            })
    
    return results


def explain_tree_model(model, features_df: pd.DataFrame, top_n: int = 5) -> list[dict]:
    """
    KernelSHAP или TreeSHAP для sklearn-моделей (RF, LR, SVM).
    Для RF используем TreeExplainer, для LR/SVM — LinearExplainer.
    """
    shap = _get_shap()
    
    model_type = type(model).__name__
    
    if 'Forest' in model_type or 'Gradient' in model_type or 'Decision' in model_type:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(features_df)
        
        if isinstance(shap_values, list):
            values = shap_values[1]
        else:
            values = shap_values
            
    elif 'Logistic' in model_type:
        explainer = shap.LinearExplainer(model, features_df)
        shap_values = explainer.shap_values(features_df)
        values = shap_values
        
    else:
        # Fallback: KernelSHAP (медленно, но работает для всего)
        background = shap.sample(features_df, 1) if len(features_df) > 1 else features_df
        explainer = shap.KernelExplainer(model.predict_proba, background)
        shap_values = explainer.shap_values(features_df, nsamples=100)
        
        if isinstance(shap_values, list):
            values = shap_values[1]
        else:
            values = shap_values
    
    if len(values.shape) > 1:
        contributions = values[0]
    else:
        contributions = values
    
    results = []
    feature_names = list(features_df.columns)
    indices = np.argsort(np.abs(contributions))[::-1][:top_n]
    
    for idx in indices:
        if abs(contributions[idx]) > 1e-6:
            results.append({
                'feature': feature_names[idx],
                'value': float(features_df.iloc[0, idx]),
                'contribution': float(contributions[idx]),
            })
    
    return results


def global_feature_importance(model, metadata: dict, training_data: pd.DataFrame, 
                                n_samples: int = 500, top_n: int = 10) -> list[dict]:
    """
    Глобальная важность признаков по SHAP — для диагностики смещения.
    
    Если доминируют length/entropy/url_length — модель выучила длину, а не семантику XSS.
    
    Args:
        model: обученная модель
        metadata: metadata dict для CatBoost (или None для sklearn)
        training_data: DataFrame с обучающими данными
        n_samples: количество сэмплов для оценки
        top_n: топ-N признаков
    """
    shap = _get_shap()
    
    sample = training_data.sample(min(n_samples, len(training_data)), random_state=42)
    
    if metadata and 'feature_names' in metadata:
        cat_features = metadata.get('cat_features', [])
        for col in cat_features:
            if col in sample.columns:
                sample[col] = sample[col].astype('category')
        
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(sample)
        
        if isinstance(shap_values, list):
            values = shap_values[1]
        else:
            values = shap_values
    else:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(sample)
        
        if isinstance(shap_values, list):
            values = shap_values[1]
        else:
            values = shap_values
    
    # Средняя абсолютная важность по всем сэмплам
    mean_abs_shap = np.mean(np.abs(values), axis=0)
    
    feature_names = list(sample.columns)
    results = []
    indices = np.argsort(mean_abs_shap)[::-1][:top_n]
    
    for idx in indices:
        results.append({
            'feature': feature_names[idx],
            'mean_abs_shap': float(mean_abs_shap[idx]),
        })
    
    return results


def diagnose_bias(global_importance: list[dict]) -> dict:
    """
    Анализ глобальной важности: выявляет, учится ли модель на длине.
    
    Returns:
        dict с полями:
        - 'biased': bool — доминируют ли длина/энтропия
        - 'warning': str — описание проблемы
        - 'top_features': list — топ-5 признаков
    """
    length_features = {'length', 'url_length', 'html_length', 'entropy', 
                       'word_count', 'url_special_characters', 'special_char_ratio'}
    
    top5 = global_importance[:5]
    top5_names = {f['feature'] for f in top5}
    
    length_dominance = len(top5_names & length_features)
    
    biased = length_dominance >= 3
    
    if biased:
        warning = (
            f"⚠️ СМЕЩЕНИЕ ОБНАРУЖЕНО: {length_dominance}/5 топ-признаков — "
            f"длина/энтропия ({', '.join(top5_names & length_features)}). "
            f"Модель, вероятно, учится на длине строки, а не на семантике XSS."
        )
    else:
        warning = "✅ Смещение не обнаружено: топ-признаки семантические."
    
    return {
        'biased': biased,
        'warning': warning,
        'top_features': top5,
    }
