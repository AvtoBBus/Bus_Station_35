"""Единый способ получить вероятности XSS от моделей реестра на произвольном наборе текстов.

Нужен, чтобы сравнивать модели (и CRS) на ОДНОМ И ТОМ ЖЕ тестовом наборе,
а не брать метрики из разных run-ов с разными выборками.
"""
import numpy as np
import pandas as pd

CLASSICAL_MODELS = {"catboost", "random_forest", "logistic_regression", "svm"}


def _positive_class(proba) -> np.ndarray:
    """Приводит выход predict_proba к 1-мерному массиву P(XSS)."""
    if hasattr(proba, "detach"):  # torch.Tensor
        proba = proba.detach().cpu().numpy()
    arr = np.asarray(proba, dtype=float)
    if arr.ndim == 2 and arr.shape[1] == 2:
        return arr[:, 1]
    return arr.reshape(-1)


def score_texts(model_name: str, texts, adapter=None, batch_size: int = 512):
    """Возвращает np.ndarray вероятностей XSS или None, если модель недоступна."""
    if adapter is None:
        from ml.serving.predictor import model_manager
        adapter = model_manager.get_model(model_name)
    if adapter is None:
        return None

    texts = [str(t) for t in texts]
    if model_name in CLASSICAL_MODELS:
        from ml.features.extract_features import extract_features
        # CatBoost обучается с текстовым признаком (train.py: extract_features(text)),
        # остальные классические модели - без него.
        with_text = model_name == "catboost"
        feats = pd.DataFrame([extract_features(t, with_text) for t in texts])
        return _positive_class(adapter.predict_proba(feats))

    parts = [
        _positive_class(adapter.predict_proba(texts[i:i + batch_size]))
        for i in range(0, len(texts), batch_size)
    ]
    return np.concatenate(parts) if parts else np.array([])
