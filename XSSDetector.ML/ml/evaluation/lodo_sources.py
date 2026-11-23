"""Единый список LODO-источников для всех моделей.

LODO имеет смысл только на источниках, где в тесте есть ОБА класса: на источнике только с XSS
(vulnxss, fwaf, capec, payloadbox, synthetic-xss...) или только с нормальными примерами (hard_benign)
ROC-AUC не определён, PR-AUC даёт 1.0 или 0.0, а TPR@1%FPR/FPR бессмысленны.
Для одноклассовых источников считают одну метрику: долю обнаруженных атак (recall) или долю
ложных срабатываний (FPR); в ранжировании моделей они не участвуют.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# Источники с обоими классами (по результатам прогонов). Все модели оцениваются на одном и том же списке.
LODO_SOURCES = ["csic2010", "ecmlpkdd2007", "httpparams", "kaggle", "modsecurity"]
MIN_ROWS_PER_CLASS = 20


def select_lodo_sources(df: pd.DataFrame, requested=None, min_per_class: int = MIN_ROWS_PER_CLASS, verbose: bool = True) -> list:
    """Источники для LODO: есть в данных и содержат оба класса (не меньше min_per_class каждого)."""
    names = list(requested) if requested else list(LODO_SOURCES)
    selected = []
    for name in names:
        part = df[df["source"] == name]
        counts = part["label"].value_counts()
        if part.empty:
            reason = "нет в датасете"
        elif min(counts.get(0, 0), counts.get(1, 0)) < min_per_class:
            reason = f"мало примеров одного из классов (normal={counts.get(0, 0)}, xss={counts.get(1, 0)})"
        else:
            selected.append(name)
            continue
        if verbose:
            print(f"LODO: источник '{name}' пропущен: {reason}")
    return selected


def cap_per_class(y, cap: int, seed: int = 42):
    """Позиции для ОБУЧАЮЩЕЙ выборки: не более `cap` примеров каждого класса (случайно, воспроизводимо).

    Ограничение применяется только к обучающей части фолда. Тестовый источник остаётся целиком:
    раньше выборка ограничивалась ДО разбиения на источники, из-за чего тест получался крошечным
    (например, ~100 нормальных примеров у kaggle) и с искажённой долей классов.
    """
    y = np.asarray(y)
    if cap is None or cap <= 0:
        return np.arange(len(y))
    rng = np.random.default_rng(seed)
    parts = [rng.choice(np.where(y == c)[0], min(cap, int((y == c).sum())), replace=False) for c in (0, 1)]
    idx = np.concatenate(parts)
    rng.shuffle(idx)
    return idx
