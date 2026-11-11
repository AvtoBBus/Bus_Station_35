"""
Пункт 2.4 «Более сложная модель»: итоговое сравнение моделей по LODO.

Читает УЖЕ посчитанные LODO-результаты из results/ (ничего не обучает), приводит
разные форматы файлов к одному виду и отвечает на вопрос: даёт ли усложнение модели
прирост обобщаемости на неизвестных источниках, или только in-distribution метрики.

Запуск: python -m ml lodo-summary
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from ml.paths import RESULTS_DIR  # noqa: E402

CLASSICAL = ["catboost", "random_forest", "logistic_regression", "svm", "tfidf_lr_baseline"]
COMPLEX = ["lstm", "bilstm", "char_cnn", "transformer"]
ALL_MODELS = [m for m in CLASSICAL + COMPLEX if m != "tfidf_lr_baseline"]

MODEL_ALIASES = {"rf": "random_forest", "lr": "logistic_regression", "charcnn": "char_cnn", "cnn": "char_cnn"}
COLUMN_ALIASES = {"tpr@1%fpr": "tpr_at_1pct_fpr", "tpr_1pct_fpr": "tpr_at_1pct_fpr"}

# (имя файла или маска, модель, если в файле нет колонки model)
LEGACY_FILES = [
    ("lodo_classical.csv", None),
    ("lodo_charcnn.csv", "char_cnn"),
    ("lodo_transformer.csv", "transformer"),
    ("lodo_baseline_metrics.csv", "tfidf_lr_baseline"),
]
METRICS = ["pr_auc", "roc_auc", "tpr_at_1pct_fpr", "negative_fpr"]
VERDICT_METRICS = ["roc_auc", "tpr_at_1pct_fpr", "pr_auc"]
MIN_COMMON_SOURCES = 3   # меньше - сравнивать модели нельзя (std по 1-2 точкам не имеет смысла)
TOLERANCE = 0.02          # разница меньше этого значения считается отсутствием различий


def source_key(name) -> str:
    """Ключ сопоставления источников: 'CSIC-2010', 'csic_2010' и 'csic2010' - один источник."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _normalize(df: pd.DataFrame, model: str | None, source_file: Path) -> pd.DataFrame:
    df = df.copy()
    first = df.columns[0]
    if "source" not in df.columns and (str(first).startswith("Unnamed") or first == ""):
        df = df.rename(columns={first: "source"})  # новые скрипты пишут источник в индекс
    df = df.rename(columns=COLUMN_ALIASES)
    if "model" not in df.columns:
        df["model"] = model
    df["model"] = df["model"].map(lambda m: MODEL_ALIASES.get(str(m), str(m)))
    df["source_file"] = source_file.name
    df["_mtime"] = source_file.stat().st_mtime
    return df


def _model_from_filename(name: str) -> str:
    stem = Path(name).stem.removeprefix("lodo_results_").removeprefix("lodo_").removesuffix("_results")
    return MODEL_ALIASES.get(stem, stem)


def load_lodo_results(results_dir: Path) -> pd.DataFrame:
    """Собирает LODO из старых и новых форматов; при дубликатах (model, source) берёт самый свежий файл."""
    frames, seen = [], set()
    for name, model in LEGACY_FILES:
        p = results_dir / name
        if p.is_file():
            frames.append(_normalize(pd.read_csv(p), model, p)); seen.add(p.name)
    for pattern in ("lodo_results_*.csv", "lodo_*_results.csv"):
        for p in sorted(results_dir.glob(pattern)):
            if p.name in seen:
                continue
            frames.append(_normalize(pd.read_csv(p), _model_from_filename(p.name), p)); seen.add(p.name)
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, ignore_index=True)
    df["source_key"] = df["source"].map(source_key)
    df = df.sort_values("_mtime").drop_duplicates(subset=["model", "source_key"], keep="last")
    return df.drop(columns=["_mtime"]).sort_values(["model", "source"]).reset_index(drop=True)


def _compare_groups(means: pd.DataFrame, metric: str):
    classical = means.loc[means.index.isin(CLASSICAL), metric].dropna()
    complex_ = means.loc[means.index.isin(COMPLEX), metric].dropna()
    if classical.empty or complex_.empty:
        return None
    best_classical, best_complex = classical.idxmax(), complex_.idxmax()
    delta = float(complex_[best_complex] - classical[best_classical])
    result = "complex_better" if delta > TOLERANCE else "classical_better" if delta < -TOLERANCE else "no_difference"
    return {"best_classical": best_classical, "best_complex": best_complex, "delta": round(delta, 4), "result": result}


def _verdict_text(n_common: int, per_metric: dict) -> str:
    if n_common < MIN_COMMON_SOURCES:
        return (f"Недостаточно общих источников ({n_common} < {MIN_COMMON_SOURCES}): сравнение моделей ненадёжно, "
                "вывод не делается. Приведите все модели к одному набору источников (см. таблицу «Источники по моделям»).")
    if not per_metric:
        return "Недостаточно данных: нужна хотя бы одна классическая и одна сложная модель."
    by_result = {}
    for metric, r in per_metric.items():
        by_result.setdefault(r["result"], []).append(metric)
    if set(by_result) <= {"classical_better", "no_difference"}:
        return "Сложные модели не превосходят классические на LODO (по метрикам: " + ", ".join(per_metric) + ")."
    if set(by_result) <= {"complex_better", "no_difference"}:
        return "Сложные модели лучше классических на LODO (по метрикам: " + ", ".join(by_result["complex_better"]) + ")."
    return ("Метрики расходятся: сложные лучше по " + ", ".join(by_result["complex_better"]) +
            ", классические лучше по " + ", ".join(by_result.get("classical_better", [])) + ". Однозначного вывода нет.")


def build_summary(results_dir: Path) -> dict:
    df = load_lodo_results(results_dir)
    out = {"long": df, "by_model": pd.DataFrame(), "common": pd.DataFrame(), "common_sources": [],
           "sources_by_model": {}, "pivots": {}, "present": [], "missing": list(ALL_MODELS), "verdict": None}
    if df.empty:
        return out

    present = sorted(df["model"].unique())
    out["present"] = present
    out["missing"] = [m for m in ALL_MODELS if m not in present]
    out["sources_by_model"] = {m: sorted(g["source"].unique()) for m, g in df.groupby("model")}

    metrics = [m for m in METRICS if m in df.columns]
    by_model = df.groupby("model")[metrics].mean().round(4)
    by_model.insert(0, "n_sources", df.groupby("model")["source_key"].nunique())
    out["by_model"] = by_model

    for metric in ("roc_auc", "tpr_at_1pct_fpr"):
        if metric in df.columns:
            out["pivots"][metric] = df.pivot_table(index="source_key", columns="model", values=metric).round(3)

    common = sorted(set.intersection(*[set(g["source_key"]) for _, g in df.groupby("model")]))
    out["common_sources"] = common
    per_metric = {}
    if common:
        sub = df[df["source_key"].isin(common)]
        out["common"] = sub.groupby("model")[metrics].agg(["mean", "std"]).round(4)
        means = sub.groupby("model")[[m for m in VERDICT_METRICS if m in df.columns]].mean()
        for metric in means.columns:
            r = _compare_groups(means, metric)
            if r:
                per_metric[metric] = r
    out["verdict"] = {
        "n_common": len(common),
        "insufficient": len(common) < MIN_COMMON_SOURCES,
        "metrics": per_metric if len(common) >= MIN_COMMON_SOURCES else {},
        "text": _verdict_text(len(common), per_metric),
        "preliminary": bool(out["missing"]),
    }
    return out


def main(argv=None) -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    s = build_summary(RESULTS_DIR)
    if s["long"].empty:
        print(f"Нет LODO-результатов в {RESULTS_DIR}. Запустите: python -m ml evaluate --model <name>")
        return 1

    print("=" * 80 + "\nИсточники по моделям (LODO считается по каждому источнику отдельно)\n" + "=" * 80)
    for model, sources in s["sources_by_model"].items():
        print(f"{model:<20} ({len(sources)}): {', '.join(sources)}")

    print("\n" + "=" * 80 + "\nLODO: среднее по ВСЕМ источникам каждой модели (наборы источников могут различаться)\n" + "=" * 80)
    print(s["by_model"].to_string())

    for metric, pivot in s["pivots"].items():
        print("\n" + "=" * 80 + f"\n{metric} по источникам (NaN = у модели нет этого источника)\n" + "=" * 80)
        print(pivot.to_string())

    print("\n" + "=" * 80)
    print(f"LODO: сравнение на ОБЩИХ источниках ({len(s['common_sources'])}): {', '.join(s['common_sources']) or 'нет'}")
    print("=" * 80)
    print(s["common"].to_string() if not s["common"].empty else "Общих источников нет: сравнивать модели нельзя.")
    print("\nПримечание: PR-AUC зависит от доли XSS в тестовой выборке источника; между источниками надёжнее "
          "сравнивать ROC-AUC и TPR@1%FPR.")
    print("Модели БЕЗ LODO-результатов (missing):", ", ".join(s["missing"]) or "нет")

    v = s["verdict"]
    print("\n" + "=" * 80 + "\nВЫВОД (пункт 2.4)\n" + "=" * 80)
    for metric, r in v["metrics"].items():
        print(f"{metric:<18} лучшая классическая: {r['best_classical']:<20} лучшая сложная: {r['best_complex']:<12} "
              f"разница {r['delta']:+.4f} -> {r['result']}")
    print(v["text"])
    if v["preliminary"]:
        print("ПРЕДВАРИТЕЛЬНО: для части моделей LODO ещё не посчитан (см. missing).")

    out = RESULTS_DIR / "summary_24.csv"
    s["long"].to_csv(out, index=False)
    s["by_model"].to_csv(RESULTS_DIR / "summary_24_by_model.csv")
    print(f"\nСохранено: {out} и summary_24_by_model.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
