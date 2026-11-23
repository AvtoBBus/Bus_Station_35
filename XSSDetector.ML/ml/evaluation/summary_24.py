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


def _direction(delta: float) -> str:
    return "complex_better" if delta > TOLERANCE else "classical_better" if delta < -TOLERANCE else "no_difference"


def _compare_groups(means: pd.DataFrame, metric: str):
    classical = means.loc[means.index.isin(CLASSICAL), metric].dropna()
    complex_ = means.loc[means.index.isin(COMPLEX), metric].dropna()
    if classical.empty or complex_.empty:
        return None
    best_classical, best_complex = classical.idxmax(), complex_.idxmax()
    delta = float(complex_[best_complex] - classical[best_classical])
    group_delta = float(complex_.mean() - classical.mean())
    return {
        "best_classical": best_classical, "best_complex": best_complex,
        "delta": round(delta, 4), "result": _direction(delta),          # лучшая против лучшей
        "group": {                                                      # среднее по группе моделей
            "classical_mean": round(float(classical.mean()), 4), "complex_mean": round(float(complex_.mean()), 4),
            "delta": round(group_delta, 4), "result": _direction(group_delta),
        },
    }


def _friedman_p(pivot: pd.DataFrame):
    """p-value критерия Фридмана (источники = блоки, модели = обработки); None, если посчитать нельзя."""
    try:
        from scipy import stats
        clean = pivot.dropna()
        if clean.shape[0] < 2 or clean.shape[1] < 3:
            return None
        p = float(stats.friedmanchisquare(*[clean[c] for c in clean.columns]).pvalue)
        return None if p != p else p   # NaN, если все значения одинаковы
    except Exception:
        return None


def _verdict_text(n_common: int, per_metric: dict, best_model=None) -> str:
    if n_common < MIN_COMMON_SOURCES:
        return (f"Недостаточно общих источников ({n_common} < {MIN_COMMON_SOURCES}): сравнение моделей ненадёжно, "
                "вывод не делается. Приведите все модели к одному набору источников (см. таблицу «Источники по моделям»).")
    if not per_metric:
        return "Недостаточно данных: нужна хотя бы одна классическая и одна сложная модель."
    results = [r["group"]["result"] for r in per_metric.values()]
    n = len(results)
    n_classical, n_complex = results.count("classical_better"), results.count("complex_better")
    better = lambda key: ", ".join(m for m, r in per_metric.items() if r["group"]["result"] == key)
    if n_classical == 0 and n_complex == 0:
        text = f"Как классы методов классические и сложные модели не различаются (средние по группам в пределах ±{TOLERANCE})."
    elif n_complex == 0 and n_classical > n / 2:
        text = f"Классические методы лучше сложных как группа (по метрикам: {better('classical_better')}; по остальным различий нет)."
    elif n_classical == 0 and n_complex > n / 2:
        text = f"Сложные модели лучше классических как группа (по метрикам: {better('complex_better')}; по остальным различий нет)."
    else:
        parts = [f"{m}: {r['group']['result']}" for m, r in per_metric.items()]
        text = "Однозначного преимущества у класса методов нет (" + "; ".join(parts) + ")."
    if best_model:
        text += f" Лучшая отдельная модель по среднему рангу на источниках: {best_model}."
    return text


def build_summary(results_dir: Path) -> dict:
    full = load_lodo_results(results_dir)
    df = full
    single_class = {}
    if not full.empty and "roc_auc" in full.columns:
        undefined = full["roc_auc"].isna()   # ROC-AUC не определён => в тесте был один класс
        single_class = {m: sorted(g["source"]) for m, g in full[undefined].groupby("model")}
        df = full[~undefined]
    out = {"long": full, "single_class": single_class, "by_model": pd.DataFrame(), "common": pd.DataFrame(), "common_sources": [],
           "sources_by_model": {}, "pivots": {}, "ranks": pd.DataFrame(), "present": [], "missing": list(ALL_MODELS), "verdict": None}
    if df.empty:
        return out

    present = sorted(full["model"].unique())
    out["present"] = present
    out["missing"] = [m for m in ALL_MODELS if m not in present]
    out["sources_by_model"] = {m: sorted(g["source"].unique()) for m, g in df.groupby("model")}
    out["present"] = sorted(full["model"].unique())

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
    ranks, friedman = {}, {}
    if common:
        sub = df[df["source_key"].isin(common)]
        out["common"] = sub.groupby("model")[metrics].agg(["mean", "std"]).round(4)
        means = sub.groupby("model")[[m for m in VERDICT_METRICS if m in df.columns]].mean()
        for metric in means.columns:
            r = _compare_groups(means, metric)
            if r:
                per_metric[metric] = r
        for metric in means.columns:
            pivot = sub.pivot_table(index="source_key", columns="model", values=metric)
            ranks[metric] = pivot.rank(axis=1, ascending=False).mean()
            friedman[metric] = _friedman_p(pivot)
    ranks_df = pd.DataFrame(ranks).round(2)
    best_model = ranks_df.mean(axis=1).idxmin() if not ranks_df.empty else None
    out["ranks"] = ranks_df
    out["verdict"] = {
        "n_common": len(common),
        "insufficient": len(common) < MIN_COMMON_SOURCES,
        "metrics": per_metric if len(common) >= MIN_COMMON_SOURCES else {},
        "text": _verdict_text(len(common), per_metric, best_model),
        "best_model": best_model,
        "friedman_p": friedman,
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

    if s["single_class"]:
        print("\nИсточники только с одним классом (метрики не определены, в сравнении НЕ участвуют):")
        for model, sources in s["single_class"].items():
            print(f"  {model:<20} {', '.join(sources)}")

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
        g = r["group"]
        print(f"{metric:<16} лучшая классическая {r['best_classical']} vs лучшая сложная {r['best_complex']}: "
              f"разница {r['delta']:+.4f} ({r['result']})")
        print(f"{'':<16} среднее по группе: классические {g['classical_mean']:.4f}, сложные {g['complex_mean']:.4f}: "
              f"разница {g['delta']:+.4f} ({g['result']})")
    if not s["ranks"].empty:
        print("\nСредний ранг модели по источникам (1 = лучший):")
        print(s["ranks"].assign(средний=s["ranks"].mean(axis=1).round(2)).sort_values("средний").to_string())
        for metric, p in v["friedman_p"].items():
            if p is not None:
                print(f"Критерий Фридмана ({metric}, {v['n_common']} источников): p = {p:.3f}")
        print(f"(допуск различий ±{TOLERANCE}; при {v['n_common']} источниках точный парный тест Уилкоксона не может дать p < "
              f"{2 / 2 ** v['n_common']:.4f}, поэтому выводы описательные)")
    print("\n" + v["text"])
    if v["preliminary"]:
        print("ПРЕДВАРИТЕЛЬНО: для части моделей LODO ещё не посчитан (см. missing).")

    out = RESULTS_DIR / "summary_24.csv"
    s["long"].to_csv(out, index=False)
    s["by_model"].to_csv(RESULTS_DIR / "summary_24_by_model.csv")
    print(f"\nСохранено: {out} и summary_24_by_model.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
