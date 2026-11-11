import json
from datetime import datetime
from pathlib import Path

import pandas as pd

HOLDOUT_NOTE = (
    "Протокол: случайный holdout внутри обучающего датасета (in-distribution). Это НЕ показатель обобщаемости.\n"
    "Кросс-датасетные результаты (LODO, пункт 2.4): python -m ml lodo-summary"
)


def _confusion_stats(cm):
    """n_test и FPR из матрицы ошибок [[TN, FP], [FN, TP]]; (None, None), если матрицы нет."""
    try:
        (tn, fp), (fn, tp) = cm
        total = tn + fp + fn + tp
        fpr = fp / (fp + tn) if (fp + tn) else None
        return int(total), fpr
    except (TypeError, ValueError):
        return None, None


def load_all_metrics(artifacts_dir: str) -> pd.DataFrame:
    """Сканирует папку runs, читает metrics.json и собирает их в DataFrame (последний run каждой модели)."""
    runs_dir = Path(artifacts_dir) / "runs"
    if not runs_dir.exists():
        print(f"Директория с артефактами не найдена: {runs_dir}")
        return pd.DataFrame()

    data = []
    for run_path in runs_dir.iterdir():
        if not run_path.is_dir():
            continue
        metrics_file = run_path / "metrics.json"
        if not metrics_file.exists():
            continue

        try:
            with open(metrics_file, "r", encoding="utf-8-sig") as f:
                metrics = json.load(f)

            n_test, fpr = _confusion_stats(metrics.get("confusion_matrix"))
            ts = metrics.get("timestamp")
            row = {
                "model": metrics.get("model", "unknown"),
                "timestamp": datetime.fromisoformat(ts) if ts else datetime.fromtimestamp(run_path.stat().st_mtime),
                "run_dir": str(run_path.name),
                "dataset": metrics.get("dataset"),
                "n_test": n_test,
                "roc_auc": metrics.get("roc_auc"),
                "pr_auc": metrics.get("pr_auc"),
                "accuracy": metrics.get("accuracy"),
                "precision": metrics.get("precision"),
                "recall": metrics.get("recall"),
                "f1_score": metrics.get("f1_score"),
                "tpr_at_1pct_fpr": metrics.get("tpr_at_1pct_fpr"),
                "fpr": fpr,
            }
            data.append(row)
        except Exception as e:
            print(f"Ошибка при чтении {metrics_file}: {e}")

    df = pd.DataFrame(data)
    if not df.empty:
        df = df.sort_values(by="timestamp", ascending=False).drop_duplicates(subset=["model"], keep="first")
        df = df.sort_values(by="model")
    return df


def _to_markdown(df: pd.DataFrame) -> str:
    try:
        return df.to_markdown(index=False)
    except ImportError:  # tabulate не установлен
        cols = [str(c) for c in df.columns]
        lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
        for _, r in df.iterrows():
            lines.append("| " + " | ".join(str(v) for v in r.tolist()) + " |")
        return "\n".join(lines)


def format_output(df: pd.DataFrame, fmt: str):
    if df.empty:
        print("Нет данных для отображения.")
        return

    df = df.copy()
    numeric_cols = ["roc_auc", "pr_auc", "accuracy", "precision", "recall", "f1_score", "tpr_at_1pct_fpr", "fpr"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = df[col].apply(lambda x: round(float(x), 4) if pd.notnull(x) else None)

    display_cols = ["model", "roc_auc", "pr_auc", "tpr_at_1pct_fpr", "fpr", "accuracy", "f1_score", "n_test", "timestamp"]
    df_out = df[[c for c in display_cols if c in df.columns]]

    if fmt == "json":
        # отсутствующие значения -> null
        print(df_out.to_json(orient="records", date_format="iso", indent=2))
    elif fmt == "csv":
        print(df_out.to_csv(index=False))  # отсутствующие значения -> пустая ячейка
    else:
        shown = df_out.astype(object).where(df_out.notna(), "missing")
        print(_to_markdown(shown) if fmt == "markdown" else shown.to_string(index=False))
        print("\n" + HOLDOUT_NOTE)


def run_stats(artifacts_dir: str, model_name: str = None, fmt: str = "table"):
    df = load_all_metrics(artifacts_dir)

    if model_name:
        df = df[df["model"] == model_name] if not df.empty else df
        if df.empty:
            print(f"Статистика для модели '{model_name}' не найдена.")
            return

    format_output(df, fmt)
