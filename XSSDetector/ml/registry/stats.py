import json
import pandas as pd
from pathlib import Path
from datetime import datetime

def load_all_metrics(artifacts_dir: str) -> pd.DataFrame:
    """Сканирует папку runs, читает metrics.json и собирает их в DataFrame."""
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
            with open(metrics_file, "r", encoding="utf-8") as f:
                metrics = json.load(f)
            
            # Читаем ПЛОСКУЮ структуру (как её пишет calculate_metrics)
            row = {
                "model": metrics.get("model", "unknown"),
                "timestamp": datetime.fromtimestamp(run_path.stat().st_mtime),
                "run_dir": str(run_path.name),
                "roc_auc": metrics.get("roc_auc"),
                "pr_auc": metrics.get("pr_auc"),
                "accuracy": metrics.get("accuracy"),
                "precision": metrics.get("precision"),
                "recall": metrics.get("recall"),
                "f1_score": metrics.get("f1_score"),
                "tpr_at_1pct_fpr": metrics.get("tpr_at_1pct_fpr"),
            }
            data.append(row)
        except Exception as e:
            print(f"Ошибка при чтении {metrics_file}: {e}")

    df = pd.DataFrame(data)
    if not df.empty:
        # Оставляем только последний запуск для каждой модели
        df = df.sort_values(by="timestamp", ascending=False).drop_duplicates(subset=["model"], keep="first")
        df = df.sort_values(by="model")
    
    return df

def format_output(df: pd.DataFrame, fmt: str):
    if df.empty:
        print("Нет данных для отображения.")
        return

    # Округляем числовые значения
    numeric_cols = ["roc_auc", "pr_auc", "accuracy", "precision", "recall", "f1_score", "tpr_at_1pct_fpr"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = df[col].apply(lambda x: round(x, 4) if pd.notnull(x) else "missing")

    display_cols = ["model", "roc_auc", "pr_auc", "tpr_at_1pct_fpr", "accuracy", "f1_score", "timestamp"]
    display_cols = [c for c in display_cols if c in df.columns]
    df_out = df[display_cols]

    if fmt == "json":
        print(df_out.to_json(orient="records", date_format="iso", indent=2))
    elif fmt == "csv":
        print(df_out.to_csv(index=False))
    elif fmt == "markdown":
        print(df_out.to_markdown(index=False))
    else:
        try:
            print(df_out.to_markdown(index=False))
        except ImportError:
            print(df_out.to_string(index=False))

def run_stats(artifacts_dir: str, model_name: str = None, fmt: str = "table"):
    df = load_all_metrics(artifacts_dir)
    
    if model_name:
        df = df[df["model"] == model_name]
        if df.empty:
            print(f"Статистика для модели '{model_name}' не найдена.")
            return

    format_output(df, fmt)