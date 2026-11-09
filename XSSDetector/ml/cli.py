import argparse
import sys
import os
import yaml

# Добавляем корень ml в sys.path для импорта внутренних модулей
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from training import run_training, run_evaluation, run_adversarial_training
from registry import run_stats

def load_models_config():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(current_dir, "config", "models.yaml")
    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def cmd_list_models(args):
    config = load_models_config()
    models = config.get("models", {})
    print(f"{'Model Name':<20} | {'Status':<15} | {'Legacy Script':<40} | {'Artifacts'}")
    print("-" * 110)
    for key, data in models.items():
        name = data.get("name", key)
        status = data.get("status", "unknown")
        legacy = data.get("legacy_script")
        legacy_str = legacy if legacy else "-"
        artifacts = data.get("artifact_files", [])
        artifacts_str = ", ".join(artifacts) if artifacts else "none"
        print(f"{name:<20} | {status:<15} | {legacy_str:<40} | {artifacts_str}")

def cmd_train(args):
    supported_models = ["catboost", "logistic_regression", "lstm", "random_forest", "svm", "bilstm", "char_cnn", "transformer"]
    if args.model in supported_models:
        run_training(args.model, args.dataset, args.artifacts_dir)
    else:
        print(f"NOT_IMPLEMENTED: Обучение модели '{args.model}' еще не перенесено в скрипт.")
        print(f"Доступные для обучения модели: {', '.join(supported_models)}")

def cmd_evaluate(args):
    supported_models = ["catboost", "logistic_regression", "lstm", "random_forest", "svm", "bilstm", "char_cnn", "transformer"]
    if args.model in supported_models:
        run_evaluation(args.model, args.dataset, args.output_dir)
    else:
        print(f"NOT_IMPLEMENTED: Оценка модели '{args.model}' еще не перенесена.")

def cmd_adversarial(args):
    run_adversarial_training()

def cmd_stats(args):
    # Определяем путь к артефактам относительно текущего файла
    artifacts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts")
    if args.all:
        run_stats(artifacts_dir, model_name=None, fmt=args.format)
    elif args.model:
        run_stats(artifacts_dir, model_name=args.model, fmt=args.format)
    else:
        print("Ошибка: укажите --model <name> или --all")

def main():
    parser = argparse.ArgumentParser(prog="xssdetector.ml", description="Unified CLI for XSS Detector ML pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list-models
    subparsers.add_parser("list-models", help="List all available models").set_defaults(func=cmd_list_models)

    # train
    p_train = subparsers.add_parser("train", help="Train a model")
    p_train.add_argument("--model", type=str, required=True, help="Model name to train")
    p_train.add_argument("--dataset", type=str, help="Path to dataset")
    p_train.add_argument("--artifacts-dir", type=str, default="XSSDetector/ml/artifacts", help="Directory for artifacts")
    p_train.set_defaults(func=cmd_train)

    # evaluate
    p_eval = subparsers.add_parser("evaluate", help="Evaluate a model (LODO)")
    p_eval.add_argument("--model", type=str, required=True, help="Model name to evaluate")
    p_eval.add_argument("--dataset", type=str, help="Path to dataset")
    p_eval.add_argument("--output-dir", type=str, default="XSSDetector/results", help="Directory for LODO results")
    p_eval.set_defaults(func=cmd_evaluate)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show model statistics")
    p_stats.add_argument("--model", type=str, help="Specific model name")
    p_stats.add_argument("--all", action="store_true", help="Show stats for all models")
    p_stats.add_argument("--format", type=str, default="table", choices=["table", "json", "csv", "markdown"], help="Output format")
    p_stats.set_defaults(func=cmd_stats)

    p_adv = subparsers.add_parser("adversarial", help="Run adversarial training for CatBoost")
    p_adv.set_defaults(func=cmd_adversarial)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()