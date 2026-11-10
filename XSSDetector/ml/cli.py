import argparse
import sys

import yaml

from .paths import ARTIFACTS_DIR, ML_ROOT, RESULTS_DIR
from .registry import run_stats
from .training import run_adversarial_training, run_evaluation, run_training

MODELS_CONFIG = ML_ROOT / "config" / "models.yaml"


def load_models_config() -> dict:
    if not MODELS_CONFIG.exists():
        print(f"Error: Config file not found at {MODELS_CONFIG}", file=sys.stderr)
        sys.exit(1)
    with open(MODELS_CONFIG, "r", encoding="utf-8-sig") as f:
        return yaml.safe_load(f)


def supported_models() -> list:
    return list(load_models_config().get("models", {}).keys())


def cmd_list_models(args):
    models = load_models_config().get("models", {})
    print(f"{'Model Name':<20} | {'Status':<15} | {'Legacy Script':<40} | {'Artifacts'}")
    print("-" * 110)
    for key, data in models.items():
        name = data.get("name", key)
        status = data.get("status", "unknown")
        legacy = data.get("legacy_script") or "-"
        artifacts = ", ".join(data.get("artifact_files", [])) or "none"
        print(f"{name:<20} | {status:<15} | {legacy:<40} | {artifacts}")


def _check_model(name: str) -> bool:
    if name not in supported_models():
        print(f"Unknown model '{name}'. Available: {', '.join(supported_models())}", file=sys.stderr)
        return False
    return True


def cmd_train(args):
    if args.model == "all":
        results = {name: run_training(name, args.dataset, args.artifacts_dir) for name in supported_models()}
        print("\nSummary:")
        for name, ok in results.items():
            print(f"  {name:<20} {'OK' if ok else 'FAILED'}")
        sys.exit(0 if all(results.values()) else 1)
    if not _check_model(args.model):
        sys.exit(2)
    sys.exit(0 if run_training(args.model, args.dataset, args.artifacts_dir) else 1)


def cmd_evaluate(args):
    if not _check_model(args.model):
        sys.exit(2)
    sys.exit(0 if run_evaluation(args.model, args.dataset, args.output_dir) else 1)


def cmd_adversarial(args):
    sys.exit(0 if run_adversarial_training() else 1)


def cmd_stats(args):
    if args.all:
        run_stats(args.artifacts_dir, model_name=None, fmt=args.format)
    elif args.model:
        run_stats(args.artifacts_dir, model_name=args.model, fmt=args.format)
    else:
        print("Error: specify --model <name> or --all", file=sys.stderr)
        sys.exit(2)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m ml", description="Unified CLI for XSS Detector ML pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-models", help="List all available models").set_defaults(func=cmd_list_models)

    p_train = subparsers.add_parser("train", help="Train a model (or 'all')")
    p_train.add_argument("--model", required=True, help="Model name or 'all'")
    p_train.add_argument("--dataset", help="Path to dataset")
    p_train.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR), help="Directory for run artifacts")
    p_train.set_defaults(func=cmd_train)

    p_eval = subparsers.add_parser("evaluate", help="Evaluate a model (LODO)")
    p_eval.add_argument("--model", required=True, help="Model name to evaluate")
    p_eval.add_argument("--dataset", help="Path to dataset")
    p_eval.add_argument("--output-dir", default=str(RESULTS_DIR), help="Directory for LODO results")
    p_eval.set_defaults(func=cmd_evaluate)

    p_stats = subparsers.add_parser("stats", help="Show model statistics")
    p_stats.add_argument("--model", help="Specific model name")
    p_stats.add_argument("--all", action="store_true", help="Show stats for all models")
    p_stats.add_argument("--format", default="table", choices=["table", "json", "csv", "markdown"], help="Output format")
    p_stats.add_argument("--artifacts-dir", default=str(ARTIFACTS_DIR), help="Directory with runs/")
    p_stats.set_defaults(func=cmd_stats)

    subparsers.add_parser("adversarial", help="Run adversarial training for CatBoost").set_defaults(func=cmd_adversarial)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
