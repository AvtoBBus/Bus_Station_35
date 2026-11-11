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
    try:
        from .registry.loader import ModelRegistry
        ready = set(ModelRegistry().available_models)
    except Exception as exc:  # манифест не читается
        print(f"Warning: registry unavailable: {exc}", file=sys.stderr)
        ready = set()

    print(f"{'Model Name':<20} | {'Group':<10} | {'Artifacts':<12} | {'Train script':<13} | {'LODO script'}")
    print("-" * 80)
    for key, data in models.items():
        name = data.get("name", key)
        artifacts = "ready" if key in ready else "missing"
        train = "ok" if (ML_ROOT / data.get("train_script", "")).is_file() else "missing"
        lodo = "ok" if (ML_ROOT / data.get("evaluate_script", "")).is_file() else "missing"
        print(f"{name:<20} | {data.get('group', '-'):<10} | {artifacts:<12} | {train:<13} | {lodo}")


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


def cmd_lodo_summary(args):
    from .evaluation.summary_24 import main as summary_main
    sys.exit(summary_main())


def cmd_crs_compare(args):
    from .evaluation.crs_comparison import main as crs_main
    sys.exit(crs_main(args.crs_args))


def cmd_shap_reference(args):
    from .datasets.tools.make_shap_reference import main as ref_main
    sys.exit(ref_main(args.ref_args))


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

    subparsers.add_parser("lodo-summary", help="Item 2.4: compare models on LODO results").set_defaults(func=cmd_lodo_summary)

    p_crs = subparsers.add_parser("crs-compare", help="Item 2.5: ML models vs OWASP CRS on one dataset")
    p_crs.add_argument("crs_args", nargs=argparse.REMAINDER, help="Arguments for crs_comparison (e.g. --models catboost)")
    p_crs.set_defaults(func=cmd_crs_compare)

    subparsers.add_parser("shap-reference", help="Make compact SHAP reference sample (ml/config/shap_reference_sample.csv)")

    subparsers.add_parser("adversarial", help="Run adversarial training for CatBoost").set_defaults(func=cmd_adversarial)

    argv = sys.argv[1:] if argv is None else list(argv)
    # argparse.REMAINDER плохо дружит с опциями в начале: передаём аргументы как есть
    if argv and argv[0] == "crs-compare":
        cmd_crs_compare(argparse.Namespace(crs_args=argv[1:]))
        return
    if argv and argv[0] == "shap-reference":
        cmd_shap_reference(argparse.Namespace(ref_args=argv[1:]))
        return
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
