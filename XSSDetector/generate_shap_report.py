import importlib.util
import json
from pathlib import Path

import pandas as pd

from xssdetector.utils.load_models import (
    load_logistic_regression,
    load_random_forest,
    load_svm,
    _ensure_catboost,
)
from xssdetector.utils.shap_explainer import (
    diagnose_bias,
    global_feature_importance,
    global_model_feature_importance,
    load_global_reference_features,
)


ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = ROOT / 'results' / 'global_shap_heldout.json'


def main():
    catboost, metadata = _ensure_catboost()
    reference = load_global_reference_features(metadata, n_samples=128)
    report = {
        'reference_dataset': 'datasets_test/xss_dataset.csv',
        'stratification': ['source', 'label'],
        'sample_size': len(reference),
        'models': {},
        'neural_model_status': {
            'lstm': 'Local Integrated Gradients explanations are available; token rankings are not comparable to engineered-feature SHAP.',
            'transformer': 'Not verified: local checkpoint/dependencies are checked below.',
        },
        'notes': [
            'SHAP values describe model behavior on held-out examples; rankings are not causal proof.',
            'Transformer and LSTM token IG are local explanations and are not mixed with engineered-feature rankings.',
        ],
    }

    transformer_weights = ROOT / 'Transformer' / 'best_model' / 'model.safetensors'
    if not transformer_weights.is_file():
        report['neural_model_status']['transformer'] = 'Not verified: local model.safetensors is missing.'
    elif transformer_weights.read_bytes()[:80].startswith(b'version https://git-lfs.github.com/spec/v1'):
        report['neural_model_status']['transformer'] = (
            'Not verified: model.safetensors is a Git LFS pointer, not local model weights.'
        )
    elif importlib.util.find_spec('torch') is None or importlib.util.find_spec('transformers') is None:
        report['neural_model_status']['transformer'] = (
            'Not verified: torch and/or transformers are not installed in this Python environment.'
        )
    else:
        report['neural_model_status']['transformer'] = (
            'Local weights and dependencies are present; Transformer global token IG is not included '
            'in the engineered-feature comparison.'
        )

    catboost_importance = global_feature_importance(
        catboost, metadata, reference, n_samples=128, top_n=10
    )
    report['models']['catboost'] = {
        'method': 'CatBoost TreeSHAP',
        'sample_size': len(reference),
        'top_features': catboost_importance,
        'bias_diagnostic': diagnose_bias(catboost_importance),
    }

    feature_names = [name for name in metadata['feature_names'] if name != 'text']
    numeric_reference = reference.drop(columns=['text'], errors='ignore').reindex(
        columns=feature_names, fill_value=0
    )
    for feature in numeric_reference.columns:
        if isinstance(numeric_reference[feature].dtype, pd.CategoricalDtype):
            numeric_reference[feature] = numeric_reference[feature].astype(float)

    rf = load_random_forest()
    report['models']['rf'] = {
        'method': 'TreeSHAP',
        'sample_size': len(reference),
        'top_features': global_model_feature_importance(
            rf, 'rf', numeric_reference, n_samples=128, top_n=10
        ),
    }

    lr, lr_scaler = load_logistic_regression()
    report['models']['lr'] = {
        'method': 'LinearSHAP',
        'sample_size': len(reference),
        'top_features': global_model_feature_importance(
            lr, 'lr', numeric_reference, scaler=lr_scaler, n_samples=128, top_n=10
        ),
    }

    svm, svm_scaler = load_svm()
    report['models']['svm'] = {
        'method': 'KernelSHAP',
        'sample_size': len(reference),
        'top_features': global_model_feature_importance(
            svm,
            'svm',
            numeric_reference,
            scaler=svm_scaler,
            n_samples=128,
            top_n=10,
            kernel_samples=64,
        ),
    }

    for result in report['models'].values():
        result['bias_diagnostic'] = diagnose_bias(result['top_features'])

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'Wrote {OUTPUT_PATH}')
    for model_name, result in report['models'].items():
        top = ', '.join(item['feature'] for item in result['top_features'][:5])
        print(f'{model_name} ({result["method"]}, n={result["sample_size"]}): {top}')
        if 'bias_diagnostic' in result:
            print(result['bias_diagnostic']['warning'])


if __name__ == '__main__':
    main()
