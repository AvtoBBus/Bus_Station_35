import asyncio
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
XSS_ROOT = os.path.join(ROOT, 'xssdetector')
for path in (ROOT, XSS_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from xssdetector import main as api
from xssdetector.main import XSSBody, explain
from xssdetector.utils.shap_explainer import diagnose_bias
from xssdetector.utils import load_models


class ExplainBiasTest(unittest.TestCase):
    def test_explain_returns_local_and_global_shap_results(self):
        async def run_check():
            result = await explain(
                XSSBody(text='<script>alert(1)</script>', models=['catboost'])
            )

            self.assertEqual(result.explanation_model, 'catboost')
            self.assertEqual(result.explanation_method, 'CatBoost TreeSHAP')
            self.assertGreater(len(result.top_features), 0)
            self.assertTrue(all(math.isfinite(item['contribution']) for item in result.top_features))
            self.assertGreater(result.global_sample_size, 0)
            self.assertGreater(len(result.global_top_features), 0)
            self.assertTrue(
                all(math.isfinite(item['mean_abs_shap']) for item in result.global_top_features)
            )
            self.assertIsNotNone(result.bias_warning)
            self.assertGreaterEqual(len(result.bias_warning), 10)

        asyncio.run(run_check())

    def test_explain_supports_each_registered_model(self):
        expected_methods = {
            'rf': 'TreeSHAP',
            'lr': 'LinearSHAP',
            'svm': 'KernelSHAP',
            'lstm': 'Integrated Gradients',
        }
        for model_name, expected_method in expected_methods.items():
            with self.subTest(model=model_name):
                result = asyncio.run(explain(
                    XSSBody(text='<script>alert(1)</script>', models=[model_name])
                ))
                self.assertEqual(result.explanation_model, model_name)
                self.assertEqual(result.explanation_method, expected_method)
                self.assertGreater(len(result.top_features), 0)
                self.assertTrue(
                    all(math.isfinite(item['contribution']) for item in result.top_features)
                )

    def test_transformer_is_registered_for_predict_and_explain(self):
        fake_features = [{
            'feature': 'token[1]:alert',
            'value': 'alert',
            'contribution': 0.4,
        }]
        with (
            patch.dict(api.models_functions, {'transformer': lambda _text: (True, 0.99)}),
            patch.object(api, 'load_transformer', return_value=((object(), object()), 256)),
            patch.object(api, 'explain_transformer', return_value=fake_features),
        ):
            result = asyncio.run(api.explain(
                XSSBody(text='<script>alert(1)</script>', models=['transformer'])
            ))

        self.assertIn('transformer', api.models_functions)
        self.assertEqual(result.explanation_model, 'transformer')
        self.assertEqual(result.explanation_method, 'Integrated Gradients')
        self.assertEqual(result.top_features, fake_features)

    def test_transformer_unavailable_returns_service_unavailable(self):
        def unavailable(_text):
            raise RuntimeError('torch is not installed')

        with patch.dict(api.models_functions, {'transformer': unavailable}):
            with self.assertRaises(api.HTTPException) as context:
                asyncio.run(api.predict(
                    XSSBody(text='<script>alert(1)</script>', models=['transformer'])
                ))

        self.assertEqual(context.exception.status_code, 503)
        self.assertIn('Transformer is unavailable locally', context.exception.detail)

    def test_lfs_pointer_returns_clear_transformer_unavailable_response(self):
        with tempfile.TemporaryDirectory() as directory:
            model_dir = Path(directory) / 'best_model'
            model_dir.mkdir()
            (model_dir / 'model.safetensors').write_text(
                'version https://git-lfs.github.com/spec/v1\n'
                'oid sha256:local-test\nsize 267832560\n',
                encoding='ascii',
            )
            with patch.dict(load_models.MODEL_DIR, {'transformer': Path(directory)}):
                with self.assertRaises(api.HTTPException) as context:
                    asyncio.run(api.predict(
                        XSSBody(text='<script>alert(1)</script>', models=['transformer'])
                    ))

        self.assertEqual(context.exception.status_code, 503)
        self.assertIn('Transformer is unavailable locally', context.exception.detail)

    def test_bias_diagnostic_names_length_artifact_concentration(self):
        importance = [
            {'feature': 'length', 'mean_abs_shap': 0.5},
            {'feature': 'entropy', 'mean_abs_shap': 0.4},
            {'feature': 'js_max_length', 'mean_abs_shap': 0.3},
            {'feature': 'html_tag_script', 'mean_abs_shap': 0.2},
            {'feature': 'js_has_alert', 'mean_abs_shap': 0.1},
        ]
        result = diagnose_bias(importance)

        self.assertTrue(result['biased'])
        self.assertIn('3/5', result['warning'])
        self.assertEqual(len(result['top_features']), 5)


if __name__ == '__main__':
    unittest.main()
