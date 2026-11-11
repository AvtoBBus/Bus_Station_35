import json
import tempfile
import unittest
from pathlib import Path

from ml.registry.loader import ModelRegistry
from ml.serving.predictor import ModelManager


class ServingDegradationTests(unittest.TestCase):
    """Сервис не должен падать, если часть моделей не попала в образ (lite-сборка)."""

    def _manager(self, active):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        manifest = Path(d.name) / "manifest.json"
        manifest.write_text(json.dumps({"active_models": active}), encoding="utf-8")
        manager = ModelManager()
        manager.registry = ModelRegistry(str(manifest))
        return manager

    def test_unknown_model_returns_none(self):
        self.assertIsNone(self._manager({}).get_model("no_such_model"))

    def test_model_without_artifacts_returns_none_not_exception(self):
        manager = self._manager({"svm": {"version": "v1", "path": "/nonexistent/svm.pkl", "scaler": "/nonexistent/s.pkl"}})
        self.assertIsNone(manager.get_model("svm"))

    def test_predict_ensemble_reports_skipped_models(self):
        manager = self._manager({"svm": {"version": "v1", "path": "/nonexistent/svm.pkl", "scaler": "/nonexistent/s.pkl"}})
        result = manager.predict_ensemble("<script>alert(1)</script>", model_names=["svm"])
        self.assertIn("error", result)
        self.assertEqual(result["skipped_models"], ["svm"])

    def test_default_model_list_contains_only_models_on_disk(self):
        manager = self._manager({"svm": {"version": "v1", "path": "/nonexistent/svm.pkl", "scaler": "/nonexistent/s.pkl"}})
        self.assertEqual(manager.supported_models, [])


if __name__ == "__main__":
    unittest.main()
