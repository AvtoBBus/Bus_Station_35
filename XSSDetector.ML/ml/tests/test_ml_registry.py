import json
import tempfile
import unittest
from pathlib import Path

from ml.registry.loader import ML_ROOT, ModelRegistry


class RegistryTests(unittest.TestCase):
    def _registry(self, active):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "manifest.json"
        p.write_text(json.dumps({"active_models": active}), encoding="utf-8")
        return ModelRegistry(str(p))

    def test_relative_paths_resolve_against_ml_root_not_cwd(self):
        reg = self._registry({"svm": {"version": "v1", "path": "models/svm/weights/x.pkl"}})
        info = reg.get_active_model_info("svm")
        self.assertEqual(Path(info["path"]), ML_ROOT / "models/svm/weights/x.pkl")
        self.assertEqual(info["version"], "v1")

    def test_unknown_model_raises(self):
        with self.assertRaises(ValueError):
            self._registry({}).get_active_model_info("nope")

    def test_real_manifest_has_no_cwd_relative_prefix(self):
        manifest = json.loads((ML_ROOT / "registry" / "manifest.json").read_text(encoding="utf-8-sig"))
        for name, info in manifest["active_models"].items():
            for key, value in info.items():
                if key != "version":
                    self.assertFalse(str(value).startswith("XSSDetector.ML/"), f"{name}.{key}")

    def test_available_models_requires_existing_non_empty_artifacts(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = Path(d.name)
        (root / "ok.pkl").write_text("x")
        (root / "full_dir").mkdir()
        (root / "full_dir" / "w.bin").write_text("x")
        (root / "empty_dir").mkdir()
        reg = self._registry({
            "present": {"version": "v1", "path": str(root / "ok.pkl")},
            "present_dir": {"version": "v1", "path": str(root / "full_dir")},
            "absent": {"version": "v1", "path": str(root / "nope.pkl")},
            "empty": {"version": "v1", "path": str(root / "empty_dir")},
        })
        self.assertEqual(sorted(reg.available_models), ["present", "present_dir"])


if __name__ == "__main__":
    unittest.main()
