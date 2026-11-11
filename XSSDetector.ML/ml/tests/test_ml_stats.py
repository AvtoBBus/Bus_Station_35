import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ml.evaluation.advanced_metrics import tpr_at_fpr
from ml.registry.stats import load_all_metrics, run_stats


def _write_run(root: Path, name: str, model: str, cm, **extra):
    run = root / "runs" / name
    run.mkdir(parents=True)
    (run / "metrics.json").write_text(json.dumps({
        "model": model, "roc_auc": 0.9, "pr_auc": 0.8, "accuracy": 0.95,
        "f1_score": 0.9, "tpr_at_1pct_fpr": None, "confusion_matrix": cm, **extra}), encoding="utf-8")


class StatsTests(unittest.TestCase):
    def test_fpr_and_n_test_come_from_confusion_matrix(self):
        with tempfile.TemporaryDirectory() as d:
            _write_run(Path(d), "r1", "svm", [[90, 10], [5, 95]])
            row = load_all_metrics(d).iloc[0]
            self.assertEqual(row["n_test"], 200)
            self.assertAlmostEqual(row["fpr"], 0.1)

    def test_missing_metric_is_null_in_json_and_missing_in_table(self):
        with tempfile.TemporaryDirectory() as d:
            _write_run(Path(d), "r1", "svm", [[90, 10], [5, 95]])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_stats(d, "svm", "json")
            self.assertIsNone(json.loads(buf.getvalue())[0]["tpr_at_1pct_fpr"])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_stats(d, None, "table")
            self.assertIn("missing", buf.getvalue())

    def test_markdown_works_without_tabulate(self):
        with tempfile.TemporaryDirectory() as d:
            _write_run(Path(d), "r1", "svm", [[90, 10], [5, 95]])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run_stats(d, None, "markdown")
            self.assertIn("| model", buf.getvalue())

    def test_latest_run_per_model_only(self):
        with tempfile.TemporaryDirectory() as d:
            _write_run(Path(d), "old", "svm", [[1, 1], [1, 1]], timestamp="2026-01-01T00:00:00")
            _write_run(Path(d), "new", "svm", [[9, 1], [1, 9]], timestamp="2026-02-01T00:00:00")
            df = load_all_metrics(d)
            self.assertEqual(len(df), 1)
            self.assertEqual(df.iloc[0]["run_dir"], "new")


class TprAtFprTests(unittest.TestCase):
    def test_discrete_scores_do_not_overshoot_one_percent_fpr(self):
        # 100 негативов: у половины скор 1 (FPR 50%), все позитивы со скором 1.
        y = [0] * 100 + [1] * 10
        s = [1.0] * 50 + [0.0] * 50 + [1.0] * 10
        # при FPR <= 1% допустим только порог выше всех скоров => TPR = 0
        self.assertEqual(tpr_at_fpr(y, s, 0.01), 0.0)

    def test_perfect_separation(self):
        self.assertEqual(tpr_at_fpr([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9], 0.01), 1.0)


if __name__ == "__main__":
    unittest.main()
