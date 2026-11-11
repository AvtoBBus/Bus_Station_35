import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from ml.evaluation import crs_comparison as crs
from ml.evaluation.scoring import _positive_class, score_texts
from ml.evaluation.summary_24 import build_summary


class CrsTests(unittest.TestCase):
    def test_fpr_is_false_positive_rate_not_specificity(self):
        labels = np.array([0, 0, 0, 0, 1, 1])
        probs = np.array([0.1, 0.9, 0.1, 0.1, 0.9, 0.9])
        preds = (probs >= 0.5).astype(int)
        res = crs.summarize_scores("x", "ML", labels, probs, preds=preds)
        self.assertAlmostEqual(res["fpr"], 0.25)   # 1 из 4 нормальных
        self.assertAlmostEqual(res["tnr"], 0.75)
        self.assertEqual(res["n_test"], 6)

    def test_crs_levels_flag_more_with_higher_paranoia(self):
        texts = ["hello world", "id=5&name=bob", "<script>alert(1)</script>", "a=b;c=d"]
        labels = [0, 0, 1, 0]
        fprs = [crs.evaluate_crs_on_dataset(texts, labels, pl)["fpr"] for pl in (1, 2, 3, 4)]
        self.assertEqual(fprs, sorted(fprs))       # FPR не убывает с уровнем паранойи
        self.assertGreater(fprs[-1], fprs[0])


class ScoringTests(unittest.TestCase):
    def test_positive_class_shapes(self):
        self.assertEqual(_positive_class(np.array([[0.2, 0.8], [0.9, 0.1]])).tolist(), [0.8, 0.1])
        self.assertEqual(_positive_class(np.array([[0.8], [0.1]])).tolist(), [0.8, 0.1])

    def test_nn_adapter_is_batched_and_missing_model_is_none(self):
        class Fake:
            def __init__(self): self.calls = 0
            def predict_proba(self, texts):
                self.calls += 1
                return np.full((len(texts), 1), 0.5)
        fake = Fake()
        out = score_texts("lstm", ["a"] * 1200, adapter=fake, batch_size=500)
        self.assertEqual(len(out), 1200)
        self.assertEqual(fake.calls, 3)


def _lodo(directory: Path, name: str, rows: dict, metric_values=None):
    """rows: {source: (roc_auc, tpr_at_1pct_fpr, pr_auc)}"""
    pd.DataFrame(
        [{"source": s, "roc_auc": v[0], "tpr_at_1pct_fpr": v[1], "pr_auc": v[2]} for s, v in rows.items()]
    ).to_csv(directory / name, index=False)


class Summary24Tests(unittest.TestCase):
    def test_old_and_new_formats_are_normalised_and_missing_reported(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            pd.DataFrame({"model": ["rf", "rf"], "source": ["a", "b"], "pr_auc": [0.9, 0.8], "roc_auc": [0.9, 0.8],
                          "tpr_at_1pct_fpr": [0.5, 0.4], "negative_fpr": [0.1, 0.1]}).to_csv(d / "lodo_classical.csv", index=False)
            # новый формат: источник в индексе, колонка tpr@1%fpr, имя модели из имени файла
            pd.DataFrame({"roc_auc": [0.7, 0.6], "pr_auc": [0.7, 0.6], "tpr@1%fpr": [0.3, 0.2]},
                         index=["a", "b"]).to_csv(d / "lodo_results_charcnn.csv")
            s = build_summary(d)
            self.assertEqual(s["present"], ["char_cnn", "random_forest"])
            self.assertIn("catboost", s["missing"])
            self.assertEqual(s["common_sources"], ["a", "b"])
            self.assertTrue(s["verdict"]["preliminary"])

    def test_source_names_are_matched_across_spellings(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            _lodo(d, "lodo_results_rf.csv", {"csic2010": (0.9, 0.8, 0.9), "kaggle": (0.9, 0.8, 0.9), "ecmlpkdd2007": (0.9, 0.8, 0.9)})
            _lodo(d, "lodo_results_lstm.csv", {"CSIC-2010": (0.8, 0.5, 0.8), "Kaggle": (0.8, 0.5, 0.8), "ecml_pkdd_2007": (0.8, 0.5, 0.8)})
            self.assertEqual(build_summary(d)["common_sources"], ["csic2010", "ecmlpkdd2007", "kaggle"])

    def test_too_few_common_sources_gives_no_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            _lodo(d, "lodo_results_rf.csv", {"a": (0.9, 0.8, 0.9), "b": (0.9, 0.8, 0.9), "c": (0.9, 0.8, 0.9)})
            _lodo(d, "lodo_results_lstm.csv", {"b": (0.5, 0.1, 0.5), "c": (0.5, 0.1, 0.5), "x": (0.5, 0.1, 0.5)})
            v = build_summary(d)["verdict"]
            self.assertTrue(v["insufficient"])
            self.assertEqual(v["metrics"], {})
            self.assertIn("Недостаточно общих источников", v["text"])

    def test_verdict_per_metric_when_enough_sources(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            rich = {s: (0.9, 0.8, 0.9) for s in "abc"}
            poor = {s: (0.6, 0.2, 0.9) for s in "abc"}   # PR-AUC такой же, ROC и TPR хуже
            _lodo(d, "lodo_results_rf.csv", rich)
            _lodo(d, "lodo_results_lstm.csv", poor)
            v = build_summary(d)["verdict"]
            self.assertFalse(v["insufficient"])
            self.assertEqual(v["metrics"]["roc_auc"]["result"], "classical_better")
            self.assertEqual(v["metrics"]["pr_auc"]["result"], "no_difference")
            self.assertIn("не превосходят", v["text"])

    def test_conflicting_metrics_give_no_single_answer(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            _lodo(d, "lodo_results_rf.csv", {s: (0.7, 0.9, 0.7) for s in "abc"})
            _lodo(d, "lodo_results_lstm.csv", {s: (0.9, 0.3, 0.9) for s in "abc"})
            self.assertIn("расходятся", build_summary(d)["verdict"]["text"])


if __name__ == "__main__":
    unittest.main()
