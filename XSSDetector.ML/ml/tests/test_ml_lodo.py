import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from ml.evaluation.lodo_sources import LODO_SOURCES, cap_per_class, select_lodo_sources
from ml.evaluation.summary_24 import build_summary
from ml.training.metrics import calculate_metrics, tpr_at_1pct_fpr


class TprAt1PctFprTests(unittest.TestCase):
    def test_perfect_separation_gives_one_even_with_few_negatives(self):
        # Регрессия: прежняя реализация при числе нормальных < 100 возвращала ~0.0025
        for n_neg in (20, 50, 99, 100, 1000):
            y = np.array([0] * n_neg + [1] * 400)
            p = np.concatenate([np.linspace(0, 0.3, n_neg), np.linspace(0.7, 1, 400)])
            self.assertEqual(tpr_at_1pct_fpr(y, p), 1.0, n_neg)

    def test_one_class_is_undefined_not_zero(self):
        self.assertIsNone(tpr_at_1pct_fpr(np.ones(50, dtype=int), np.linspace(0, 1, 50)))
        self.assertIsNone(tpr_at_1pct_fpr(np.zeros(50, dtype=int), np.linspace(0, 1, 50)))

    def test_calculate_metrics_one_class_pr_auc_is_none(self):
        y = np.ones(30, dtype=int)
        m = calculate_metrics(y, y, np.linspace(0.5, 1, 30))
        self.assertIsNone(m["pr_auc"])


class SelectSourcesTests(unittest.TestCase):
    def _df(self):
        rows = []
        for src, (n0, n1) in {"csic2010": (100, 100), "vulnxss": (0, 200), "hard_benign": (200, 0), "kaggle": (5, 100)}.items():
            rows += [{"source": src, "label": 0}] * n0 + [{"source": src, "label": 1}] * n1
        return pd.DataFrame(rows)

    def test_only_two_class_sources_are_selected(self):
        sel = select_lodo_sources(self._df(), ["csic2010", "vulnxss", "hard_benign", "kaggle", "absent"], verbose=False)
        self.assertEqual(sel, ["csic2010"])

    def test_default_list_has_only_two_class_sources(self):
        for bad in ("fwaf", "vulnxss", "capec", "payloadbox", "hard_benign"):
            self.assertNotIn(bad, LODO_SOURCES)


class SummaryMaskingTests(unittest.TestCase):
    def test_one_class_rows_do_not_pollute_means(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            pd.DataFrame({
                "source": ["a", "b", "c", "vulnxss", "hard_benign"],
                "roc_auc": [0.9, 0.9, 0.9, np.nan, np.nan],
                "pr_auc": [0.9, 0.9, 0.9, 1.0, 0.0],
                "tpr_at_1pct_fpr": [0.8, 0.8, 0.8, 0.0, 0.0],
            }).to_csv(d / "lodo_results_catboost.csv", index=False)
            s = build_summary(d)
            row = s["by_model"].loc["catboost"]
            self.assertEqual(row["n_sources"], 3)
            self.assertAlmostEqual(row["pr_auc"], 0.9)
            self.assertAlmostEqual(row["tpr_at_1pct_fpr"], 0.8)
            self.assertEqual(s["single_class"]["catboost"], ["hard_benign", "vulnxss"])


class CapPerClassTests(unittest.TestCase):
    def test_caps_each_class_and_is_reproducible(self):
        y = np.array([0] * 1000 + [1] * 30)
        idx = cap_per_class(y, 100)
        self.assertEqual(int((y[idx] == 0).sum()), 100)
        self.assertEqual(int((y[idx] == 1).sum()), 30)       # все редкие атаки сохраняются
        self.assertEqual(len(set(idx.tolist())), len(idx))   # без повторов
        np.testing.assert_array_equal(idx, cap_per_class(y, 100))

    def test_non_positive_cap_keeps_everything(self):
        self.assertEqual(len(cap_per_class(np.array([0, 1, 0]), 0)), 3)


class LodoScriptsRegressionTests(unittest.TestCase):
    """Регрессия: выборка не должна ограничиваться ДО разбиения на источники, а CatBoost не должен
    выбирать итерацию на тестовом источнике."""

    def _src(self, model):
        path = Path(__file__).resolve().parents[1] / "models" / model / "evaluate_lodo.py"
        return path.read_text(encoding="utf-8-sig")

    def test_no_global_balancing_before_split(self):
        for model in ("lstm", "bilstm", "char_cnn", "catboost"):
            src = self._src(model)
            self.assertNotIn("df = pd.concat([df_0, df_1])", src, model)
            self.assertIn("cap_per_class(", src, model)

    def test_catboost_does_not_early_stop_on_test_source(self):
        src = self._src("catboost")
        self.assertNotIn("eval_set=test_pool", src)
        self.assertIn("eval_set=val_pool", src)


if __name__ == "__main__":
    unittest.main()
