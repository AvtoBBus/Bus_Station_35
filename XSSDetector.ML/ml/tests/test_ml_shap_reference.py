import tempfile
import unittest
from pathlib import Path

import pandas as pd

from ml.datasets.tools.make_shap_reference import main, make_reference
from ml.paths import ML_ROOT, REFERENCE_SAMPLE


def _source_csv(directory: Path) -> Path:
    rows = []
    for source in ("a", "b"):
        for label in (0, 1):
            rows += [{"text": f"{source}{label}-{i}", "label": label, "source": source} for i in range(300)]
    path = directory / "src.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


class ShapReferenceTests(unittest.TestCase):
    def test_sample_is_stratified_and_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            src = _source_csv(Path(d))
            first = make_reference(src, n_samples=100)
            second = make_reference(src, n_samples=100)
            self.assertEqual(len(first), 100)
            self.assertEqual(first.groupby(["source", "label"]).size().tolist(), [25, 25, 25, 25])
            pd.testing.assert_frame_equal(first, second)

    def test_cli_entry_writes_file_and_missing_source_fails(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "ref.csv"
            self.assertEqual(main(["--source", str(_source_csv(Path(d))), "--n", "40", "--out", str(out)]), 0)
            self.assertEqual(len(pd.read_csv(out)), 40)
            self.assertEqual(main(["--source", str(Path(d) / "none.csv")]), 1)

    def test_reference_sample_lives_in_config_so_it_ships_in_docker_image(self):
        self.assertEqual(REFERENCE_SAMPLE.parent, ML_ROOT / "config")


if __name__ == "__main__":
    unittest.main()
