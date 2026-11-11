import contextlib
import io
import unittest

from ml import cli


class CliTests(unittest.TestCase):
    def test_list_models_prints_all_models(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["list-models"])
        for name in ("CatBoost", "Random Forest", "SVM", "Transformer"):
            self.assertIn(name, buf.getvalue())

    def test_list_models_shows_group_and_script_status(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["list-models"])
        self.assertIn("classical", buf.getvalue())
        self.assertIn("complex", buf.getvalue())
        self.assertNotIn("XSSDetector/", buf.getvalue())

    def test_unknown_model_exits_with_2(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["train", "--model", "no_such_model"])
        self.assertEqual(ctx.exception.code, 2)

    def test_stats_requires_target(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["stats"])
        self.assertEqual(ctx.exception.code, 2)

    def test_supported_models_match_config(self):
        self.assertIn("char_cnn", cli.supported_models())


if __name__ == "__main__":
    unittest.main()
