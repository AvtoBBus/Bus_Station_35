"""Создаёт компактную референсную выборку для глобального SHAP (ml/config/shap_reference_sample.csv).

Выборка стратифицирована по (source, label) тем же алгоритмом, что и explainer._load_reference_features,
поэтому глобальная важность признаков в Docker-образе (без датасетов) считается на тех же примерах.

Запуск: python -m ml shap-reference [--source datasets_test/xss_dataset.csv] [--n 512]
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.append(str(Path(__file__).resolve().parents[3]))
from ml.paths import REFERENCE_SAMPLE, TEST_DATASET  # noqa: E402


def make_reference(source: Path, n_samples: int = 512, seed: int = 42) -> pd.DataFrame:
    reference = pd.read_csv(source, usecols=["text", "label", "source"]).dropna(subset=["text", "label", "source"])
    groups = list(reference.groupby(["source", "label"], sort=True))
    if not groups:
        raise ValueError("В исходном наборе нет размеченных строк")
    sample_size = min(n_samples, len(reference))
    per_group, remainder = divmod(sample_size, len(groups))
    parts = []
    for index, (_, group) in enumerate(groups):
        size = per_group + (index < remainder)
        if size:
            parts.append(group.sample(n=min(size, len(group)), random_state=seed))
    return pd.concat(parts, ignore_index=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Make SHAP reference sample")
    parser.add_argument("--source", default=str(TEST_DATASET), help="CSV с колонками text,label,source")
    parser.add_argument("--n", type=int, default=512, help="Размер выборки (как n_samples в /explain)")
    parser.add_argument("--out", default=str(REFERENCE_SAMPLE))
    args = parser.parse_args(argv)

    source = Path(args.source)
    if not source.is_file():
        print(f"Ошибка: источник не найден: {source}")
        return 1
    sample = make_reference(source, args.n)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(out, index=False)
    print(f"Сохранено {len(sample)} строк в {out} (групп source/label: {sample.groupby(['source', 'label']).ngroups})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
