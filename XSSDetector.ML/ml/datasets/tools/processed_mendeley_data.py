"""Load Mendeley data from CSV and rename its columns."""

from pathlib import Path
from typing import Mapping

import pandas as pd


def load_processed_mendeley_data(
	csv_path: str | Path,
	column_names: Mapping[str, str],
) -> pd.DataFrame:
	"""Read a CSV file and rename columns according to ``column_names``."""
	data = pd.read_csv(csv_path)
	return data.rename(columns=column_names)


if __name__ == "__main__":
    csv_path = Path('../raw/MendeleyData/xss_dataset.csv')
    column_names = {
        "Query": "text",
        "Label": "label",
    }
    df = load_processed_mendeley_data(csv_path, column_names)
    df['source'] = 'mendeley'
    print(df.head())
    df.to_csv('../processed/mendeley_data.csv', index=False)