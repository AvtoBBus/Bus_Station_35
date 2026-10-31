"""Character-level encoding for XSS sequence models."""

from __future__ import annotations

import numpy as np

PAD_ID = 0
UNK_ID = 1
CHAR_START = 32
CHAR_END = 126
VOCAB_SIZE = 2 + (CHAR_END - CHAR_START + 1)


def char_to_id(char: str) -> int:
    if not char:
        return PAD_ID
    code = ord(char[0])
    if CHAR_START <= code <= CHAR_END:
        return 2 + (code - CHAR_START)
    return UNK_ID


def encode_texts(texts: list[str] | np.ndarray, max_len: int = 256) -> np.ndarray:
    """Map strings to a padded integer matrix of printable-ASCII ids."""
    encoded = np.zeros((len(texts), max_len), dtype=np.int32)
    for row, text in enumerate(texts):
        value = '' if text is None else str(text)
        limit = min(len(value), max_len)
        for column in range(limit):
            encoded[row, column] = char_to_id(value[column])
    return encoded
