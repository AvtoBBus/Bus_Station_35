"""Char-level multi-kernel CNN for XSS detection."""

from __future__ import annotations

from tensorflow.keras import Input, Model
from tensorflow.keras.layers import Concatenate, Conv1D, Dense, Dropout, Embedding, GlobalMaxPooling1D
from tensorflow.keras.optimizers import Adam

from .char_sequence import VOCAB_SIZE


def build_char_cnn(
    max_len: int = 256,
    embedding_dim: int = 32,
    context_dim: int = 4,
    dropout: float = 0.3,
) -> Model:
    """
    Char-CNN with kernels 3/5/7 plus optional injection-context features.

    Trains from scratch, so LODO folds do not depend on a downloaded encoder.
    """
    tokens = Input(shape=(max_len,), dtype='int32', name='tokens')
    embedded = Embedding(VOCAB_SIZE, embedding_dim, mask_zero=False, name='char_embedding')(tokens)
    pooled = []
    for kernel in (3, 5, 7):
        conv = Conv1D(64, kernel, activation='relu', padding='same', name=f'conv_{kernel}')(embedded)
        pooled.append(GlobalMaxPooling1D(name=f'pool_{kernel}')(conv))
    merged = Concatenate(name='conv_concat')(pooled)

    if context_dim > 0:
        context = Input(shape=(context_dim,), dtype='float32', name='context')
        merged = Concatenate(name='with_context')([merged, context])
        inputs = [tokens, context]
    else:
        inputs = tokens

    hidden = Dense(64, activation='relu', name='dense')(merged)
    hidden = Dropout(dropout, name='dropout')(hidden)
    output = Dense(1, activation='sigmoid', name='xss')(hidden)
    model = Model(inputs=inputs, outputs=output, name='char_cnn_xss')
    model.compile(optimizer=Adam(learning_rate=1e-3), loss='binary_crossentropy', metrics=['accuracy'])
    return model
