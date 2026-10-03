from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
from catboost import Pool

from .extract_features import extract_features
from .preprocess import decode_recursive

_shap = None
REFERENCE_DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / 'datasets_test'
    / 'xss_dataset.csv'
)
_GLOBAL_IMPORTANCE_CACHE = {}


def _get_shap():
    global _shap
    if _shap is None:
        import shap
        _shap = shap
    return _shap


def explain_catboost(model, metadata, features_df: pd.DataFrame, top_n: int = 5) -> list[dict]:
    """Return local CatBoost TreeSHAP contributions in raw-score units."""
    cat_features = metadata.get('cat_features', [])
    pool = features_df.copy()
    for col in cat_features:
        if col in pool.columns:
            pool[col] = pool[col].astype('category')

    text_features = ['text'] if 'text' in pool.columns else None
    pool_obj = Pool(
        pool,
        feature_names=list(pool.columns),
        cat_features=cat_features,
        text_features=text_features,
    )
    contributions = _catboost_shap_values(model, pool_obj)[0]

    results = []
    feature_names = list(features_df.columns)
    indices = np.argsort(np.abs(contributions))[::-1][:top_n]

    for idx in indices:
        if abs(contributions[idx]) > 1e-6:
            value = features_df.iloc[0, idx]
            results.append({
                'feature': feature_names[idx],
                'value': float(value) if isinstance(value, (int, float, np.integer, np.floating)) else str(value),
                'contribution': float(contributions[idx]),
            })

    return results


def _catboost_shap_values(model, pool: Pool) -> np.ndarray:
    values = np.asarray(model.get_feature_importance(pool, type='ShapValues'))
    expected_width = pool.num_col() + 1
    if values.ndim != 2 or values.shape[1] != expected_width:
        raise ValueError(
            f'Expected CatBoost SHAP values with shape (rows, {expected_width}), '
            f'got {values.shape}'
        )
    return values[:, :-1]


@lru_cache(maxsize=4)
def _load_reference_features(
    feature_names: tuple[str, ...],
    cat_features: tuple[str, ...],
    n_samples: int,
) -> pd.DataFrame:
    if not REFERENCE_DATA_PATH.is_file():
        raise FileNotFoundError(f'Local SHAP reference data not found: {REFERENCE_DATA_PATH}')

    reference = pd.read_csv(
        REFERENCE_DATA_PATH,
        usecols=['text', 'label', 'source'],
    ).dropna(subset=['text', 'label', 'source'])
    groups = list(reference.groupby(['source', 'label'], sort=True))
    if not groups:
        raise ValueError('Local SHAP reference dataset has no labeled rows')

    sample_size = min(n_samples, len(reference))
    per_group, remainder = divmod(sample_size, len(groups))
    samples = []
    for index, (_, group) in enumerate(groups):
        group_size = per_group + (index < remainder)
        if group_size:
            samples.append(group.sample(n=min(group_size, len(group)), random_state=42))

    reference_sample = pd.concat(samples, ignore_index=True)
    features = pd.DataFrame([
        extract_features(decode_recursive(str(text)))
        for text in reference_sample['text']
    ]).reindex(columns=feature_names, fill_value=0)

    for feature in cat_features:
        if feature in features.columns:
            features[feature] = features[feature].astype('category')

    return features


def load_global_reference_features(metadata: dict, n_samples: int = 512) -> pd.DataFrame:
    """Load a deterministic local sample stratified by source and label."""
    feature_names = tuple(metadata['feature_names'])
    cat_features = tuple(metadata.get('cat_features', []))
    return _load_reference_features(feature_names, cat_features, n_samples).copy()


def explain_tree_model(
    model,
    features_df: pd.DataFrame,
    top_n: int = 5,
    background_df: pd.DataFrame | None = None,
) -> list[dict]:
    shap = _get_shap()
    model_type = type(model).__name__
    background = background_df if background_df is not None else features_df

    if 'Forest' in model_type or 'Gradient' in model_type or 'Decision' in model_type:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(features_df)
    elif 'Logistic' in model_type:
        background_sample = background.sample(min(100, len(background)), random_state=42)
        explainer = shap.LinearExplainer(model, background_sample)
        shap_values = explainer.shap_values(features_df)
    else:
        background_sample = shap.sample(background, min(20, len(background)))
        explainer = shap.KernelExplainer(model.predict_proba, background_sample)
        shap_values = explainer.shap_values(features_df, nsamples=100)

    if isinstance(shap_values, list):
        values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
    else:
        values = np.asarray(shap_values)
        if values.ndim == 3:
            values = values[:, :, 1] if values.shape[-1] > 1 else values[:, :, 0]

    contributions = values[0] if len(values.shape) > 1 else values
    results = []
    feature_names = list(features_df.columns)
    indices = np.argsort(np.abs(contributions))[::-1][:top_n]

    for idx in indices:
        if abs(contributions[idx]) > 1e-6:
            value = features_df.iloc[0, idx]
            results.append({
                'feature': feature_names[idx],
                'value': float(value) if isinstance(value, (int, float, np.integer, np.floating)) else str(value),
                'contribution': float(contributions[idx]),
            })

    return results


def explain_transformer(
    model, tokenizer, text: str, max_len: int, top_n: int = 5
) -> list[dict]:
    """Explain Transformer token embeddings with Integrated Gradients."""
    import torch

    encoded = tokenizer(
        text,
        return_tensors='pt',
        truncation=True,
        max_length=max_len,
        padding='max_length',
    )
    input_ids = encoded['input_ids']
    attention_mask = encoded['attention_mask']
    input_embeddings = model.get_input_embeddings()(input_ids)
    baseline = torch.zeros_like(input_embeddings)
    delta = input_embeddings - baseline
    steps = 32
    alphas = torch.linspace(0.0, 1.0, steps).view(steps, 1, 1)
    interpolated = (baseline + alphas * delta).squeeze(1).requires_grad_(True)
    expanded_mask = attention_mask.expand(steps, -1)

    model.eval()
    outputs = model(
        inputs_embeds=interpolated,
        attention_mask=expanded_mask,
    ).logits
    gradients = torch.autograd.grad(outputs[:, 1].sum(), interpolated)[0]
    attributions = delta * gradients.mean(dim=0, keepdim=True)
    token_scores = attributions.sum(dim=-1)[0].detach().cpu().numpy()
    token_ids = input_ids[0].tolist()
    active_positions = [
        position
        for position, token_id in enumerate(token_ids)
        if attention_mask[0, position].item() and token_id not in tokenizer.all_special_ids
    ]
    ranked_positions = sorted(
        active_positions,
        key=lambda position: abs(token_scores[position]),
        reverse=True,
    )

    results = []
    for position in ranked_positions[:top_n]:
        token_id = token_ids[position]
        token = tokenizer.convert_ids_to_tokens(token_id)
        results.append({
            'feature': f'token[{position}]:{token}',
            'value': token,
            'contribution': float(token_scores[position]),
        })
    return results


def explain_lstm(model, tokenizer, text: str, max_len: int, top_n: int = 5) -> list[dict]:
    """Explain LSTM token embeddings with Integrated Gradients."""
    import tensorflow as tf
    from tensorflow import keras

    sequences = tokenizer.texts_to_sequences([text])
    token_ids = keras.preprocessing.sequence.pad_sequences(
        sequences, maxlen=max_len, padding='post', truncating='post'
    )
    embedding_layer = model.get_layer('embedding')
    embedding_size = embedding_layer.output_dim
    embedding_input = keras.Input(shape=(max_len, embedding_size), dtype='float32')
    hidden = embedding_input
    for layer in model.layers[1:]:
        hidden = layer(hidden, training=False)
    embedded_model = keras.Model(embedding_input, hidden)

    input_embeddings = embedding_layer(tf.convert_to_tensor(token_ids))
    baseline = tf.zeros_like(input_embeddings)
    delta = input_embeddings - baseline
    steps = 32
    alphas = tf.reshape(tf.linspace(0.0, 1.0, steps), (steps, 1, 1, 1))
    interpolated = tf.squeeze(baseline + alphas * delta, axis=1)

    with tf.GradientTape() as tape:
        tape.watch(interpolated)
        output = embedded_model(interpolated, training=False)
        target = tf.reduce_sum(output[:, 0])
    gradients = tape.gradient(target, interpolated)
    average_gradients = tf.reduce_mean(gradients, axis=0, keepdims=True)
    attributions = delta * average_gradients
    token_scores = tf.reduce_sum(attributions, axis=-1).numpy()[0]
    active_positions = np.flatnonzero(token_ids[0])
    ranked_positions = sorted(active_positions, key=lambda pos: abs(token_scores[pos]), reverse=True)

    results = []
    for position in ranked_positions[:top_n]:
        token_id = int(token_ids[0, position])
        token = tokenizer.index_word.get(token_id, str(token_id))
        results.append({
            'feature': f'token[{position}]:{token}',
            'value': token,
            'contribution': float(token_scores[position]),
        })
    return results


def global_feature_importance(model, metadata: dict, reference_data: pd.DataFrame,
                             n_samples: int = 512, top_n: int = 10) -> list[dict]:
    sample_count = min(n_samples, len(reference_data))
    cache_key = (id(model), tuple(reference_data.columns), sample_count, top_n)
    if cache_key in _GLOBAL_IMPORTANCE_CACHE:
        return [dict(item) for item in _GLOBAL_IMPORTANCE_CACHE[cache_key]]

    sample = reference_data.sample(sample_count, random_state=42)
    cat_features = metadata.get('cat_features', [])
    for col in cat_features:
        if col in sample.columns:
            sample[col] = sample[col].astype('category')

    text_features = ['text'] if 'text' in sample.columns else None
    sample_pool = Pool(
        sample,
        feature_names=list(sample.columns),
        cat_features=cat_features,
        text_features=text_features,
    )
    shap_values = _catboost_shap_values(model, sample_pool)
    mean_abs_shap = np.mean(np.abs(shap_values), axis=0)

    feature_names = list(sample.columns)
    indices = np.argsort(mean_abs_shap)[::-1][:top_n]
    results = [
        {
            'feature': feature_names[idx],
            'mean_abs_shap': float(mean_abs_shap[idx]),
        }
        for idx in indices
    ]
    _GLOBAL_IMPORTANCE_CACHE[cache_key] = tuple(dict(item) for item in results)
    return results


def global_model_feature_importance(
    model,
    model_name: str,
    reference_data: pd.DataFrame,
    scaler=None,
    n_samples: int = 128,
    top_n: int = 10,
    kernel_samples: int = 100,
) -> list[dict]:
    """Compute mean absolute SHAP on a deterministic held-out sample."""
    shap = _get_shap()
    sample = reference_data.sample(min(n_samples, len(reference_data)), random_state=42)
    background = reference_data.sample(min(32, len(reference_data)), random_state=43)
    if scaler is not None:
        sample = pd.DataFrame(scaler.transform(sample), columns=sample.columns)
        background = pd.DataFrame(scaler.transform(background), columns=background.columns)

    if model_name == 'rf':
        explainer = shap.TreeExplainer(model)
        raw_values = explainer.shap_values(sample)
    elif model_name == 'lr':
        explainer = shap.LinearExplainer(model, background)
        raw_values = explainer.shap_values(sample)
    elif model_name == 'svm':
        explainer = shap.KernelExplainer(model.predict_proba, background)
        raw_values = explainer.shap_values(sample, nsamples=kernel_samples)
    else:
        raise ValueError(f'Unsupported tabular SHAP model: {model_name}')

    if isinstance(raw_values, list):
        values = np.asarray(raw_values[1] if len(raw_values) > 1 else raw_values[0])
    else:
        values = np.asarray(raw_values)
        if values.ndim == 3:
            values = values[:, :, 1] if values.shape[-1] > 1 else values[:, :, 0]
    if values.ndim != 2 or values.shape[1] != sample.shape[1]:
        raise ValueError(f'Unexpected SHAP shape for {model_name}: {values.shape}')

    mean_abs_shap = np.mean(np.abs(values), axis=0)
    indices = np.argsort(mean_abs_shap)[::-1][:top_n]
    return [
        {
            'feature': str(sample.columns[index]),
            'mean_abs_shap': float(mean_abs_shap[index]),
        }
        for index in indices
    ]


def diagnose_bias(global_importance: list[dict]) -> dict:
    length_features = {'length', 'url_length', 'html_length', 'js_max_length',
                       'js_string_max_length', 'entropy', 'word_count',
                       'url_special_characters', 'special_char_ratio'}

    top5 = global_importance[:5]
    top5_names = {f['feature'] for f in top5}
    length_dominance = len(top5_names & length_features)
    biased = length_dominance >= 3

    if biased:
        warning = (
            f"Potential length/entropy artifact: {length_dominance}/5 top features are "
            f"length/entropy-related ({', '.join(sorted(top5_names & length_features))}). "
            f"Review these global SHAP rankings against semantic features and held-out results."
        )
    else:
        warning = "No strong length/entropy concentration among the five most influential global SHAP features."

    return {
        'biased': biased,
        'warning': warning,
        'top_features': top5,
    }
