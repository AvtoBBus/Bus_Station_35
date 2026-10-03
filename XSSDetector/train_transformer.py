"""
DistilBERT-С‚СЂР°РЅСЃС„РѕСЂРјРµСЂ РґР»СЏ РѕР±РЅР°СЂСѓР¶РµРЅРёСЏ XSS.

Р”РѕРѕР±СѓС‡Р°РµРј РїСЂРµРґРѕР±СѓС‡РµРЅРЅС‹Р№ DistilBERT РЅР° РґРµРєРѕРґРёСЂРѕРІР°РЅРЅС‹С… XSS-РґР°РЅРЅС‹С….
РћР¶РёРґР°РЅРёРµ: С‚СЂР°РЅСЃС„РѕСЂРјРµСЂ РјРѕР¶РµС‚ Р»СѓС‡С€Рµ РѕР±РѕР±С‰Р°С‚СЊ РЅР° РЅРѕРІС‹С… РґР°РЅРЅС‹С… (LODO),
С‡РµРј hand-crafted features, Р·Р° СЃС‡С‘С‚ РїРѕРґСЃР»РѕРІРЅС‹С… С‚РѕРєРµРЅРѕРІ.

Р—Р°РїСѓСЃРє: python train_transformer.py
Р РµР·СѓР»СЊС‚Р°С‚: Transformer/best_model/, Transformer/tokenizer/
"""

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_curve, auc, roc_curve
import os
import sys
import json

# РџСѓС‚СЊ Рє utils
sys.path.insert(0, os.path.dirname(__file__))
from utils.preprocess import decode_recursive

OUTPUT_DIR = "./Transformer"
os.makedirs(OUTPUT_DIR, exist_ok=True)
TRAIN_MAX_SAMPLES = int(os.getenv("TRANSFORMER_MAX_TRAIN_SAMPLES", "0"))
TEST_MAX_SAMPLES = int(os.getenv("TRANSFORMER_MAX_TEST_SAMPLES", "0"))
NUM_EPOCHS = float(os.getenv("TRANSFORMER_EPOCHS", "3"))
TRAIN_BATCH_SIZE = int(os.getenv("TRANSFORMER_TRAIN_BATCH_SIZE", "16"))
EVAL_BATCH_SIZE = int(os.getenv("TRANSFORMER_EVAL_BATCH_SIZE", "64"))


def load_and_decode(path: str) -> tuple[list[str], np.ndarray]:
    """Р—Р°РіСЂСѓР¶Р°РµС‚ РґР°С‚Р°СЃРµС‚, РґРµРєРѕРґРёСЂСѓРµС‚ С‚РµРєСЃС‚С‹."""
    df = pd.read_csv(path)
    texts = df['text'].astype(str).tolist()
    labels = df['label'].values

    decoded = []
    n_changed = 0
    for t in texts:
        d = decode_recursive(t)
        if d != t:
            n_changed += 1
        decoded.append(d)

    print(f"  {path}: {len(texts)} РїСЂРёРјРµСЂРѕРІ, РґРµРєРѕРґРёСЂРѕРІР°РЅРѕ {n_changed}")
    return decoded, labels


def limit_samples(
    texts: list[str], labels: np.ndarray, limit: int, seed: int = 42
) -> tuple[list[str], np.ndarray]:
    """Returns a reproducible class-balanced subset when a positive limit is set."""
    if limit <= 0 or limit >= len(labels):
        return texts, labels

    rng = np.random.default_rng(seed)
    selected = []
    per_class = max(1, limit // len(np.unique(labels)))
    for label in np.unique(labels):
        indices = np.flatnonzero(labels == label)
        selected.extend(
            rng.choice(indices, size=min(per_class, len(indices)), replace=False)
        )

    selected = np.asarray(selected[:limit])
    rng.shuffle(selected)
    return [texts[index] for index in selected], labels[selected]


def main():
    from transformers import (
        DistilBertTokenizerFast,
        DistilBertForSequenceClassification,
        TrainingArguments,
        Trainer,
    )
    from datasets import Dataset
    import torch

    print("=" * 60)
    print("DistilBERT вЂ” РѕР±СѓС‡РµРЅРёРµ РЅР° РґРµРєРѕРґРёСЂРѕРІР°РЅРЅС‹С… XSS-РґР°РЅРЅС‹С…")
    print("=" * 60)

    # === Р—Р°РіСЂСѓР·РєР° РґР°РЅРЅС‹С… ===
    train_texts, train_labels = load_and_decode("./datasets_train/xss_dataset.csv")
    test_texts, test_labels = load_and_decode("./datasets_test/xss_dataset.csv")
    train_texts, train_labels = limit_samples(
        train_texts, train_labels, TRAIN_MAX_SAMPLES
    )
    test_texts, test_labels = limit_samples(
        test_texts, test_labels, TEST_MAX_SAMPLES, seed=43
    )

    # === РўРѕРєРµРЅРёР·Р°С†РёСЏ ===
    MODEL_NAME = "distilbert-base-uncased"
    MAX_LEN = 256

    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)

    def tokenize(examples):
        return tokenizer(examples["text"], truncation=True, padding="max_length", max_length=MAX_LEN)

    train_ds = Dataset.from_dict({"text": train_texts, "label": train_labels.tolist()})
    test_ds = Dataset.from_dict({"text": test_texts, "label": test_labels.tolist()})

    train_ds = train_ds.map(tokenize, batched=True, batch_size=256)
    test_ds = test_ds.map(tokenize, batched=True, batch_size=256)

    train_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
    test_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])

    # === РњРѕРґРµР»СЊ ===
    model = DistilBertForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
        id2label={0: "NORMAL", 1: "XSS"},
        label2id={"NORMAL": 0, "XSS": 1},
    )

    # === РћР±СѓС‡РµРЅРёРµ ===
    training_args = TrainingArguments(
        output_dir=os.path.join(OUTPUT_DIR, "checkpoints"),
        num_train_epochs=NUM_EPOCHS,
        per_device_train_batch_size=TRAIN_BATCH_SIZE,
        per_device_eval_batch_size=EVAL_BATCH_SIZE,
        warmup_steps=500,
        weight_decay=0.01,
        logging_strategy="steps",
        logging_steps=100,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        report_to="none",
        fp16=torch.cuda.is_available(),
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()[:, 1]
        preds = (probs >= 0.5).astype(int)
        auc_score = roc_auc_score(labels, probs)
        acc = (preds == labels).mean()
        return {"accuracy": float(acc), "auc": float(auc_score)}

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=test_ds,
        compute_metrics=compute_metrics,
    )

    print("\nРќР°С‡РёРЅР°РµРј РѕР±СѓС‡РµРЅРёРµ...")
    trainer.train()

    # === РћС†РµРЅРєР° ===
    print("\n" + "=" * 60)
    print("РћР¦Р•РќРљРђ РќРђ РўР•РЎРўРћР’РћРњ Р”РђРўРђРЎР•РўР•")
    print("=" * 60)

    predictions = trainer.predict(test_ds)
    probs = torch.softmax(torch.tensor(predictions.predictions), dim=-1).numpy()[:, 1]
    preds = (probs >= 0.5).astype(int)

    print(classification_report(test_labels, preds, target_names=["Normal", "XSS"]))
    print(f"AUC: {roc_auc_score(test_labels, probs):.4f}")

    precision_arr, recall_arr, _ = precision_recall_curve(test_labels, probs)
    pr_auc = auc(recall_arr, precision_arr)
    print(f"PR-AUC: {pr_auc:.4f}")

    fpr, tpr, _ = roc_curve(test_labels, probs)
    idx_1pct = np.searchsorted(fpr, 0.01)
    if idx_1pct < len(tpr):
        print(f"TPR@1%FPR: {tpr[idx_1pct]:.4f}")

    # === РЎРѕС…СЂР°РЅРµРЅРёРµ ===
    model.save_pretrained(os.path.join(OUTPUT_DIR, "best_model"))
    tokenizer.save_pretrained(os.path.join(OUTPUT_DIR, "tokenizer"))
    print(f"\nвњ… РњРѕРґРµР»СЊ СЃРѕС…СЂР°РЅРµРЅР° РІ {OUTPUT_DIR}/best_model/")
    print(f"вњ… РўРѕРєРµРЅРёР·Р°С‚РѕСЂ СЃРѕС…СЂР°РЅС‘РЅ РІ {OUTPUT_DIR}/tokenizer/")

    # === РўРµСЃС‚С‹ СѓСЃС‚РѕР№С‡РёРІРѕСЃС‚Рё ===
    print("\n" + "=" * 60)
    print("РўР•РЎРўР« РЈРЎРўРћР™Р§РР’РћРЎРўР Рљ РћР‘РҐРћР”РђРњ")
    print("=" * 60)

    evasion_tests = [
        ("<script>alert('XSS')</script>", "Р‘Р°Р·РѕРІС‹Р№ script"),
        ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL-encoded"),
        ("%253Cscript%253Ealert('XSS')%253C/script%253E", "Double URL-encoded"),
        ("<script>alert('XSS')</script>", "HTML entities"),
        ("<ScRiPt>AlErT('XSS')</ScRiPt>", "Mixed case"),
        ("\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e", "Unicode escape"),
        ('<img src=x onerror="alert(1)">', "Event handler"),
        ("<div class='post'>Hello world</div>", "Benign HTML"),
        ("This is a normal comment about <script> tags", "Benign with keyword"),
        ("javascript:alert(document.cookie)", "JS pseudo-protocol"),
    ]

    model.eval()
    for text, label in evasion_tests:
        decoded = decode_recursive(text)
        inputs = tokenizer(decoded, return_tensors="pt", truncation=True, max_length=MAX_LEN)
        with torch.no_grad():
            logits = model(**inputs).logits
        prob = torch.softmax(logits, dim=-1)[0][1].item()
        verdict = "XSS" if prob >= 0.5 else "NORMAL"
        print(f"  [{verdict:>6}] prob={prob:.3f} | {label}: {text[:60]}")


if __name__ == "__main__":
    main()




