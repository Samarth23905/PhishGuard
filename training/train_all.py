"""
PhishGuard DL — Train All Models
==================================
Trains all 3 DL models and saves them to flask-server/models/

  Model 1: url_model      — CNN on URL characters  (Layer 2)
  Model 2: sms_model      — LSTM on SMS text       (Layer 1)
  Model 3: page_model     — LSTM on page content   (Layer 3)

Run: python training/train_all.py
Requirements: pip install tensorflow scikit-learn pandas numpy
"""

import os
import sys
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"   # suppress TF noise

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    Embedding, Conv1D, GlobalMaxPooling1D,
    LSTM, Dense, Dropout, Bidirectional
)
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

BASE_DIR    = Path(__file__).parent.parent
DATA_DIR    = BASE_DIR / "datasets" / "processed"
MODELS_DIR  = BASE_DIR / "flask-server" / "models"
MODELS_DIR.mkdir(exist_ok=True)

print(f"TensorFlow version: {tf.__version__}")
print(f"Models will be saved to: {MODELS_DIR}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_dataset(filename):
    path = DATA_DIR / filename
    if not path.exists():
        print(f"❌ Dataset not found: {path}")
        print("   Run: python datasets/download_datasets.py first")
        sys.exit(1)
    df = pd.read_csv(path)
    print(f"Loaded {filename}: {len(df)} rows")
    return df


def prepare_binary_dataset(df, text_column, dataset_name):
    """Normalize labels, remove empty rows and eliminate exact-text leakage.

    Conflicting labels for the same normalized sample are discarded rather than
    arbitrarily assigning a class.
    """
    required = {text_column, "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{dataset_name} missing columns: {sorted(missing)}")
    work = df[[text_column, "label"]].copy()
    work[text_column] = work[text_column].fillna("").astype(str).str.strip()
    work["label"] = pd.to_numeric(work["label"], errors="coerce")
    work = work[(work[text_column] != "") & work["label"].isin([0, 1])]
    work["_normalized"] = work[text_column].str.lower().str.replace(r"\s+", " ", regex=True)
    conflicts = work.groupby("_normalized")["label"].nunique()
    conflicting = set(conflicts[conflicts > 1].index)
    if conflicting:
        print(f"  Removed {len(conflicting)} samples with conflicting labels")
        work = work[~work["_normalized"].isin(conflicting)]
    before = len(work)
    work = work.drop_duplicates("_normalized").drop(columns="_normalized")
    print(f"  Cleaned {dataset_name}: {before} unique rows")
    if len(work) < 10 or work["label"].nunique() != 2:
        raise ValueError(f"{dataset_name} needs at least 10 usable rows and both classes")
    return work[text_column].tolist(), work["label"].astype("int32").to_numpy()


def save_tokenizer(tokenizer, name):
    path = MODELS_DIR / f"{name}_tokenizer.pkl"
    with open(path, "wb") as f:
        pickle.dump(tokenizer, f)
    print(f"  Tokenizer saved: {path}")


def evaluate_model(model, X_test, y_test, name):
    y_pred = (model.predict(X_test, verbose=0) > 0.5).astype(int).flatten()
    print(f"\n  {name} — Test Results:")
    print(classification_report(y_test, y_pred,
          target_names=["Legitimate", "Phishing"]))
    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:\n{cm}")


# ─────────────────────────────────────────────────────────────────────────────
# MODEL 1 — URL Classifier (CNN on character sequences)
# Input : URL string  e.g. "http://hdfc-verify-now.xyz/login"
# Output: 0 = legitimate, 1 = phishing
# ─────────────────────────────────────────────────────────────────────────────

def train_url_model():
    print("=" * 60)
    print("Training Model 1: URL Classifier (CNN)")
    print("=" * 60)

    df = load_dataset("url_dataset.csv")
    urls, labels = prepare_binary_dataset(df, "url", "URL dataset")

    # Character-level tokenization — split URL into chars
    MAX_URL_LEN  = 200
    VOCAB_SIZE   = 128   # ASCII characters

    # Encode each URL as list of ASCII char codes
    def url_to_sequence(url, max_len=MAX_URL_LEN):
        seq = [min(ord(c), 127) for c in url[:max_len]]
        return seq

    X = [url_to_sequence(u) for u in urls]
    X = pad_sequences(X, maxlen=MAX_URL_LEN, padding="post", truncating="post")
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)}  |  Test: {len(X_test)}")

    model = Sequential([
        Embedding(input_dim=VOCAB_SIZE + 1, output_dim=64, input_length=MAX_URL_LEN),
        Conv1D(128, kernel_size=3, activation="relu"),
        Conv1D(64,  kernel_size=3, activation="relu"),
        GlobalMaxPooling1D(),
        Dense(64, activation="relu"),
        Dropout(0.4),
        Dense(1, activation="sigmoid")
    ])

    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.summary()

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=3, restore_best_weights=True),
    ]

    model.fit(
        X_train, y_train,
        validation_split=0.15,
        epochs=15,
        batch_size=32,
        callbacks=callbacks,
        verbose=1
    )

    evaluate_model(model, X_test, y_test, "URL Classifier")

    # Save model + config
    save_path = MODELS_DIR / "url_model.keras"
    model.save(save_path)
    print(f"  Model saved: {save_path}")

    config = {"max_url_len": MAX_URL_LEN, "vocab_size": VOCAB_SIZE}
    with open(MODELS_DIR / "url_model_config.json", "w") as f:
        json.dump(config, f)
    print("  Config saved.")


# ─────────────────────────────────────────────────────────────────────────────
# MODEL 2 — SMS Classifier (Bidirectional LSTM on message text)
# Input : SMS/notification text
# Output: 0 = legitimate, 1 = smishing
# ─────────────────────────────────────────────────────────────────────────────

def train_sms_model():
    print("\n" + "=" * 60)
    print("Training Model 2: SMS Classifier (BiLSTM)")
    print("=" * 60)

    df = load_dataset("sms_dataset.csv")
    texts, labels = prepare_binary_dataset(df, "text", "SMS dataset")

    MAX_WORDS  = 5000
    MAX_SEQ_LEN = 100
    text_train, text_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    tokenizer = Tokenizer(num_words=MAX_WORDS, oov_token="<OOV>")
    tokenizer.fit_on_texts(text_train)  # fit vocabulary on training data only
    X_train = pad_sequences(tokenizer.texts_to_sequences(text_train), maxlen=MAX_SEQ_LEN, padding="post", truncating="post")
    X_test = pad_sequences(tokenizer.texts_to_sequences(text_test), maxlen=MAX_SEQ_LEN, padding="post", truncating="post")
    print(f"  Vocab size: {min(len(tokenizer.word_index)+1, MAX_WORDS)}")
    print(f"  Train: {len(X_train)}  |  Test: {len(X_test)}")

    model = Sequential([
        Embedding(input_dim=MAX_WORDS, output_dim=64, input_length=MAX_SEQ_LEN),
        Bidirectional(LSTM(64, return_sequences=True)),
        Bidirectional(LSTM(32)),
        Dense(64, activation="relu"),
        Dropout(0.4),
        Dense(1, activation="sigmoid")
    ])

    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.summary()

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True),
    ]

    model.fit(
        X_train, y_train,
        validation_split=0.15,
        epochs=20,
        batch_size=16,
        callbacks=callbacks,
        verbose=1
    )

    evaluate_model(model, X_test, y_test, "SMS Classifier")

    save_path = MODELS_DIR / "sms_model.keras"
    model.save(save_path)
    print(f"  Model saved: {save_path}")

    save_tokenizer(tokenizer, "sms")

    config = {"max_words": MAX_WORDS, "max_seq_len": MAX_SEQ_LEN}
    with open(MODELS_DIR / "sms_model_config.json", "w") as f:
        json.dump(config, f)
    print("  Config saved.")


# ─────────────────────────────────────────────────────────────────────────────
# MODEL 3 — Page Content Classifier (LSTM on page text)
# Input : Extracted plain text from a webpage
# Output: 0 = legitimate page, 1 = phishing page
# ─────────────────────────────────────────────────────────────────────────────

def train_page_model():
    print("\n" + "=" * 60)
    print("Training Model 3: Page Content Classifier (LSTM)")
    print("=" * 60)

    df = load_dataset("page_dataset.csv")
    texts, labels = prepare_binary_dataset(df, "text", "Page dataset")

    MAX_WORDS   = 8000
    MAX_SEQ_LEN = 200
    text_train, text_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    tokenizer = Tokenizer(num_words=MAX_WORDS, oov_token="<OOV>")
    tokenizer.fit_on_texts(text_train)  # fit vocabulary on training data only
    X_train = pad_sequences(tokenizer.texts_to_sequences(text_train), maxlen=MAX_SEQ_LEN, padding="post", truncating="post")
    X_test = pad_sequences(tokenizer.texts_to_sequences(text_test), maxlen=MAX_SEQ_LEN, padding="post", truncating="post")
    print(f"  Vocab size: {min(len(tokenizer.word_index)+1, MAX_WORDS)}")
    print(f"  Train: {len(X_train)}  |  Test: {len(X_test)}")

    model = Sequential([
        Embedding(input_dim=MAX_WORDS, output_dim=128, input_length=MAX_SEQ_LEN),
        LSTM(128, return_sequences=True),
        LSTM(64),
        Dense(64, activation="relu"),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dense(1, activation="sigmoid")
    ])

    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.summary()

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True),
    ]

    model.fit(
        X_train, y_train,
        validation_split=0.15,
        epochs=20,
        batch_size=16,
        callbacks=callbacks,
        verbose=1
    )

    evaluate_model(model, X_test, y_test, "Page Content Classifier")

    save_path = MODELS_DIR / "page_model.keras"
    model.save(save_path)
    print(f"  Model saved: {save_path}")

    save_tokenizer(tokenizer, "page")

    config = {"max_words": MAX_WORDS, "max_seq_len": MAX_SEQ_LEN}
    with open(MODELS_DIR / "page_model_config.json", "w") as f:
        json.dump(config, f)
    print("  Config saved.")


# ─────────────────────────────────────────────────────────────────────────────
# Run all
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    train_url_model()
    train_sms_model()
    train_page_model()

    print("\n" + "=" * 60)
    print("✅ All 3 models trained and saved to flask-server/models/")
    print("   Files created:")
    for f in sorted(MODELS_DIR.iterdir()):
        size = f.stat().st_size / 1024
        print(f"   {f.name}  ({size:.1f} KB)")
    print("\n   Next: cd flask-server && python app.py")
    print("=" * 60)
