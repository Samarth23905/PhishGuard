"""
PhishGuard DL Engine
=====================
Loads all 3 trained DL models and exposes predict() methods.
Called by link_checker.py and sms_checker.py at inference time.

Models are loaded once at startup (lazy singleton) — fast per-request.
"""

import os
import re
import json
import pickle
import logging
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent.parent / "models"

# Lazy-loaded singletons
_url_model   = None
_sms_model   = None
_page_model  = None
_sms_tok     = None
_page_tok    = None
_url_cfg     = {}
_sms_cfg     = {}
_page_cfg    = {}
_tf          = None   # TensorFlow loaded on first use


def _load_tf():
    global _tf
    if _tf is None:
        os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
        import tensorflow as tf
        _tf = tf
        logger.info(f"TensorFlow {tf.__version__} loaded")
    return _tf


def _load_url_model():
    global _url_model, _url_cfg
    if _url_model is None:
        tf = _load_tf()
        model_path = MODELS_DIR / "url_model.keras"
        cfg_path   = MODELS_DIR / "url_model_config.json"
        if not model_path.exists():
            logger.warning(f"URL model not found at {model_path} — run training/train_all.py")
            return None, {}
        _url_model = tf.keras.models.load_model(str(model_path))
        with open(cfg_path) as f:
            _url_cfg = json.load(f)
        logger.info("URL model loaded")
    return _url_model, _url_cfg


def _load_sms_model():
    global _sms_model, _sms_tok, _sms_cfg
    if _sms_model is None:
        tf = _load_tf()
        model_path = MODELS_DIR / "sms_model.keras"
        tok_path   = MODELS_DIR / "sms_tokenizer.pkl"
        cfg_path   = MODELS_DIR / "sms_model_config.json"
        if not model_path.exists():
            logger.warning(f"SMS model not found at {model_path}")
            return None, None, {}
        _sms_model = tf.keras.models.load_model(str(model_path))
        with open(tok_path, "rb") as f:
            _sms_tok = pickle.load(f)
        with open(cfg_path) as f:
            _sms_cfg = json.load(f)
        logger.info("SMS model loaded")
    return _sms_model, _sms_tok, _sms_cfg


def _load_page_model():
    global _page_model, _page_tok, _page_cfg
    if _page_model is None:
        tf = _load_tf()
        model_path = MODELS_DIR / "page_model.keras"
        tok_path   = MODELS_DIR / "page_tokenizer.pkl"
        cfg_path   = MODELS_DIR / "page_model_config.json"
        if not model_path.exists():
            logger.warning(f"Page model not found at {model_path}")
            return None, None, {}
        _page_model = tf.keras.models.load_model(str(model_path))
        with open(tok_path, "rb") as f:
            _page_tok = pickle.load(f)
        with open(cfg_path) as f:
            _page_cfg = json.load(f)
        logger.info("Page content model loaded")
    return _page_model, _page_tok, _page_cfg


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def predict_url(url: str) -> dict:
    """
    Predict whether a URL is phishing using the CNN character-level model.
    Returns: { "score": float 0-1, "verdict": "SAFE"|"SUSPICIOUS"|"DANGEROUS" }
    """
    model, cfg = _load_url_model()
    if model is None:
        return {"score": 0.5, "verdict": "SUSPICIOUS", "reason": "URL model not trained yet"}

    tf = _load_tf()
    max_len = cfg.get("max_url_len", 200)

    seq = [min(ord(c), 127) for c in url[:max_len]]
    padded = tf.keras.preprocessing.sequence.pad_sequences(
        [seq], maxlen=max_len, padding="post", truncating="post"
    )
    score = float(model.predict(padded, verbose=0)[0][0])

    verdict = "SAFE"
    if score >= 0.75:
        verdict = "DANGEROUS"
    elif score >= 0.45:
        verdict = "SUSPICIOUS"

    return {"score": round(score, 4), "verdict": verdict, "reason": f"URL model confidence: {score:.1%}"}


def predict_sms(text: str) -> dict:
    """
    Predict whether an SMS/notification is smishing using the BiLSTM model.
    Returns: { "score": float 0-1, "verdict": "SAFE"|"SUSPICIOUS"|"DANGEROUS" }
    """
    model, tokenizer, cfg = _load_sms_model()
    if model is None:
        return {"score": 0.5, "verdict": "SUSPICIOUS", "reason": "SMS model not trained yet"}

    tf = _load_tf()
    max_len = cfg.get("max_seq_len", 100)

    seq = tokenizer.texts_to_sequences([text])
    padded = tf.keras.preprocessing.sequence.pad_sequences(
        seq, maxlen=max_len, padding="post", truncating="post"
    )
    score = float(model.predict(padded, verbose=0)[0][0])

    verdict = "SAFE"
    if score >= 0.78:
        verdict = "DANGEROUS"
    elif score >= 0.50:
        verdict = "SUSPICIOUS"

    return {"score": round(score, 4), "verdict": verdict, "reason": f"SMS model confidence: {score:.1%}"}


def predict_page(page_text: str) -> dict:
    """
    Predict whether page content is phishing using the LSTM model.
    Returns: { "score": float 0-1, "verdict": "SAFE"|"SUSPICIOUS"|"DANGEROUS" }
    """
    model, tokenizer, cfg = _load_page_model()
    if model is None:
        return {"score": 0.5, "verdict": "SUSPICIOUS", "reason": "Page model not trained yet"}

    tf = _load_tf()
    max_len = cfg.get("max_seq_len", 200)

    # Clean and truncate page text
    clean_text = re.sub(r'\s+', ' ', page_text.lower())[:2000]

    seq = tokenizer.texts_to_sequences([clean_text])
    padded = tf.keras.preprocessing.sequence.pad_sequences(
        seq, maxlen=max_len, padding="post", truncating="post"
    )
    score = float(model.predict(padded, verbose=0)[0][0])

    verdict = "SAFE"
    if score >= 0.72:
        verdict = "DANGEROUS"
    elif score >= 0.45:
        verdict = "SUSPICIOUS"

    return {"score": round(score, 4), "verdict": verdict, "reason": f"Page model confidence: {score:.1%}"}


def models_loaded() -> dict:
    """Health check — returns which models are available."""
    return {
        "url_model":  (MODELS_DIR / "url_model.keras").exists(),
        "sms_model":  (MODELS_DIR / "sms_model.keras").exists(),
        "page_model": (MODELS_DIR / "page_model.keras").exists(),
    }
