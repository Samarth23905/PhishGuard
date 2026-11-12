"""PhishGuard DL API. Fail-closed authentication, bounded inputs and privacy-safe logs."""
import hmac
import logging
import os
import time
from collections import defaultdict, deque
from threading import Lock

from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequest

from utils.link_checker import check_link_safety
from utils.summarizer import summarize_notification
from utils.fcm_sender import send_fcm_notification
from utils.dl_engine import predict_sms, models_loaded

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("phishguard")
app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=32 * 1024, JSON_SORT_KEYS=False)
SESSION_TOKEN = os.environ.get("SESSION_TOKEN", "").strip()
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "30"))
_buckets = defaultdict(deque)
_bucket_lock = Lock()


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "application": "PhishGuard DL",
        "description": "Deep Learning Based Phishing Detection System",
        "status": "running",
        "version": "1.0",
        "available_endpoints": {
            "health": "/health",
            "analyze": "/analyze"
        }
    }), 200
    
def _authorized():
    supplied = request.headers.get("X-Session-Token", "")
    return bool(SESSION_TOKEN) and bool(supplied) and hmac.compare_digest(supplied, SESSION_TOKEN)


def _rate_limited():
    now = time.monotonic()
    key = request.remote_addr or "unknown"
    with _bucket_lock:
        q = _buckets[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= max(1, RATE_LIMIT):
            return True
        q.append(now)
        if len(_buckets) > 5000:
            for old_key in list(_buckets)[:1000]:
                if old_key != key and not _buckets[old_key]:
                    _buckets.pop(old_key, None)
    return False


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Request body exceeds 32 KB limit"}), 413


@app.route("/analyze", methods=["POST"])
def analyze():
    if not _authorized():
        return jsonify({"error": "Unauthorized; configure SESSION_TOKEN on the server"}), 401
    if _rate_limited():
        return jsonify({"error": "Rate limit exceeded"}), 429
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    try:
        data = request.get_json(silent=False)
    except BadRequest:
        return jsonify({"error": "Malformed JSON"}), 400
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    app_name = str(data.get("app_name", "Unknown App"))[:120]
    sender = str(data.get("sender", ""))[:200]
    message = str(data.get("text", ""))[:5000]
    fcm_token = str(data.get("fcm_token", ""))[:4096]
    links = data.get("links", [])
    if not isinstance(links, list) or len(links) > 5 or any(not isinstance(x, str) or len(x) > 2048 for x in links):
        return jsonify({"error": "links must be an array of at most 5 URLs, each <= 2048 characters"}), 400
    if not message and not links:
        return jsonify({"error": "Provide message text or at least one URL"}), 400

    # A trusted sender is a contextual hint, never a bypass for content inspection.
    sms_result = predict_sms(f"{sender} {message}".strip())
    sms_score = float(sms_result.get("score", 0.5))
    overall = sms_result.get("verdict", "SUSPICIOUS")
    if overall not in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        overall = "SUSPICIOUS"

    reports = []
    for candidate in links:
        report = check_link_safety(candidate)
        reports.append(report)
        if report["verdict"] == "DANGEROUS":
            overall = "DANGEROUS"
        elif report["verdict"] == "SUSPICIOUS" and overall != "DANGEROUS":
            overall = "SUSPICIOUS"

    summary = summarize_notification(app_name, sender, message, reports, overall, sms_score)
    result = {"verdict": overall, "summary": summary, "sms_score": round(sms_score, 4), "links_checked": reports, "layer_used": "dl_pipeline", "disclaimer": "Automated assessment; SAFE does not guarantee a message or website is legitimate."}
    # Never log message text, URLs, FCM tokens or sender identifiers.
    logger.info("Analysis completed: verdict=%s links=%d", overall, len(reports))
    if fcm_token:
        send_fcm_notification(fcm_token, app_name, sender, result)
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    ml = models_loaded()
    available = sum(bool(v) for v in ml.values())
    return jsonify({"status": "ready" if available == len(ml) else "degraded", "models": ml, "models_available": available, "models_expected": len(ml), "page_fetch_enabled": os.environ.get("PHISHGUARD_ENABLE_PAGE_FETCH", "false").lower() == "true"}), 200


from werkzeug.exceptions import HTTPException

@app.errorhandler(HTTPException)
def handle_http_exception(exc):
    return jsonify({
        "error": exc.name,
        "message": exc.description
    }), exc.code


@app.errorhandler(Exception)
def unhandled_error(exc):
    logger.exception(
        "Unhandled API error: %s",
        type(exc).__name__
    )

    return jsonify({
        "error": "Internal server error"
    }), 500


if __name__ == "__main__":
    if not SESSION_TOKEN:
        logger.warning("SESSION_TOKEN is unset; /analyze will reject all requests")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
