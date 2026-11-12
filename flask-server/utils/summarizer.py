"""
Path A Summarizer — No AI API needed.
Generates clear, human-readable summaries from DL model results.
Simple template-based logic — honest, direct, and zero cost.
"""

VERDICT_EMOJI = {
    "SAFE":      "✅",
    "SUSPICIOUS": "⚠️",
    "DANGEROUS":  "🚨",
}


def summarize_notification(
    app_name: str,
    sender: str,
    text: str,
    link_reports: list,
    overall_verdict: str,
    sms_score: float = None,
) -> str:
    emoji = VERDICT_EMOJI.get(overall_verdict, "ℹ️")
    sender_str = sender if sender else app_name

    # ── SAFE ─────────────────────────────────────────────────────────────
    if overall_verdict == "SAFE":
        if not link_reports:
            return f"{emoji} Message from {sender_str} — no links found. Looks legitimate."
        return f"{emoji} Message from {sender_str} looks legitimate. All links checked and verified safe."

    # ── Build reason summary ──────────────────────────────────────────────
    all_reasons = []
    dangerous_urls = []
    suspicious_urls = []

    for r in link_reports:
        if r["verdict"] == "DANGEROUS":
            dangerous_urls.append(r["url"])
        elif r["verdict"] == "SUSPICIOUS":
            suspicious_urls.append(r["url"])
        all_reasons.extend(r.get("reasons", []))

    # Pick the most relevant reason to show
    top_reason = ""
    priority_keywords = [
        "impersonate", "SSL", "redirect", "brand", "IP address",
        "confidence", "phishing", "unofficial"
    ]
    for kw in priority_keywords:
        for reason in all_reasons:
            if kw.lower() in reason.lower():
                top_reason = reason
                break
        if top_reason:
            break
    if not top_reason and all_reasons:
        top_reason = all_reasons[0]

    # ── DANGEROUS ─────────────────────────────────────────────────────────
    if overall_verdict == "DANGEROUS":
        n = len(dangerous_urls)
        url_part = f"{n} link{'s' if n > 1 else ''} flagged as dangerous"
        reason_part = f" ({top_reason})" if top_reason else ""
        return (
            f"{emoji} DANGER — Message from {sender_str}. "
            f"{url_part}{reason_part}. "
            f"Do NOT click any links or enter any details."
        )

    # ── SUSPICIOUS ────────────────────────────────────────────────────────
    n = len(suspicious_urls) + len(dangerous_urls)
    if n == 0 and sms_score and sms_score > 0.50:
        return (
            f"{emoji} Suspicious message from {sender_str}. "
            f"Message content pattern matches known phishing (score: {sms_score:.0%}). "
            f"Be cautious — verify through official app or customer care."
        )

    url_part = f"{n} link{'s' if n > 1 else ''} flagged" if n > 0 else "Link flagged"
    reason_part = f": {top_reason}" if top_reason else ""
    return (
        f"{emoji} Suspicious message from {sender_str}. "
        f"{url_part}{reason_part}. "
        f"Verify through official website or app before clicking."
    )
