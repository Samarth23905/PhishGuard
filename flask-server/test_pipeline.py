"""
End-to-end pipeline test — run after training models and starting server.
Usage: python test_pipeline.py
"""

import requests, json

SERVER = "http://localhost:5000"
TOKEN  = "changeme-secret-token"
HEADERS = {"Content-Type": "application/json", "X-Session-Token": TOKEN}

def test(name, payload, expected_verdict=None):
    print(f"\n── {name} {'─'*(50-len(name))}")
    r = requests.post(f"{SERVER}/analyze", json=payload, headers=HEADERS)
    data = r.json()
    verdict = data.get("verdict", "?")
    summary = data.get("summary", "")
    sms_sc  = data.get("sms_score", "N/A")
    status  = "✅" if (expected_verdict is None or verdict == expected_verdict) else "❌"
    print(f"  Status:     HTTP {r.status_code}")
    print(f"  Verdict:    {verdict} {status}")
    print(f"  SMS score:  {sms_sc}")
    print(f"  Summary:    {summary}")
    links = data.get("links_checked", [])
    for lnk in links:
        print(f"  Link [{lnk['verdict']}] url_score={lnk.get('url_score')} page_score={lnk.get('page_score')}")
        for r2 in lnk.get("reasons", []):
            print(f"    → {r2}")

# Health check
print("── Health Check ──────────────────────────────────────")
r = requests.get(f"{SERVER}/health")
print(json.dumps(r.json(), indent=2))

# Test 1: Trusted bank sender → SAFE
test("Trusted bank OTP", {
    "fcm_token": "test-token",
    "app_name":  "com.android.messaging",
    "sender":    "VM-HDFCBK",
    "text":      "Your HDFC OTP is 482910. Valid 10 mins. Do not share.",
    "links":     []
}, expected_verdict="SAFE")

# Test 2: Phishing SMS with bad URL → DANGEROUS or SUSPICIOUS
test("Phishing SMS with fake bank link", {
    "fcm_token": "test-token",
    "app_name":  "com.android.messaging",
    "sender":    "Unknown-5432",
    "text":      "URGENT: Your SBI account suspended! Verify: http://sbi-verify-now.xyz/login",
    "links":     ["http://sbi-verify-now.xyz/login"]
}, expected_verdict=None)

# Test 3: Prize scam SMS
test("Prize scam no links", {
    "fcm_token": "test-token",
    "app_name":  "com.android.messaging",
    "sender":    "AD-PROMO99",
    "text":      "Congratulations you have won Rs.50000 in our lucky draw! Claim your prize immediately by entering your bank details",
    "links":     []
}, expected_verdict=None)

# Test 4: Legitimate Swiggy delivery notification
test("Legit Swiggy notification", {
    "fcm_token": "test-token",
    "app_name":  "com.swiggy.android",
    "sender":    "Swiggy",
    "text":      "Your order from Dominos is out for delivery. Track on swiggy.com",
    "links":     ["https://www.swiggy.com/track/12345"]
}, expected_verdict="SAFE")

# Test 5: Unauthorized request
print("\n── Bad session token ──────────────────────────────────")
r = requests.post(f"{SERVER}/analyze", json={"fcm_token": "x"}, headers={**HEADERS, "X-Session-Token": "wrong"})
print(f"  Status: {r.status_code} (expected 401)")

print("\n✅ Tests complete.")
