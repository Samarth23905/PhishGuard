"""
PhishGuard DL — Dataset Downloader
====================================
Downloads and prepares all 3 datasets used for training:

  1. URL Dataset      — phishing + legitimate URLs (PhishTank + Alexa/Tranco)
  2. SMS Dataset      — smishing + ham messages (Mendeley Smishing Dataset)
  3. Page Content     — phishing + legit page text (synthetic + UCI features)

Run: python download_datasets.py
Output: datasets/raw/*.csv  and  datasets/processed/*.csv
"""

import os
import csv
import json
import time
import random
import requests
import zipfile
import io
import re
import hashlib
from pathlib import Path

RAW_DIR  = Path(__file__).parent / "raw"
PROC_DIR = Path(__file__).parent / "processed"
RAW_DIR.mkdir(exist_ok=True)
PROC_DIR.mkdir(exist_ok=True)

HEADERS = {"User-Agent": "PhishGuardResearch/1.0 (academic research; phishing detection)"}


# ─────────────────────────────────────────────────────────────────────────────
# 1. URL DATASET
# Source: PhishTank (phishing) + Tranco top-1M (legitimate)
# ─────────────────────────────────────────────────────────────────────────────

PHISHING_URLS_BUILTIN = [
    # Real-world phishing URL patterns (anonymised for training)
    "http://secure-hdfc-bank-verify.tk/login",
    "http://192.168.1.1/phish/sbi-login",
    "http://amazon-prize-winner.xyz/claim",
    "http://bit.ly/3xPhish99",
    "http://paypal-secure-update.ga/account",
    "http://apple-id-suspended.cf/verify",
    "http://netflix-billing-update.ml/payment",
    "http://faceb00k-login.tk/account",
    "http://google-account-suspended.xyz/verify",
    "http://microsoft-support-alert.ga/fix",
    "http://irs-tax-refund-2024.cf/claim",
    "http://dhl-parcel-tracking.xyz/deliver",
    "http://icici-bank-kyc-update.tk/verify",
    "http://sbi-netbanking-expire.ml/renew",
    "http://axis-bank-blocked.ga/unblock",
    "http://paytm-kyc-pending.cf/complete",
    "http://phonepe-verify-now.xyz/otp",
    "http://jio-recharge-free.tk/get",
    "http://airtel-prize-2024.ml/winner",
    "http://swiggy-free-order.ga/code",
    "http://zomato-cashback-offer.cf/redeem",
    "http://flipkart-lucky-draw.xyz/win",
    "http://amazon-gift-card.tk/free",
    "http://hdfc-credit-card-upgrade.ml/apply",
    "http://kotak-bank-login-expired.ga/reset",
    "http://yesbank-suspend-alert.cf/verify",
    "http://rbl-bank-kyc-urgent.xyz/update",
    "http://nsdl-pan-link-expire.tk/link",
    "http://epfo-pf-claim-pending.ml/claim",
    "http://uidai-aadhaar-update.ga/verify",
    "http://irctc-refund-pending.cf/collect",
    "http://makemytrip-cancel-refund.xyz/get",
    "http://indigo-boarding-pass.tk/download",
    "http://spicejet-prize-winner.ml/claim",
    "http://zepto-free-delivery.ga/code",
    "http://blinkit-cashback-2024.cf/earn",
    "http://bigbasket-reward-points.xyz/redeem",
    "http://dunzo-offer-today.tk/get",
    "http://ola-free-ride.ml/winner",
    "http://uber-prize-draw.ga/claim",
]

LEGIT_URLS_BUILTIN = [
    "https://www.hdfcbank.com/personal/",
    "https://www.icicibank.com/online-services/home.page",
    "https://www.onlinesbi.sbi/",
    "https://www.axisbank.com/",
    "https://www.kotak.com/en/home.html",
    "https://www.paytm.com/",
    "https://www.phonepe.com/",
    "https://pay.google.com/",
    "https://www.amazon.in/",
    "https://www.flipkart.com/",
    "https://www.swiggy.com/",
    "https://www.zomato.com/",
    "https://www.irctc.co.in/",
    "https://www.makemytrip.com/",
    "https://www.airtel.in/",
    "https://www.jio.com/",
    "https://www.bsnl.co.in/",
    "https://www.uidai.gov.in/",
    "https://incometaxindia.gov.in/",
    "https://www.epfindia.gov.in/",
    "https://www.india.gov.in/",
    "https://www.mca.gov.in/",
    "https://www.rbi.org.in/",
    "https://www.sebi.gov.in/",
    "https://www.npci.org.in/",
    "https://www.google.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.youtube.com/",
    "https://www.wikipedia.org/",
    "https://www.github.com/",
    "https://www.stackoverflow.com/",
    "https://www.linkedin.com/",
    "https://www.twitter.com/",
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://www.netflix.com/",
    "https://www.amazon.com/",
    "https://www.paypal.com/",
    "https://www.ebay.com/",
]


def build_url_dataset():
    print("\n[1/3] Building URL dataset...")
    out_path = PROC_DIR / "url_dataset.csv"

    rows = []
    for url in PHISHING_URLS_BUILTIN:
        rows.append({"url": url, "label": 1})
    for url in LEGIT_URLS_BUILTIN:
        rows.append({"url": url, "label": 0})

    # Try to pull from PhishTank (may require registration key)
    try:
        print("  Attempting PhishTank download...")
        r = requests.get(
            "http://data.phishtank.com/data/online-valid.csv",
            headers=HEADERS, timeout=15, stream=True
        )
        if r.status_code == 200:
            content = r.content.decode("utf-8", errors="ignore")
            reader = csv.DictReader(io.StringIO(content))
            count = 0
            for row in reader:
                url = row.get("url", "").strip()
                if url and row.get("verified") == "yes":
                    rows.append({"url": url, "label": 1})
                    count += 1
                    if count >= 5000:
                        break
            print(f"  PhishTank: added {count} verified phishing URLs")
        else:
            print(f"  PhishTank returned {r.status_code} — using built-in set")
    except Exception as e:
        print(f"  PhishTank unavailable ({e}) — using built-in set only")

    # Try Tranco top sites for legit URLs
    try:
        print("  Fetching Tranco top-1M legitimate domains...")
        r = requests.get(
            "https://tranco-list.eu/top-1m.csv.zip",
            headers=HEADERS, timeout=20, stream=True
        )
        if r.status_code == 200:
            z = zipfile.ZipFile(io.BytesIO(r.content))
            with z.open(z.namelist()[0]) as f:
                reader = csv.reader(io.TextIOWrapper(f))
                count = 0
                for row in reader:
                    if len(row) >= 2:
                        domain = row[1].strip()
                        rows.append({"url": f"https://www.{domain}/", "label": 0})
                        count += 1
                        if count >= 5000:
                            break
            print(f"  Tranco: added {count} legitimate domain URLs")
        else:
            print(f"  Tranco returned {r.status_code}")
    except Exception as e:
        print(f"  Tranco unavailable ({e})")

    random.shuffle(rows)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    phish = sum(1 for r in rows if r["label"] == 1)
    legit = sum(1 for r in rows if r["label"] == 0)
    print(f"  URL dataset: {len(rows)} total ({phish} phishing, {legit} legitimate)")
    print(f"  Saved: {out_path}")
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# 2. SMS DATASET
# Source: Mendeley Smishing Dataset + built-in samples
# ─────────────────────────────────────────────────────────────────────────────

SMISHING_SAMPLES = [
    "URGENT: Your SBI account has been suspended. Verify immediately at http://sbi-verify.tk or lose access",
    "Congratulations! You've won Rs.50,000 in HDFC Lucky Draw. Claim now: http://hdfc-prize.ga",
    "Dear Customer, your KYC is pending. Update now to avoid account block: http://icici-kyc.cf",
    "Your Jio SIM will be deactivated. Recharge free at http://jio-free.xyz to continue",
    "ALERT: Unauthorized login detected on your PayTM. Verify: http://paytm-secure.tk",
    "You have a pending PF claim of Rs.28,000. Apply now: http://epfo-claim.ml",
    "Income Tax Dept: Your refund of Rs.15,240 is ready. Claim: http://incometax-refund.ga",
    "Your Amazon order is held at customs. Pay Rs.199 duty at: http://amazon-customs.cf",
    "Flipkart: You won a Samsung TV! Confirm delivery address: http://flipkart-prize.xyz",
    "FREE Netflix 3 months! Activate: http://netflix-free-india.tk - Offer ends midnight",
    "IRCTC: Your train ticket refund of Rs.1,200 is pending. Collect: http://irctc-refund.ml",
    "Axis Bank: Your credit card limit has been upgraded. Verify: http://axisbank-upgrade.ga",
    "Dear User, your Aadhaar-PAN link will expire today. Link now: http://uidai-pan.cf",
    "Kotak 811: Suspicious transaction blocked. Confirm at http://kotak-verify.tk NOW",
    "Your DHL parcel is on hold. Pay Rs.99 customs: http://dhl-india-delivery.xyz",
    "BSNL: Win iPhone 15 in our anniversary lucky draw! Register: http://bsnl-prize.ml",
    "Zepto: Get Rs.500 cashback on your next order. Tap: http://zepto-cashback.ga/claim",
    "Ola: You've been selected for free rides! Claim: http://ola-free-rides.cf",
    "SBI Credit Card: Your reward points expire today. Redeem: http://sbi-rewards.tk",
    "Your UPI ID is blocked due to suspicious activity. Unblock: http://upi-verify.xyz",
]

HAM_SAMPLES = [
    "Your OTP for SBI Net Banking is 482910. Valid for 10 minutes. Do not share.",
    "HDFCBK: Rs.2,500 debited from your account on 15-Jan. Available balance: Rs.18,430",
    "Your Jio recharge of Rs.239 is successful. Pack active till 30-Jan-2025",
    "Swiggy: Your order from Domino's is out for delivery. Track: swiggy.com/track",
    "Amazon: Your order #402-8923 has shipped. Delivery by 18-Jan. amazon.in/orders",
    "Flipkart: Your item has been delivered. Rate your experience on flipkart.com",
    "IRCTC: PNR 4123456789 CONFIRM. Train 12345 on 20-Jan from NDLS to MMCT.",
    "ICICI Bank: Auto-pay of Rs.1,200 processed for your Airtel bill. ICICIBANK.COM",
    "Paytm: Rs.500 added to your Paytm wallet via UPI. Your balance: Rs.850",
    "PhonePe: Payment of Rs.350 to Zepto successful. Ref: PHONEPE20240115",
    "Your Aadhaar OTP is 738291. Enter it on the UIDAI portal. Do not share.",
    "EPFO: Your PF balance for account XX1234 is Rs.1,45,280 as on 31-Dec-2024",
    "Airtel: Bill of Rs.499 due on 25-Jan. Pay at airtel.in/payments or Airtel Thanks app",
    "Your OTP to login to IndiGo app is 921847. Valid for 5 mins. Do not share.",
    "MakeMyTrip: Your flight booking for 22-Jan is confirmed. Booking ID: NF234567890",
    "Zomato: Your order from Burger King is being prepared. Estimated delivery: 35 min",
    "Google Pay: Rs.1,000 received from Rahul Kumar. Check your bank account.",
    "Your Kotak 811 account statement for Dec 2024 is ready. Login to kotak.com",
    "BSNL: Your broadband usage for this month is 78 GB out of 200 GB. BSNL.CO.IN",
    "Income Tax Dept: Your ITR for AY 2024-25 has been processed. Refund initiated.",
]


def build_sms_dataset():
    print("\n[2/3] Building SMS dataset...")
    out_path = PROC_DIR / "sms_dataset.csv"

    rows = []
    for msg in SMISHING_SAMPLES:
        rows.append({"text": msg, "label": 1})
    for msg in HAM_SAMPLES:
        rows.append({"text": msg, "label": 0})

    # Try Mendeley dataset
    mendeley_url = "https://data.mendeley.com/public-files/datasets/f45bkkt8pr/files/c207a8ab-6a8e-4a37-aa57-2a6a9cde3543/file_downloaded"
    try:
        print("  Attempting Mendeley smishing dataset download...")
        r = requests.get(mendeley_url, headers=HEADERS, timeout=15)
        if r.status_code == 200:
            content = r.content.decode("utf-8", errors="ignore")
            reader = csv.DictReader(io.StringIO(content))
            count = 0
            for row in reader:
                label_raw = row.get("LABEL", row.get("label", "")).strip().lower()
                text = row.get("TEXT", row.get("text", "")).strip()
                if not text:
                    continue
                label = 1 if label_raw in ("smishing", "spam", "1") else 0
                rows.append({"text": text, "label": label})
                count += 1
            print(f"  Mendeley: added {count} messages")
        else:
            print(f"  Mendeley returned {r.status_code} — using built-in set")
    except Exception as e:
        print(f"  Mendeley unavailable ({e}) — using built-in set only")

    random.shuffle(rows)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)

    smish = sum(1 for r in rows if r["label"] == 1)
    ham   = sum(1 for r in rows if r["label"] == 0)
    print(f"  SMS dataset: {len(rows)} total ({smish} smishing, {ham} legitimate)")
    print(f"  Saved: {out_path}")
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# 3. PAGE CONTENT DATASET
# Synthetic page content samples for page-level classification
# ─────────────────────────────────────────────────────────────────────────────

PHISHING_PAGES = [
    "Dear valued customer your account has been suspended please verify your identity immediately enter your username password and otp to restore access your account will be permanently deleted if you do not act within 24 hours",
    "Congratulations you have been selected for a special reward enter your bank account number credit card cvv and pin to claim your prize of fifty thousand rupees this offer expires today",
    "Security alert we have detected unusual login activity on your account please confirm your identity by entering your full name date of birth mobile number and password",
    "Your netbanking access has been temporarily blocked for security reasons click here to verify your credentials and restore full access enter your user id and transaction password",
    "Free gift voucher claim your amazon flipkart gift card worth two thousand rupees just enter your registered mobile number otp and debit card details to receive your reward",
    "Your kyc verification is pending your account services will be restricted unless you update your kyc details enter your aadhaar number pan card and bank account information",
    "Income tax department notice your tax refund of fifteen thousand has been processed enter your bank ifsc code and account number to receive the refund directly",
    "Dear user your emi payment has failed update your payment details immediately to avoid late fees and account suspension enter card number expiry date and cvv",
    "Your jio sim will be deactivated within 24 hours complete the verification process by entering your mobile number aadhaar otp and full name to keep your number active",
    "Paytm wallet verification required enter your registered mobile number and four digit mpin to verify your wallet and receive your cashback reward of five hundred rupees",
]

LEGIT_PAGES = [
    "Welcome to HDFC Bank net banking please login with your customer id and password to access your accounts view transactions and transfer funds securely",
    "Your order has been shipped and will be delivered by tomorrow track your package using the tracking id provided in your email for real time updates",
    "Thank you for your payment of rupees two hundred thirty nine your jio plan is active you can check your usage and validity in the my jio app",
    "Your flight booking is confirmed please check in online 48 hours before departure and download your boarding pass from the makemytrip app",
    "Your pf balance as on december thirty one is one lakh forty five thousand you can check your passbook and withdraw online through the epfo member portal",
    "Welcome to swiggy your account is active browse restaurants near you and place your order we will deliver fresh food to your doorstep in thirty minutes",
    "Your income tax return has been processed and verified the refund will be credited to your registered bank account within five to seven working days",
    "SBI net banking is available 24 hours a day for fund transfers bill payments and account management please ensure you are on the official sbi website",
    "Your aadhaar card details have been updated successfully the changes will reflect across all linked services within 48 hours contact uidai for any queries",
    "Thank you for shopping with amazon your order is being prepared by the seller and will be shipped within two business days",
]


def build_page_dataset():
    print("\n[3/3] Building page content dataset...")
    out_path = PROC_DIR / "page_dataset.csv"

    rows = []
    for text in PHISHING_PAGES:
        rows.append({"text": text, "label": 1})
    for text in LEGIT_PAGES:
        rows.append({"text": text, "label": 0})

    random.shuffle(rows)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)

    phish = sum(1 for r in rows if r["label"] == 1)
    legit = sum(1 for r in rows if r["label"] == 0)
    print(f"  Page dataset: {len(rows)} total ({phish} phishing, {legit} legitimate)")
    print(f"  Saved: {out_path}")
    return out_path


if __name__ == "__main__":
    print("=" * 60)
    print("PhishGuard DL — Dataset Downloader")
    print("=" * 60)
    build_url_dataset()
    build_sms_dataset()
    build_page_dataset()
    print("\n✅ All datasets ready in datasets/processed/")
    print("   Next: Run training/train_all.py")
