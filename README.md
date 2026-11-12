# PhishGuard DL — 4-Layer Deep Learning Phishing Detector

A complete mobile phishing detection system. **Zero AI API keys needed.**
All detection runs on your own trained DL models.

---

## Architecture

```
📱 Notification arrives on phone
        ↓
[Android App — NotificationScannerService]
  Extracts: sender, text, URLs
        ↓  POST /analyze  (session token)
[Flask Server — 4-Layer DL Pipeline]
        │
        ├─ LAYER 1: Trusted sender whitelist
        │   Known banks/telecoms → instant SAFE, no DL needed
        │
        ├─ LAYER 1B: SMS BiLSTM model
        │   Analyzes message text for smishing patterns
        │
        ├─ LAYER 2: URL CNN model
        │   Character-level CNN reads URL structure
        │   Catches fake domains even never seen before
        │
        ├─ LAYER 3: Page content LSTM model
        │   Server visits link (phone never does)
        │   LSTM reads page text → phishing or legit?
        │
        └─ LAYER 4: Rule-based summarizer (Path A)
            Plain-English verdict — zero API cost
        ↓  Firebase FCM push
📲 Result notification on phone
   "🚨 DANGER — SMS. Link redirects to fake domain,
    SSL invalid. Do NOT click."
```

---

## Project Structure

```
phishguard-dl/
├── README.md
├── datasets/
│   ├── download_datasets.py      ← Step 1: download & build datasets
│   └── processed/                ← auto-created by script
│       ├── url_dataset.csv
│       ├── sms_dataset.csv
│       └── page_dataset.csv
├── training/
│   ├── train_all.py              ← Step 2: train all 3 DL models
│   └── requirements_train.txt
└── flask-server/
    ├── app.py                    ← Step 3: run the server
    ├── requirements.txt
    ├── render.yaml               ← Step 4 (optional): deploy to Render
    ├── run_local.sh
    ├── test_pipeline.py          ← Step 5: verify everything works
    ├── .env.example
    ├── firebase-service-account.json.placeholder
    ├── models/                   ← filled by train_all.py
    └── utils/
        ├── dl_engine.py          ← loads & runs all DL models
        ├── link_checker.py       ← URL + page analysis pipeline
        ├── trusted_senders.py    ← Layer 1 whitelist
        ├── summarizer.py         ← Layer 4 rule-based summary
        └── fcm_sender.py         ← Firebase push notifications
android-app/                      ← Open in Android Studio
    └── app/src/main/
        ├── AndroidManifest.xml
        ├── java/com/phishguard/
        │   ├── MainActivity.kt
        │   ├── NotificationScannerService.kt
        │   ├── PhishGuardApi.kt
        │   └── PhishGuardMessagingService.kt
        └── res/...
```

---

## Step-by-Step Setup

### Prerequisites
- Python 3.10+
- Android Studio (Hedgehog or newer)
- A Firebase account (free)

---

### STEP 1 — Firebase Setup

1. Go to https://console.firebase.google.com → New Project
2. Add Android App → package name: `com.phishguard`
3. Download `google-services.json` → place in `android-app/app/`
4. Project Settings → Service Accounts → Generate new private key
5. Save as `flask-server/firebase-service-account.json`

---

### STEP 2 — Download Datasets

```bash
cd phishguard-dl
python -m pip install requests pandas numpy
python datasets/download_datasets.py
```

This creates:
- `datasets/processed/url_dataset.csv`   — phishing + legit URLs
- `datasets/processed/sms_dataset.csv`   — smishing + ham messages
- `datasets/processed/page_dataset.csv`  — phishing + legit page content

The script tries to pull live data from PhishTank and Tranco.
If those are unavailable, it uses the built-in curated dataset (still works).

---

### STEP 3 — Train DL Models

```bash
pip install -r training/requirements_train.txt
python training/train_all.py
```

Training takes ~3-10 minutes on CPU. After completion you'll see in `flask-server/models/`:
```
url_model.keras           ← CNN URL classifier
url_model_config.json
sms_model.keras           ← BiLSTM SMS classifier
sms_tokenizer.pkl
sms_model_config.json
page_model.keras          ← LSTM page content classifier
page_tokenizer.pkl
page_model_config.json
```

---

### STEP 4 — Run the Flask Server (locally)

```bash
cd flask-server
cp .env.example .env
# Edit .env — set SESSION_TOKEN to any strong random string
chmod +x run_local.sh
./run_local.sh
```

Server starts at: http://0.0.0.0:5000
Android emulator connects via: http://10.0.2.2:5000
Real device on same WiFi: http://192.168.x.x:5000 (your machine IP)

---

### STEP 5 — Test the Pipeline

```bash
# In a second terminal, with server running:
cd flask-server
python test_pipeline.py
```

You should see:
- Trusted bank OTP → SAFE
- Phishing SMS with fake bank link → SUSPICIOUS or DANGEROUS
- Prize scam → SUSPICIOUS
- Swiggy notification → SAFE
- Bad token → HTTP 401

---

### STEP 6 — Build the Android App

1. Open `android-app/` in Android Studio
2. Place `google-services.json` in `app/`
3. In `app/build.gradle` → set `SERVER_URL` to your server IP
4. Build & run on device/emulator
5. Grant permission: Settings → Apps → Special App Access → Notification Access → PhishGuard DL → Enable

---

### STEP 7 — Deploy to Render (production)

1. Push `flask-server/` to GitHub
2. Connect repo at render.com → New Web Service
3. Set environment variable `SESSION_TOKEN` in dashboard
4. Upload `firebase-service-account.json` as a Secret File (path: `./firebase-service-account.json`)
5. Upload your trained model files from `flask-server/models/` to the server
   (Use Render's persistent disk or train directly on the VPS)
6. Update `SERVER_URL` in Android `build.gradle` release config → rebuild

---

## Datasets Used

| Dataset | Source | Used for |
|---------|--------|----------|
| PhishTank verified URLs | phishtank.org (free) | URL model phishing class |
| Tranco top-1M domains | tranco-list.eu (free) | URL model legit class |
| Mendeley Smishing Dataset | data.mendeley.com (free) | SMS model |
| Curated built-in samples | Researched & included | Fallback for all models |

---

## API Keys Required

| Key | Required? | Purpose |
|-----|-----------|---------|
| Firebase service account | ✅ Yes | Push results to phone |
| SESSION_TOKEN | ✅ Yes | Secure your server |
| Google Safe Browsing | ❌ No | Replaced by DL URL model |
| Anthropic (Claude) | ❌ No | Replaced by rule-based summarizer |
| Any other AI API | ❌ No | All detection is local DL |

---

## DL Model Details

### Model 1 — URL Classifier (CNN)
- Input: URL string as ASCII character sequence
- Architecture: Embedding → Conv1D (128) → Conv1D (64) → GlobalMaxPool → Dense
- Why CNN: Character n-grams capture patterns like "verify-", "-secure", ".xyz", "bank-login"

### Model 2 — SMS Classifier (BiLSTM)
- Input: SMS/notification text tokenized words
- Architecture: Embedding → BiLSTM (64) → BiLSTM (32) → Dense
- Why BiLSTM: Reads message in both directions to understand context and urgency patterns

### Model 3 — Page Content Classifier (LSTM)
- Input: Extracted page text (server visits link, phone never does)
- Architecture: Embedding → LSTM (128) → LSTM (64) → Dense
- Why LSTM: Sequential reading of page content catches phishing intent even in AI-generated text

### Layer 4 — Summarizer (Rule-based, Path A)
- No model, no API
- Template-based verdict generation from model scores + reasons
- Example output: "⚠️ Suspicious message from AD-PROMO99. 1 link flagged: Domain contains brand 'hdfc' but is not the official site. Verify through official website or app before clicking."

---

## Security and reliability update (2.1)

This revision hardens the existing implementation without changing the overall
Android + Flask + three-model design.

### Backend protections

- `/analyze` now fails closed when `SESSION_TOKEN` is missing and compares tokens
  with constant-time comparison.
- Request JSON type, shape, body size, field lengths and URL count are validated.
- A basic per-process IP rate limit is applied. For multi-instance production
  deployments, replace this with a shared Redis-backed limiter or gateway limit.
- Logs no longer include message bodies, sender identifiers, URLs or FCM tokens.
- Security response headers and generic error responses are enabled.
- A SAFE verdict is explicitly not a guarantee of legitimacy.

### URL-fetch safety

- Remote page fetching is **disabled by default** (`PHISHGUARD_ENABLE_PAGE_FETCH=false`).
- URL validation rejects non-HTTP(S), credentials, localhost, private, loopback,
  link-local and reserved IP destinations.
- When enabled, page fetching uses bounded timeouts, response size limits,
  content-type checks and manually inspected redirects.
- Do not enable live fetching on a public deployment until you have reviewed
  DNS-rebinding risk and enforced outbound network restrictions at the hosting
  layer. URL-only model analysis remains available without page fetching.
- Trusted sender/domain entries are hints only; they no longer bypass message
  and link analysis. A domain suffix must match on a label boundary.

### Android privacy and build configuration

- Notification text is length-limited and common OTP / long-number patterns are
  redacted before transmission. This is best-effort redaction, not a guarantee
  that every sensitive value is removed.
- Notification contents and URLs are not written to Android logs.
- Android backup is disabled for the app.
- Configure builds with Gradle properties rather than editing source:

```bash
./gradlew assembleDebug -PphishguardServerUrl=http://10.0.2.2:5000 -PphishguardSessionToken=YOUR_LOCAL_TOKEN
./gradlew assembleRelease -PphishguardServerUrl=https://YOUR_HOST -PphishguardSessionToken=YOUR_TOKEN
```

A token embedded in an APK can be extracted. The current shared-token scheme is
suitable only as a basic project/demo gate, not strong per-user authentication.
For production, use per-device credentials, short-lived access tokens, device
revocation and an abuse-control layer. Never commit production secrets.

### Training-data improvements

- Empty rows, invalid labels and exact normalized duplicates are removed.
- Conflicting labels for identical normalized text are excluded.
- SMS/page tokenizers are fitted on training data only, reducing vocabulary
  leakage into the held-out test set.
- A random row split can still overestimate generalization when samples from
  the same campaign/domain appear in both partitions. For a research-grade
  evaluation, add campaign/domain/time-based holdouts and report precision,
  recall, F1, ROC-AUC and false-positive rate.

### Setup

1. Install backend dependencies: `pip install -r flask-server/requirements.txt`.
2. Copy `flask-server/.env.example` to `flask-server/.env` and generate a strong
   `SESSION_TOKEN` (see the example comment in that file).
3. Start locally from `flask-server`: `python app.py`.
4. Train models from the project root after preparing datasets:
   `pip install -r training/requirements_train.txt` then `python training/train_all.py`.
5. The trained model artifacts are intentionally not bundled in this source ZIP.
   `/health` reports which model files are present. Missing models are not a
   substitute for trained, validated models; do not interpret fallback outputs
   as a validated detection result.
6. For Firebase alerts, provide a real service-account JSON through a secure
   deployment secret and set `FIREBASE_SERVICE_ACCOUNT_PATH`. Do not commit it.

### Validation performed on this source revision

Run backend syntax checks from the project root:

```bash
python -m compileall -q flask-server training
cd flask-server && python -m unittest test_security.py
```

Android Gradle compilation and full model training require the Android SDK,
Firebase configuration, prepared datasets and trained model artifacts; these
were not available as part of the uploaded ZIP and therefore are not claimed as
verified here.
