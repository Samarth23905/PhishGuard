#!/bin/bash
set -e

echo "🛡️ PhishGuard DL — Flask Server"
echo "────────────────────────────────────"

if [ ! -f .env ]; then
    echo "❌ .env not found. Copy .env.example → .env and fill in values."
    exit 1
fi
export $(grep -v '^#' .env | xargs)

if [ ! -f "$FIREBASE_SERVICE_ACCOUNT_PATH" ]; then
    echo "❌ Firebase service account not found at: $FIREBASE_SERVICE_ACCOUNT_PATH"
    echo "   Download from Firebase Console → Project Settings → Service Accounts"
    exit 1
fi

if [ ! -f "models/url_model.keras" ]; then
    echo "❌ DL models not found. Train them first:"
    echo "   cd .. && python training/train_all.py"
    exit 1
fi

pip install -r requirements.txt -q
echo "✅ Dependencies ready"
echo "🚀 Starting on http://0.0.0.0:${PORT:-5000}"
echo "   (Android emulator → http://10.0.2.2:${PORT:-5000})"
echo "────────────────────────────────────"
python app.py
