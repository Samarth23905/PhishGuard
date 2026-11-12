"""
FCM Push Notification Sender — Firebase v1 API.
Sends analysis results back to the user's phone.
"""

import os, json, logging, requests
import google.auth, google.auth.transport.requests
from google.oauth2 import service_account

logger = logging.getLogger(__name__)

FCM_ENDPOINT = "https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
SERVICE_ACCOUNT_PATH = os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH", "./firebase-service-account.json")

CHANNEL = {"SAFE": "safe_channel", "SUSPICIOUS": "suspicious_channel", "DANGEROUS": "dangerous_channel"}
PRIORITY = {"SAFE": "normal", "SUSPICIOUS": "high", "DANGEROUS": "high"}
TITLE = {"SAFE": "✅ Safe", "SUSPICIOUS": "⚠️ Suspicious", "DANGEROUS": "🚨 DANGER"}


def _get_access_token():
    creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_PATH, scopes=SCOPES)
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


def _get_project_id():
    with open(SERVICE_ACCOUNT_PATH) as f:
        return json.load(f)["project_id"]


def send_fcm_notification(fcm_token: str, app_name: str, sender: str, result: dict):
    verdict = result.get("verdict", "SAFE")
    summary = result.get("summary", "Notification analyzed.")
    title   = f"{TITLE.get(verdict, 'ℹ️')} — {app_name}"

    try:
        token      = _get_access_token()
        project_id = _get_project_id()
        payload = {
            "message": {
                "token": fcm_token,
                "notification": {"title": title, "body": summary},
                "android": {
                    "priority": PRIORITY.get(verdict, "normal"),
                    "notification": {
                        "channel_id": CHANNEL.get(verdict, "safe_channel"),
                        "default_sound": True,
                        "notification_priority": "PRIORITY_MAX" if verdict == "DANGEROUS" else "PRIORITY_DEFAULT",
                    }
                },
                "apns": {"payload": {"aps": {"alert": {"title": title, "body": summary}, "sound": "default", "badge": 1}}},
                "data": {
                    "verdict": verdict, "summary": summary,
                    "sender": sender, "app_name": app_name,
                    "n_links": str(len(result.get("links_checked", []))),
                }
            }
        }
        resp = requests.post(
            FCM_ENDPOINT.format(project_id=project_id), json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=10
        )
        if resp.status_code == 200:
            logger.info(f"FCM sent | verdict={verdict}")
        else:
            logger.error(f"FCM failed: {resp.status_code} {resp.text}")
    except FileNotFoundError:
        logger.error("Firebase service account file not found. See README.md.")
    except Exception as e:
        logger.error(f"FCM error: {e}")
