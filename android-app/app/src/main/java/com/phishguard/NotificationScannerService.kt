package com.phishguard

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class NotificationScannerService : NotificationListenerService() {

    private val TAG = "PhishGuard"
    private val scope = CoroutineScope(Dispatchers.IO)

    private val IGNORED_PACKAGES = setOf(
        "com.phishguard", "com.android.systemui",
        "com.google.android.gms", "android",
        "com.android.providers.downloads"
    )

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        Log.i(TAG, "Scanner service started")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val pkg = sbn.packageName
        if (pkg in IGNORED_PACKAGES || sbn.isOngoing) return

        val extras  = sbn.notification?.extras ?: return
        val title   = extras.getString("android.title") ?: ""
        val text    = extras.getCharSequence("android.bigText")?.toString()
                   ?: extras.getCharSequence("android.text")?.toString() ?: ""
        val fullText = "$title $text".trim().take(5000)
        // Minimize exposure: redact OTPs and long payment/account-like digit strings
        // before transmitting notification content to the analysis server.
        val privacySafeText = redactSensitiveValues(fullText)
        val links = extractUrls(privacySafeText).take(5)

        // Only process if there's a URL or the text looks suspicious
        if (links.isEmpty() && !looksLikePhishing(privacySafeText)) return

        // Do not log notification text, sender names, URLs, or OTPs.
        Log.i(TAG, "Scanning notification | links=${links.size}")

        scope.launch {
            PhishGuardApi.analyze(
                context  = applicationContext,
                appName  = pkg,
                sender   = title,
                text     = privacySafeText,
                links    = links
            )
        }
    }

    private fun extractUrls(text: String): List<String> =
        Regex("""https?://[^\s<>"{}|\\^`\[\]]+""")
            .findAll(text).map { it.value }.distinct().toList()

    private fun redactSensitiveValues(input: String): String {
        var value = input
        value = value.replace(Regex("""(?i)\b(otp|one[- ]time password|verification code|security code)\s*[: is-]*\d{4,8}\b"""), "\$1 [REDACTED]")
        value = value.replace(Regex("""\b\d{10,19}\b"""), "[REDACTED_NUMBER]")
        return value
    }

    private fun looksLikePhishing(text: String): Boolean {
        val lower = text.lowercase()
        return listOf(
            "click here", "verify your", "account suspended",
            "claim your", "you have won", "free gift",
            "urgent", "congratulations", "your kyc",
            "update your details", "otp expire", "account block"
        ).any { it in lower }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            listOf(
                Triple("safe_channel",       "Safe Alerts",       NotificationManager.IMPORTANCE_LOW),
                Triple("suspicious_channel", "Suspicious Alerts", NotificationManager.IMPORTANCE_HIGH),
                Triple("dangerous_channel",  "Danger Alerts",     NotificationManager.IMPORTANCE_MAX),
            ).forEach { (id, name, importance) ->
                nm.createNotificationChannel(NotificationChannel(id, name, importance))
            }
        }
    }
}
