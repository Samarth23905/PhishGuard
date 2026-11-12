package com.phishguard

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Color
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import android.util.Log

class PhishGuardMessagingService : FirebaseMessagingService() {

    override fun onMessageReceived(message: RemoteMessage) {
        val data    = message.data
        val verdict = data["verdict"] ?: "SAFE"
        val summary = data["summary"] ?: "Notification analyzed."
        val sender  = data["sender"]  ?: "Unknown"
        val appName = data["app_name"] ?: "App"

        Log.i("PhishGuardFCM", "Result received | verdict=$verdict")
        showNotification(verdict, summary, sender, appName)
    }

    override fun onNewToken(token: String) {
        Log.i("PhishGuardFCM", "FCM token refreshed")
        getSharedPreferences("phishguard", Context.MODE_PRIVATE)
            .edit().putString("fcm_token", token).apply()
    }

    private fun showNotification(verdict: String, summary: String, sender: String, appName: String) {
        val (channel, color, priority) = when (verdict) {
            "DANGEROUS"  -> Triple("dangerous_channel",  Color.RED,                          NotificationCompat.PRIORITY_MAX)
            "SUSPICIOUS" -> Triple("suspicious_channel", Color.parseColor("#FF9800"),         NotificationCompat.PRIORITY_HIGH)
            else         -> Triple("safe_channel",       Color.parseColor("#34A853"),         NotificationCompat.PRIORITY_DEFAULT)
        }

        val title = when (verdict) {
            "DANGEROUS"  -> "🚨 DANGER — $appName"
            "SUSPICIOUS" -> "⚠️ Suspicious — $appName"
            else         -> "✅ Safe — $appName"
        }

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("verdict", verdict)
            putExtra("summary", summary)
            putExtra("sender",  sender)
        }
        val pi = PendingIntent.getActivity(
            this, System.currentTimeMillis().toInt(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notif = NotificationCompat.Builder(this, channel)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(summary)
            .setStyle(NotificationCompat.BigTextStyle().bigText(summary))
            .setColor(color)
            .setPriority(priority)
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()

        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(System.currentTimeMillis().toInt(), notif)
    }
}
