package com.phishguard

import android.content.Context
import android.util.Log
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

object PhishGuardApi {

    private const val TAG = "PhishGuardApi"

    // ── Change to your server URL ──────────────────────────────────────────
    // Emulator → local:  "http://10.0.2.2:5000"
    // Real device (WiFi): "http://192.168.x.x:5000"
    // Production:         "https://your-app.onrender.com"
    private const val SERVER_URL    = BuildConfig.SERVER_URL
    private const val SESSION_TOKEN = BuildConfig.SESSION_TOKEN

    suspend fun analyze(
        context: Context,
        appName: String,
        sender: String,
        text: String,
        links: List<String>
    ) {
        try {
            val fcmToken = getFcmToken()
            val body = JSONObject().apply {
                put("fcm_token", fcmToken)
                put("app_name",  appName)
                put("sender",    sender)
                put("text",      text)
                put("links",     JSONArray(links))
            }

            require(SERVER_URL.startsWith("https://") || BuildConfig.DEBUG) { "HTTPS is required outside debug builds" }
            val conn = (URL("$SERVER_URL/analyze").openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput      = true
                connectTimeout = 10_000
                readTimeout    = 30_000
                setRequestProperty("Content-Type",    "application/json")
                setRequestProperty("X-Session-Token", SESSION_TOKEN)
            }

            try {
                OutputStreamWriter(conn.outputStream, "UTF-8").use { it.write(body.toString()) }
                val status = conn.responseCode
                if (status !in 200..299) Log.w(TAG, "Analysis request failed: HTTP $status")
            } finally {
                conn.disconnect()
            }

        } catch (e: Exception) {
            Log.e(TAG, "API call failed: ${e.message}")
        }
    }

    private suspend fun getFcmToken(): String =
        suspendCancellableCoroutine { cont ->
            FirebaseMessaging.getInstance().token
                .addOnSuccessListener { cont.resume(it) }
                .addOnFailureListener { cont.resumeWithException(it) }
        }
}
