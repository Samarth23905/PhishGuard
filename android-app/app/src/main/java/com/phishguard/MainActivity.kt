package com.phishguard

import android.app.AlertDialog
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.phishguard.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Show result if opened from a notification tap
        intent.getStringExtra("verdict")?.let { verdict ->
            val summary = intent.getStringExtra("summary") ?: ""
            val sender  = intent.getStringExtra("sender")  ?: ""
            showResult(verdict, summary, sender)
        }

        binding.btnGrant.setOnClickListener {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        }
    }

    override fun onResume() {
        super.onResume()
        updateStatus()
    }

    private fun isListenerEnabled(): Boolean {
        val flat = Settings.Secure.getString(contentResolver, "enabled_notification_listeners") ?: return false
        return flat.contains(ComponentName(this, NotificationScannerService::class.java).flattenToString())
    }

    private fun updateStatus() {
        if (isListenerEnabled()) {
            binding.tvStatus.text = "✅ Active — scanning all notifications"
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_green_dark))
            binding.btnGrant.isEnabled = false
            binding.btnGrant.text = "Permission Granted ✓"
        } else {
            binding.tvStatus.text = "⚠️ Permission needed — tap below"
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_orange_dark))
            binding.btnGrant.isEnabled = true
            binding.btnGrant.text = "Grant Notification Access"
        }
    }

    private fun showResult(verdict: String, summary: String, sender: String) {
        val icon = when (verdict) { "DANGEROUS" -> "🚨" "SUSPICIOUS" -> "⚠️" else -> "✅" }
        AlertDialog.Builder(this)
            .setTitle("$icon $verdict — $sender")
            .setMessage(summary)
            .setPositiveButton("OK", null)
            .show()
    }
}
