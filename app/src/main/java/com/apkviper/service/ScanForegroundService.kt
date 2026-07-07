package com.apkviper.service

import android.app.*
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.apkviper.MainActivity
import kotlinx.coroutines.*
import com.apkviper.R

class ScanForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "scan_progress"
        const val CHANNEL_ID_RESULTS = "scan_results"
        const val NOTIFICATION_ID = 1001
        const val RESULT_NOTIFICATION_ID = 1002
        const val EXTRA_PROGRESS = "progress_pct"
        const val EXTRA_PHASE = "phase_name"
        const val ACTION_STOP = "com.apkviper.STOP_SCAN"
        const val ACTION_SHOW_RESULT = "com.apkviper.SHOW_SCAN_RESULT"
        const val EXTRA_NAVIGATE_TAB = "navigate_tab"
        const val EXTRA_SCAN_PATH = "scan_path"
        const val EXTRA_SCAN_NAME = "scan_name"

        @Volatile
        var cancelRequested = false
            private set

        fun resetCancelFlag() { cancelRequested = false }

        /** Render the main launcher icon (foreground on background) as a Bitmap for notification large icons. */
        fun renderLauncherIcon(context: android.content.Context, sizePx: Int = 128): Bitmap? {
            try {
                val bg = androidx.appcompat.content.res.AppCompatResources.getDrawable(context, R.drawable.ic_launcher_background)
                val fg = androidx.appcompat.content.res.AppCompatResources.getDrawable(context, R.drawable.ic_launcher_foreground)
                if (bg == null || fg == null) return null
                val bmp = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
                val c = Canvas(bmp)
                bg.setBounds(0, 0, sizePx, sizePx)
                bg.draw(c)
                fg.setBounds(0, 0, sizePx, sizePx)
                fg.draw(c)
                return bmp
            } catch (_: Exception) { return null }
        }

        fun createChannels(context: android.content.Context) {
            val scanChannel = NotificationChannel(
                CHANNEL_ID, "Scan Progress",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows APK scanning progress"
                setShowBadge(false)
            }
            context.getSystemService(NotificationManager::class.java).createNotificationChannel(scanChannel)

            val resultChannel = NotificationChannel(
                CHANNEL_ID_RESULTS, "Scan Results",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Scan completion notifications"
            }
            context.getSystemService(NotificationManager::class.java).createNotificationChannel(resultChannel)
        }

        fun showScanComplete(context: android.content.Context, apkName: String, threatLevel: String, threatScore: Int, scanPath: String? = null) {
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                putExtra(EXTRA_NAVIGATE_TAB, 0)
                putExtra(EXTRA_SCAN_NAME, apkName)
                putExtra(EXTRA_SCAN_PATH, scanPath ?: "")
            }
            val pendingIntent = PendingIntent.getActivity(
                context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val resultIcon = renderLauncherIcon(context, 128)
            val notification = NotificationCompat.Builder(context, CHANNEL_ID_RESULTS)
                .setSmallIcon(R.drawable.ic_notification)
                .setLargeIcon(resultIcon)
                .setContentTitle("Scan Complete: $apkName")
                .setContentText("$threatLevel ($threatScore/100)")
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()

            context.getSystemService(NotificationManager::class.java).notify(RESULT_NOTIFICATION_ID, notification)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createChannels(this)
        startHeartbeat()
    }

    override fun onDestroy() {
        heartbeatJob?.cancel()
        clearCheckpoint()
        super.onDestroy()
    }

    private var heartbeatJob: Job? = null

    private fun startHeartbeat() {
        heartbeatJob?.cancel()
        heartbeatJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                delay(30_000)
                try {
                    getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID,
                        buildNotification(currentProgress, currentPhase))
                } catch (_: Exception) { }
            }
        }
    }

    @Volatile private var currentProgress: Int = 0
    @Volatile private var currentPhase: String = "Scanning..."

    fun updateNotification(progress: Int, phase: String) {
        currentProgress = progress
        currentPhase = phase
        savePhaseCheckpoint(progress, phase)
        val notification = buildNotification(progress, phase)
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification)
    }

    private fun savePhaseCheckpoint(progress: Int, phase: String) {
        val prefs = getSharedPreferences("scan_checkpoint", MODE_PRIVATE)
        prefs.edit()
            .putBoolean("scan_active", true)
            .putString("apk_path", scanPath)
            .putString("apk_name", scanName)
            .putInt("progress", progress)
            .putString("phase", phase)
            .apply()
    }

    private fun clearCheckpoint() {
        getSharedPreferences("scan_checkpoint", MODE_PRIVATE).edit().clear().apply()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            cancelRequested = true
            clearCheckpoint()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val progress = intent?.getIntExtra(EXTRA_PROGRESS, 0) ?: 0
        val phase = intent?.getStringExtra(EXTRA_PHASE) ?: "Scanning..."
        currentProgress = progress
        currentPhase = phase
        val incomingPath = intent?.getStringExtra(EXTRA_SCAN_PATH)
        val incomingName = intent?.getStringExtra(EXTRA_SCAN_NAME)
        if (incomingPath != null) scanPath = incomingPath
        if (incomingName != null) scanName = incomingName

        // Check for saved checkpoint from a previous life (service restarted by system)
        if (flags and START_FLAG_REDELIVERY != 0) {
            val prefs = getSharedPreferences("scan_checkpoint", MODE_PRIVATE)
            val savedPhase = prefs.getString("phase", null)
            if (savedPhase != null) {
                android.util.Log.i("ScanFgService", "Service restarted, last known phase: $savedPhase")
            }
        }

        savePhaseCheckpoint(progress, phase)
        if (flags and START_FLAG_REDELIVERY == 0) {
            try { startForeground(NOTIFICATION_ID, buildNotification(progress, phase)) } catch (_: SecurityException) {}
        } else {
            updateNotification(progress, phase)
        }
        return START_REDELIVER_INTENT
    }

    @Volatile private var scanPath: String? = null
    @Volatile private var scanName: String? = null

    private var largeIcon: android.graphics.Bitmap? = null
    internal fun loadLargeIcon(): android.graphics.Bitmap? {
        if (largeIcon == null) {
            largeIcon = renderLauncherIcon(this, 128)
            if (largeIcon == null) {
                try {
                    largeIcon = android.graphics.BitmapFactory.decodeResource(resources, R.drawable.ic_notification)
                } catch (_: Exception) {}
            }
        }
        return largeIcon
    }

    private fun buildNotification(progress: Int, phase: String): Notification {
        val stopIntent = Intent(this, ScanForegroundService::class.java).apply { action = ACTION_STOP }
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val stopPending = PendingIntent.getService(this, 0, stopIntent, flags)

        val openIntent = Intent(this, MainActivity::class.java).apply {
            this.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(EXTRA_NAVIGATE_TAB, 0)
            putExtra(EXTRA_SCAN_PATH, scanPath ?: "")
            putExtra(EXTRA_SCAN_NAME, scanName ?: "")
        }
        val openPending = PendingIntent.getActivity(
            this, 1, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("APK Viper Scanning")
            .setContentText(phase)
            .setSmallIcon(R.drawable.ic_notification)
            .setLargeIcon(loadLargeIcon())
            .setProgress(100, progress, false)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openPending)
            .addAction(0, "Cancel", stopPending)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
