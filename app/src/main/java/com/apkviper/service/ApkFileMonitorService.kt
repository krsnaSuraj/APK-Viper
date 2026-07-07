package com.apkviper.service

import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.apkviper.MainActivity
import com.apkviper.R
import java.io.File

class ApkFileMonitorService : Service() {

    companion object {
        const val CHANNEL_ID = "apk_monitor"
        const val NOTIFICATION_ID = 2001

        fun start(context: Context) {
            val intent = Intent(context, ApkFileMonitorService::class.java)
            context.startService(intent)
        }

        fun createChannels(context: Context) {
            val channel = android.app.NotificationChannel(
                CHANNEL_ID, "APK Monitor",
                android.app.NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Alerts when new APK files are detected"
            }
            context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private var observer: FileObserver? = null

    override fun onCreate() {
        super.onCreate()
        createChannels(this)
        startObserving()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("APK Monitor Active")
            .setContentText("Watching Downloads for new APK files")
            .setSmallIcon(R.drawable.ic_notification)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
        try { startForeground(NOTIFICATION_ID, notification) } catch (e: SecurityException) {
            android.util.Log.w("ApkMonitor", "startForeground failed: ${e.message}")
        }
        return START_STICKY
    }

    private fun startObserving() {
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!dir.exists()) return

        observer = object : FileObserver(dir.absolutePath, CREATE or MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                if (path == null) return
                if (!path.endsWith(".apk", ignoreCase = true) && !path.endsWith(".xapk", ignoreCase = true)) return
                val file = File(dir, path)
                if (!file.exists()) return

                val scanIntent = Intent(this@ApkFileMonitorService, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                    putExtra("navigate_tab", 0)
                    putExtra("scan_path", file.absolutePath)
                    putExtra("scan_name", file.name)
                }
                val pendingIntent = PendingIntent.getActivity(
                    this@ApkFileMonitorService, file.absolutePath.hashCode(), scanIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )

                try { startActivity(scanIntent) } catch (_: Exception) {}

                val notification = NotificationCompat.Builder(this@ApkFileMonitorService, CHANNEL_ID)
                    .setSmallIcon(R.drawable.ic_notification)
                    .setContentTitle("Scanning $path")
                    .setContentText("APK scan started automatically")
                    .setPriority(NotificationCompat.PRIORITY_LOW)
                    .setAutoCancel(true)
                    .setContentIntent(pendingIntent)
                    .setOngoing(false)
                    .build()

                getSystemService(NotificationManager::class.java).notify(
                    (NOTIFICATION_ID + file.name.hashCode()).coerceAtMost(Int.MAX_VALUE),
                    notification
                )
            }
        }
        observer?.startWatching()
    }

    override fun onDestroy() {
        observer?.stopWatching()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
