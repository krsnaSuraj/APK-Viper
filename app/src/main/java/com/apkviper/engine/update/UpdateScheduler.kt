package com.apkviper.engine.update

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import com.apkviper.data.SettingsDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first

class UpdateSchedulerReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val store = SettingsDataStore(context)
                val autoUpdate = store.autoUpdate.first()
                if (!autoUpdate) {
                    pendingResult.finish()
                    return@launch
                }
                val engine = AutoUpdateEngine(context)
                val result = engine.checkAndUpdate()
                if (result.yaraRulesUpdated || result.hashesUpdated || result.intelUpdated) {
                    store.updateSignatureStatus(
                        result.yaraRuleCount.toLong(),
                        result.hashCount.toLong(),
                        com.apkviper.engine.advanced.ThreatIntelDB.getIpCount().toLong(),
                        com.apkviper.engine.advanced.ThreatIntelDB.getDomainCount().toLong()
                    )
                    android.util.Log.i("UpdateScheduler", "Scheduled update complete: ${result.yaraRuleCount} YARA, ${result.hashCount} hashes, ${result.intelCount} intel")
                }
            } catch (e: Exception) {
                android.util.Log.w("UpdateScheduler", "Scheduled update failed: ${e.message}")
            } finally {
                pendingResult.finish()
            }
        }
    }
}

object UpdateScheduler {
    private const val REQUEST_CODE = 9072
    private const val INTERVAL_MS = 6 * 60 * 60 * 1000L  // Every 6 hours
    private const val ACTION_UPDATE = "com.apkviper.action.SCHEDULED_UPDATE"

    fun schedule(context: Context) {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(context, UpdateSchedulerReceiver::class.java).setAction(ACTION_UPDATE)
        val pendingIntent = PendingIntent.getBroadcast(
            context, REQUEST_CODE, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        alarmManager.setInexactRepeating(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + INTERVAL_MS,
            INTERVAL_MS,
            pendingIntent
        )
    }

    fun cancel(context: Context) {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(context, UpdateSchedulerReceiver::class.java).setAction(ACTION_UPDATE)
        val pendingIntent = PendingIntent.getBroadcast(
            context, REQUEST_CODE, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        alarmManager.cancel(pendingIntent)
    }
}
