package com.apkviper.ui.scan

import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.PowerManager
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.apkviper.data.AppDatabase
import com.apkviper.engine.ScanPipeline
import com.apkviper.model.ScanResult
import com.apkviper.service.ScanForegroundService
import com.apkviper.ui.terminal.LineType
import com.apkviper.ui.terminal.LogEntry
import com.apkviper.ui.terminal.TerminalTemplates
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object ScanEventBus {
    private val _scanCompleted = MutableSharedFlow<Unit>(replay = 0, extraBufferCapacity = 4)
    val scanCompleted: SharedFlow<Unit> = _scanCompleted
    fun emitCompleted() { _scanCompleted.tryEmit(Unit) }
}

data class ScanUiState(
    val lines: List<LogEntry> = emptyList(),
    val isScanning: Boolean = false,
    val isPreparing: Boolean = false,
    val scanComplete: Boolean = false,
    val     currentPhase: Int = 0,
    val totalPhases: Int = ScanPipeline.TOTAL_PHASE_COUNT,
    val progress: Float = 0f,
    val currentActivity: String = "Preparing...",
    val etaSeconds: Int = 0,
    val result: ScanResult? = null,
    val errorMessage: String? = null,
    val apkPath: String = "",
    val apkName: String = ""
)

class ScanViewModel(private val application: Application) : ViewModel() {

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    private var _lastCompletedResult: ScanResult? = null
    val lastCompletedResult: ScanResult? get() = _lastCompletedResult

    private var scanJob: Job? = null
    private var startTimeMs: Long = 0L
    private var lastKnownProgress = 0f
    private var lastPhaseNumber = 0
    private var lastProgressPhase = -1
    private var lastProgressUiMs = 0L
    private var lastSnapshotTimeMs = 0L

    // Dynamic phase duration tracking — replaces hardcoded values
    private val phaseActualDurations = FloatArray(ScanPipeline.TOTAL_PHASE_COUNT) { 0f }
    private val phaseStartTimes = LongArray(ScanPipeline.TOTAL_PHASE_COUNT) { 0L }
    private val phaseDefaultDurations = floatArrayOf(3f, 60f, 20f, 10f, 15f, 6f, 8f, 12f, 5f)

    private val pipeline = ScanPipeline(application)
    private val database = AppDatabase.getInstance(application)
    private var scanPath: String = ""
    private var scanName: String = ""
    private var wakeLock: PowerManager.WakeLock? = null

    companion object {
        @Volatile var activeScanPath: String? = null
        @Volatile var scanCancelled: Boolean = false
    }

    init {
        val prefs = application.getSharedPreferences("scan_checkpoint", Context.MODE_PRIVATE)
        val active = prefs.getBoolean("scan_active", false)
        val savedPath = prefs.getString("apk_path", null)
        val savedName = prefs.getString("apk_name", null)
        if (active && !savedPath.isNullOrBlank()) {
            scanPath = savedPath
            scanName = savedName ?: ""
            _uiState.value = ScanUiState(
                lines = listOf(LogEntry("Resuming scan — restarting pipeline...", LineType.INFO)),
                isPreparing = true, currentActivity = "Preparing APK file...",
                apkPath = savedPath, apkName = savedName ?: ""
            )
            prefs.edit().clear().apply()
            startScan(savedPath, savedName ?: "")
        }
    }

    fun startScan(apkPath: String, apkName: String) {
        scanPath = apkPath
        scanName = apkName
        scanCancelled = false
        if (_uiState.value.isScanning) return
        if (_uiState.value.isPreparing && scanJob?.isActive == true) return

        val prefs = application.getSharedPreferences("scan_checkpoint", Context.MODE_PRIVATE)
        val checkpointActive = prefs.getBoolean("scan_active", false)
        if (checkpointActive && apkPath == prefs.getString("apk_path", null)) {
            try {
                application.stopService(Intent(application, ScanForegroundService::class.java))
            } catch (_: Exception) {}
            prefs.edit().clear().apply()
        }

        val lines = java.util.Collections.synchronizedList(ArrayList<LogEntry>(64))

        _uiState.value = ScanUiState(
            lines = synchronized(lines) { ArrayList(lines) },
            isPreparing = true, currentActivity = "Preparing APK file...",
            apkPath = apkPath, apkName = apkName
        )

        if (activeScanPath == apkPath && activeScanPath != null) {
            if (scanJob?.isActive == true) {
                _uiState.value = _uiState.value.copy(
                    isScanning = true, currentActivity = "Scan in progress...",
                    lines = listOf(LogEntry("Reconnected to running scan...", LineType.INFO))
                )
                return
            }
            activeScanPath = null
            releaseWakeLock()
        }

        activeScanPath = apkPath
        _lastCompletedResult = null
        startTimeMs = System.currentTimeMillis()
        lastSnapshotTimeMs = startTimeMs
        lastKnownProgress = 0f
        lastPhaseNumber = 0
        lastProgressPhase = -1

        try {
            val pm = application.getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "APKViper:ScanLock")
            wakeLock?.acquire(10 * 60 * 1000L)
        } catch (e: Exception) {
            android.util.Log.w("ScanViewModel", "Wake lock failed: ${e.message}")
        }

        lines.addAll(TerminalTemplates.scanStart(apkName, "brutal"))
        _uiState.value = ScanUiState(
            lines = synchronized(lines) { ArrayList(lines) },
            isScanning = true, isPreparing = false, totalPhases = ScanPipeline.TOTAL_PHASE_COUNT,
            currentActivity = "Extracting APK...", apkPath = apkPath, apkName = apkName
        )

        try {
            application.startForegroundService(Intent(application, ScanForegroundService::class.java))
        } catch (e: Exception) {
            android.util.Log.w("ScanViewModel", "Foreground service failed: ${e.message}")
        }

        scanJob = viewModelScope.launch(Dispatchers.IO) {
            ScanForegroundService.resetCancelFlag()
            scanCancelled = false

            fun snapshotUi(throttleMs: Long = 500L) {
                val now = System.currentTimeMillis()
                if (now - lastSnapshotTimeMs < throttleMs) return
                lastSnapshotTimeMs = now
                // Cap at 200 lines to prevent massive State updates from killing animation frames
                val all = synchronized(lines) { ArrayList(lines) }
                val capped = if (all.size > 200) all.takeLast(200) else all
                _uiState.value = _uiState.value.copy(lines = capped)
            }

            coroutineScope {
                val cancelJob = Job()
                launch(cancelJob) {
                    while (isActive) {
                        if (ScanForegroundService.cancelRequested) {
                            scanCancelled = true
                            cancelJob.cancel()
                        }
                        delay(500)
                    }
                }

                var pipelineError: Throwable? = null
                var scanResult: ScanResult? = null

                try {
                    if (scanCancelled) throw CancellationException("Cancelled by user")
                    scanResult = pipeline.scan(
                        apkUri = apkPath, apkName = apkName,
                        onProgress = { phase, total, message ->
                            if (scanCancelled) throw CancellationException("Cancelled by user")
                            val activityText = message.removePrefix("Phase ").trim()
                                .replace(Regex("""^\d+/\d+\s*"""), "").trim()
                            if (phase != lastProgressPhase) {
                                lines.add(TerminalTemplates.scanPhase(phase, total, message))
                                lastProgressPhase = phase
                            }

                            val nowMs = System.currentTimeMillis()
                            val elapsedTotalS = (nowMs - startTimeMs) / 1000f
                            if (phase != lastPhaseNumber) {
                                // Record completed phase duration
                                if (lastPhaseNumber > 0 && lastPhaseNumber <= ScanPipeline.TOTAL_PHASE_COUNT) {
                                    val prevIdx = lastPhaseNumber - 1
                                    val phaseDur = (nowMs - phaseStartTimes[prevIdx]) / 1000f
                                    if (phaseDur > 0) phaseActualDurations[prevIdx] = phaseDur
                                }
                                lastPhaseNumber = phase
                                val phaseIdx = (phase - 1).coerceIn(0, ScanPipeline.TOTAL_PHASE_COUNT - 1)
                                phaseStartTimes[phaseIdx] = nowMs
                            }
                            val phaseIdx = (phase - 1).coerceIn(0, ScanPipeline.TOTAL_PHASE_COUNT - 1)
                            val subElapsed = (nowMs - phaseStartTimes[phaseIdx]) / 1000f
                            // Use actual duration if available, otherwise default
                            val actualDur = phaseActualDurations[phaseIdx]
                            val estPhase = if (actualDur > 0) maxOf(subElapsed, actualDur)
                                else maxOf(subElapsed, phaseDefaultDurations.getOrElse(phaseIdx) { 5f })
                            val timeBased = (subElapsed / estPhase) * (1f / total)
                            val stepBased = (phase - 1).toFloat() / total
                            val smooth = minOf(stepBased + timeBased, 1f)
                            val display = maxOf(smooth, lastKnownProgress)
                            lastKnownProgress = display

                            // Weighted ETA: remaining phases × their estimated durations
                            var remainingEstimate = 0f
                            for (p in phaseIdx until total) {
                                val d = phaseActualDurations[p]
                                remainingEstimate += if (d > 0) d else phaseDefaultDurations.getOrElse(p) { 5f }
                            }
                            val remainingAfterCurrent = remainingEstimate * (1f - (subElapsed / estPhase))
                            val eta = if (display > 0.05f && display < 0.98f)
                                ((elapsedTotalS / display) - elapsedTotalS).toInt() else 0
                            val weightedEta = if (elapsedTotalS > 5f && display > 0.1f) eta
                                else remainingAfterCurrent.toInt()

                            if (nowMs - lastProgressUiMs > 200) {
                                lastProgressUiMs = nowMs
                                _uiState.value = _uiState.value.copy(
                                    currentPhase = phase, totalPhases = total,
                                    progress = display, currentActivity = activityText,
                                    etaSeconds = if (weightedEta in 1..3600) weightedEta else if (eta in 1..3600) eta else 0
                                )
                            }
                            updateNotification(phase, total, message)
                        },
                        onFinding = { severity, msg ->
                            if (scanCancelled) throw CancellationException("Cancelled by user")
                            lines.add(TerminalTemplates.scanFinding(severity, msg))
                            if (lines.size % 5 == 0) snapshotUi(150)
                        },
                        onLog = { msg, type ->
                            if (scanCancelled) throw CancellationException("Cancelled by user")
                            lines.add(LogEntry(msg, type))
                            if (lines.size % 10 == 0) snapshotUi()
                        }
                    )
                } catch (e: CancellationException) {
                    releaseWakeLock()
                    application.getSharedPreferences("scan_checkpoint", Context.MODE_PRIVATE).edit().clear().apply()
                    _uiState.value = _uiState.value.copy(
                        lines = synchronized(lines) { ArrayList(lines) }.also { it.add(LogEntry("Cancelled", LineType.WARNING)) },
                        isScanning = false, errorMessage = "Cancelled",
                        etaSeconds = 0, currentActivity = "Cancelled"
                    )
                    application.stopService(Intent(application, ScanForegroundService::class.java))
                    return@coroutineScope
                } catch (e: OutOfMemoryError) {
                    releaseWakeLock()
                    application.getSharedPreferences("scan_checkpoint", Context.MODE_PRIVATE).edit().clear().apply()
                    // Never show "memory limit" — the pipeline manages memory adaptively.
                    // This catch is belt-and-suspenders for truly pathological cases.
                    System.gc()
                    val msg = "Scan did not complete — APK too large. Try splitting the APK or using a lighter scan mode."
                    _uiState.value = _uiState.value.copy(
                        lines = synchronized(lines) { ArrayList(lines) }.also { it.add(LogEntry(msg, LineType.WARNING)) },
                        isScanning = false, errorMessage = msg,
                        etaSeconds = 0, currentActivity = "Too large"
                    )
                    application.stopService(Intent(application, ScanForegroundService::class.java))
                    return@coroutineScope
                } catch (e: Exception) {
                    pipelineError = e
                }

                if (pipelineError != null) {
                    releaseWakeLock()
                    application.getSharedPreferences("scan_checkpoint", Context.MODE_PRIVATE).edit().clear().apply()
                    val msg = pipelineError.message ?: "Unknown error"
                    _uiState.value = _uiState.value.copy(
                        lines = synchronized(lines) { ArrayList(lines) }.also { it.add(LogEntry(msg, LineType.DANGER)) },
                        isScanning = false, errorMessage = msg,
                        etaSeconds = 0, currentActivity = "Error"
                    )
                    application.stopService(Intent(application, ScanForegroundService::class.java))
                    return@coroutineScope
                }

                val result = scanResult ?: run {
                    releaseWakeLock()
                    _uiState.value = _uiState.value.copy(
                        lines = synchronized(lines) { ArrayList(lines) }.also { it.add(LogEntry("Scan produced no result", LineType.DANGER)) },
                        isScanning = false, errorMessage = "No result",
                        etaSeconds = 0, currentActivity = "Error"
                    )
                    application.stopService(Intent(application, ScanForegroundService::class.java))
                    return@coroutineScope
                }

                releaseWakeLock()
                application.getSharedPreferences("scan_checkpoint", Context.MODE_PRIVATE).edit().clear().apply()

                try {
                    database.scanDao().insert(result)
                    ScanEventBus.emitCompleted()
                } catch (e: Exception) {
                    android.util.Log.e("ScanViewModel", "DB insert failed", e)
                    lines.add(LogEntry("Save to history failed", LineType.WARNING))
                    withContext(Dispatchers.Main) {
                        Toast.makeText(application, "Failed to save scan: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }

                lines.addAll(TerminalTemplates.scanComplete(result.threatScore, result.threatLevel.name))
                _lastCompletedResult = result
                _uiState.value = _uiState.value.copy(
                    lines = synchronized(lines) { ArrayList(lines) },
                    isScanning = false, scanComplete = true, progress = 1f,
                    etaSeconds = 0, currentActivity = "Complete", result = result
                )
                ScanForegroundService.showScanComplete(application, apkName, result.threatLevel.name, result.threatScore, scanPath)
                application.stopService(Intent(application, ScanForegroundService::class.java))
            }
        }
    }

    fun reset() {
        scanCancelled = false
        scanJob?.cancel()
        scanJob = null
        _uiState.value = ScanUiState()
    }

    fun cancelScan() {
        scanCancelled = true
        pipeline.cancel()
        scanJob?.cancel()
        scanJob = null
        releaseWakeLock()
        _uiState.value = _uiState.value.copy(isScanning = false, currentActivity = "Cancelled")
        application.getSharedPreferences("scan_checkpoint", Context.MODE_PRIVATE).edit().clear().apply()
        application.stopService(Intent(application, ScanForegroundService::class.java))
    }

    override fun onCleared() {
        super.onCleared()
        pipeline.shutdown()
    }

    private fun releaseWakeLock() {
        try { wakeLock?.release() } catch (_: Exception) {}
        wakeLock = null
    }

    private var lastNotificationMs = 0L

    private fun updateNotification(phase: Int, total: Int, message: String) {
        val now = System.currentTimeMillis()
        if (now - lastNotificationMs < 2000L) return // Throttle: max 1 update per 2 seconds
        lastNotificationMs = now
        try {
            application.startForegroundService(Intent(application, ScanForegroundService::class.java).apply {
                putExtra(ScanForegroundService.EXTRA_PROGRESS, ((phase.toFloat() / total) * 100).toInt())
                putExtra(ScanForegroundService.EXTRA_PHASE, message)
                putExtra(ScanForegroundService.EXTRA_SCAN_PATH, scanPath)
                putExtra(ScanForegroundService.EXTRA_SCAN_NAME, scanName)
            })
        } catch (e: Exception) {
            // Ignore — notification service may be unavailable
        }
    }
}
