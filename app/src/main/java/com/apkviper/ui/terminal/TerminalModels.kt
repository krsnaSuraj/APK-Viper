package com.apkviper.ui.terminal

enum class LineType {
    INFO, WARNING, DANGER, SUCCESS, HEADER, OUTPUT, SYSTEM
}

data class LogEntry(
    val text: String,
    val type: LineType = LineType.OUTPUT,
    val timestamp: Long = System.currentTimeMillis(),
    val id: Long = idCounter.incrementAndGet()
) {
    companion object {
        private val idCounter = java.util.concurrent.atomic.AtomicLong(0)
    }
}

object TerminalTemplates {

    fun scanStart(filename: String, mode: String): List<LogEntry> = listOf(
        LogEntry("Scan started for $filename", LineType.INFO),
        LogEntry("Mode: ${mode.uppercase()}", LineType.INFO),
        LogEntry("Timestamp: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date())}", LineType.SYSTEM)
    )

    fun scanPhase(phase: Int, total: Int, name: String): LogEntry =
        LogEntry("Phase $phase/$total: $name", LineType.INFO)

    fun scanFinding(severity: String, message: String): LogEntry {
        val lineType = when (severity.uppercase()) {
            "CRITICAL", "HIGH" -> LineType.DANGER
            "MEDIUM" -> LineType.WARNING
            "LOW", "INFO" -> LineType.INFO
            else -> LineType.WARNING
        }
        return LogEntry(message, lineType)
    }
    fun scanComplete(score: Int, level: String): List<LogEntry> = listOf(
        LogEntry("Scan complete", LineType.SUCCESS),
        LogEntry("Score: $score/100 — $level", when {
            score >= 70 -> LineType.DANGER
            score >= 50 -> LineType.WARNING
            score >= 30 -> LineType.INFO
            else -> LineType.SUCCESS
        })
    )
}
