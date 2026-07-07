package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class BackgroundResourceMonitorTest {
    private val monitor = BackgroundResourceMonitor()

    private fun service(name: String, exported: Boolean = false, fg: Boolean = false,
                        stopTask: Boolean = false, filters: List<String> = emptyList(),
                        raw: String = ""): BackgroundResourceMonitor.ServiceProfile =
        BackgroundResourceMonitor.ServiceProfile(name, exported, fg, stopTask, filters, raw)

    @Test
    fun emptyInput_noFindings() {
        assertTrue(monitor.analyze("", emptyList(), emptyList(), emptyList()).isEmpty())
    }

    @Test
    fun highServiceCountWithNetwork_mediumSeverity() {
        val services = (1..6).map { service("Svc$it", raw = "normal") }
        val findings = monitor.analyze("", listOf("android.permission.INTERNET"), services, emptyList())
        assertTrue(findings.any { it.title == "High Service Count" })
        assertEquals(Severity.MEDIUM, findings.first { it.title == "High Service Count" }.severity)
    }

    @Test
    fun stickyServices_detected() {
        val services = listOf(
            service("Svc1", raw = "START_STICKY"),
            service("Svc2", raw = "START_STICKY")
        )
        val findings = monitor.analyze("", emptyList(), services, emptyList())
        assertTrue(findings.any { it.title == "Sticky Services Detected" })
    }

    @Test
    fun threeOrMoreStickyServices_highSeverity() {
        val services = (1..4).map { service("Svc$it", raw = "START_STICKY") }
        val findings = monitor.analyze("", emptyList(), services, emptyList())
        val sticky = findings.first { it.title == "Sticky Services Detected" }
        assertEquals(Severity.HIGH, sticky.severity)
    }

    @Test
    fun wakeLockBootNetwork_persistentBackgroundWorker() {
        val findings = monitor.analyze(
            "",
            listOf("android.permission.WAKE_LOCK", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"),
            emptyList(), emptyList()
        )
        assertTrue(findings.any { it.title == "Persistent Background Worker" })
    }

    @Test
    fun clickFraudIndicators_detected() {
        val services = (1..3).map { service("Svc$it") }
        val findings = monitor.analyze(
            "",
            listOf("android.permission.WAKE_LOCK", "android.permission.VIBRATE", "android.permission.INTERNET"),
            services, emptyList()
        )
        assertTrue(findings.any { it.title == "Click Fraud Indicators" })
    }

    @Test
    fun batteryOptimizationBypass_detected() {
        val findings = monitor.analyze(
            "",
            listOf("android.permission.SET_ALARM", "android.permission.WAKE_LOCK", "android.permission.INTERNET"),
            emptyList(), emptyList()
        )
        assertTrue(findings.any { it.title == "Battery Optimization Bypass" })
    }

    @Test
    fun autoInstallDropper_critical() {
        val findings = monitor.analyze(
            "",
            listOf("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECEIVE_BOOT_COMPLETED"),
            emptyList(), emptyList()
        )
        assertTrue(findings.any { it.title == "Auto-Install Dropper" })
        assertEquals(Severity.CRITICAL, findings.first { it.title == "Auto-Install Dropper" }.severity)
    }

    @Test
    fun serviceDominantArchitecture_detected() {
        val manifestXml = """
            <activity android:name=".Main"/>
            <activity android:name=".Second"/>
        """.trimIndent()
        val services = (1..5).map { service("Svc$it") }
        val findings = monitor.analyze(manifestXml, emptyList(), services, emptyList())
        assertTrue(findings.any { it.title == "Service-Dominant Architecture" })
    }

    @Test
    fun exportedServicesExposure_detected() {
        val services = (1..4).map { service("Svc$it", exported = true) }
        val findings = monitor.analyze("", emptyList(), services, emptyList())
        assertTrue(findings.any { it.title == "Exported Services Exposure" })
    }

    @Test
    fun multiReceiverBootHooks_detected() {
        val services = (1..4).map { service("Svc$it") }
        val receivers = listOf("BOOT_COMPLETED", "BOOT_COMPLETED2", "BOOT_COMPLETED3")
        val findings = monitor.analyze("", emptyList(), services, receivers)
        assertTrue(findings.any { it.title == "Multi-Receiver Boot Hooks" })
    }

    @Test
    fun dataSyncAbuse_detected() {
        val services = (1..3).map { service("SyncSvc$it", fg = true, raw = "dataSync") }
        val findings = monitor.analyze(
            "",
            listOf("android.permission.FOREGROUND_SERVICE_DATA_SYNC"),
            services, emptyList()
        )
        assertTrue(findings.any { it.title == "Data Sync Abuse" })
    }
}
