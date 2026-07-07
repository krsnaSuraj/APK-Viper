package com.apkviper.engine.advanced

import org.junit.Assert.*
import org.junit.Test

class PermissionRiskMatrixCombosTest {
    private val matrix = PermissionRiskMatrix()

    @Test
    fun bankingTrojanProfile_detected() {
        val result = matrix.analyze(
            listOf("android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SEND_SMS", "android.permission.READ_CONTACTS",
                "android.permission.CAMERA", "android.permission.INTERNET"), 0
        )
        assertTrue(result.any { it.title.contains("Banking Trojan") })
    }

    @Test
    fun overlaySmsTrojan_detected() {
        val result = matrix.analyze(
            listOf("android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.SEND_SMS"), 0
        )
        assertTrue(result.any { it.title.contains("Overlay SMS") })
    }

    @Test
    fun persistentSmsTrojan_detected() {
        val result = matrix.analyze(
            listOf("android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.RECEIVE_BOOT_COMPLETED"), 0
        )
        assertTrue(result.any { it.title.contains("Persistent SMS") })
    }

    @Test
    fun notificationSmsGrabber_detected() {
        val result = matrix.analyze(
            listOf("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET"), 0
        )
        assertTrue(result.any { it.title.contains("Notification SMS") })
    }

    @Test
    fun storageDropper_detected() {
        val result = matrix.analyze(
            listOf("android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.INTERNET"), 0
        )
        assertTrue(result.any { it.title.contains("Storage Dropper") })
    }

    @Test
    fun stalkerwareSuite_detected() {
        val result = matrix.analyze(
            listOf("android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.INTERNET"), 0
        )
        assertTrue(result.any { it.title.contains("Stalkerware") })
    }

    @Test
    fun smsRelayHub_detected() {
        val result = matrix.analyze(
            listOf("android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
                "android.permission.INTERNET"), 0
        )
        assertTrue(result.any { it.title.contains("SMS Relay") })
    }

    @Test
    fun mediaExfiltrationSuite_detected() {
        val result = matrix.analyze(
            listOf("android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.CAMERA",
                "android.permission.INTERNET"), 0
        )
        assertTrue(result.any { it.title.contains("Media Exfiltration") })
    }

    @Test
    fun noDangerousCombos_returnsEmpty() {
        val result = matrix.analyze(
            listOf("android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE"), 0
        )
        assertTrue(result.isEmpty())
    }

    @Test
    fun partialMatch_noFalsePositive() {
        val result = matrix.analyze(
            listOf("android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS"), 0
        )
        assertTrue(result.isEmpty())
    }
}