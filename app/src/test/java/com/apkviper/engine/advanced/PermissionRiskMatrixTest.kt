package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class PermissionRiskMatrixTest {
    private val matrix = PermissionRiskMatrix()

    @Test
    fun noPermissions_returnsEmpty() {
        val findings = matrix.analyze(emptyList(), 0)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun smsAndInternet_harvesterDetected() {
        val findings = matrix.analyze(
            listOf("READ_SMS", "RECEIVE_BOOT_COMPLETED", "INTERNET"), 0
        )
        assertTrue(findings.any { it.title == "SMS Harvester" })
        assertEquals(Severity.CRITICAL, findings.first { it.title == "SMS Harvester" }.severity)
    }

    @Test
    fun overlayAndAccessibility_criticalDetected() {
        val findings = matrix.analyze(
            listOf("SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"), 0
        )
        assertTrue(findings.any { it.title == "Overlay Attack" })
    }

    @Test
    fun locationAndBoot_trackerDetected() {
        val findings = matrix.analyze(
            listOf("ACCESS_FINE_LOCATION", "INTERNET", "RECEIVE_BOOT_COMPLETED"), 0
        )
        assertTrue(findings.any { it.title == "Boot-time Location Tracker" })
    }

    @Test
    fun singleHighRiskPermission_mediumSeverity() {
        val findings = matrix.analyze(
            listOf("BIND_ACCESSIBILITY_SERVICE"), 0
        )
        val permFinding = findings.find { it.title == "Privileged Permission Usage" }
        assertNotNull(permFinding)
        assertEquals(Severity.MEDIUM, permFinding!!.severity)
    }

    @Test
    fun twoHighRiskPermissions_highSeverity() {
        val findings = matrix.analyze(
            listOf("BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"), 0
        )
        val permFinding = findings.find { it.title == "Privileged Permission Usage" }
        assertNotNull(permFinding)
        assertEquals(Severity.HIGH, permFinding!!.severity)
    }

    @Test
    fun manyPermissionsAndServices_overPrivileged() {
        val perms = (1..16).map { "PERMISSION_$it" }
        val findings = matrix.analyze(perms, 10)
        assertTrue(findings.any { it.title == "Over-privileged App" })
    }

    @Test
    fun androidPermissionPrefix_normalized() {
        val findings = matrix.analyze(
            listOf("android.permission.READ_SMS", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"), 0
        )
        assertTrue(findings.any { it.title == "SMS Harvester" })
    }

    @Test
    fun partialComboMatch_belowThreshold_noFinding() {
        val findings = matrix.analyze(
            listOf("CAMERA", "RECORD_AUDIO"), 0
        )
        assertFalse(findings.any { it.title == "Full RAT Capability" })
    }

    @Test
    fun privacyRiskScore_emptyFindings_zero() {
        assertEquals(0, matrix.getPrivacyRiskScore(emptyList()))
    }

    @Test
    fun privacyRiskScore_criticalFindings_highScore() {
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.CRITICAL, "SMS Harvester", "desc"),
            Finding(FindingCategory.MANIFEST, Severity.CRITICAL, "Overlay Attack", "desc")
        )
        val score = matrix.getPrivacyRiskScore(findings)
        assertTrue(score >= 60)
    }

    @Test
    fun privacyRiskScore_mixedFindings_cappedAt100() {
        val findings = (1..20).map {
            Finding(FindingCategory.MANIFEST, Severity.CRITICAL, "SMS Harvester $it", "desc")
        }
        val score = matrix.getPrivacyRiskScore(findings)
        assertTrue(score <= 100)
    }

    @Test
    fun fullSurveillanceSuite_detected() {
        val findings = matrix.analyze(
            listOf("ACCESS_COARSE_LOCATION", "ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO"), 0
        )
        assertTrue(findings.any { it.title == "Full Surveillance Suite" })
    }

    // --- Adaptive threshold (appPurpose) tests ---

    @Test
    fun fileManager_skipsStorageDropper() {
        val findings = matrix.analyze(
            listOf("MANAGE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES", "INTERNET"), 0,
            appPurpose = "FILE_MANAGER"
        )
        assertFalse("FILE_MANAGER should skip Storage Dropper",
            findings.any { it.title == "Storage Dropper" })
    }

    @Test
    fun fileManager_stillDetectsSmsHarvester() {
        val findings = matrix.analyze(
            listOf("READ_SMS", "RECEIVE_BOOT_COMPLETED", "INTERNET"), 0,
            appPurpose = "FILE_MANAGER"
        )
        assertTrue("FILE_MANAGER should still detect SMS Harvester",
            findings.any { it.title == "SMS Harvester" })
    }

    @Test
    fun cameraApp_skipsAVSurveillance() {
        val findings = matrix.analyze(
            listOf("CAMERA", "RECORD_AUDIO", "INTERNET"), 0,
            appPurpose = "CAMERA_APP"
        )
        assertFalse("CAMERA_APP should skip A/V Surveillance",
            findings.any { it.title == "A/V Surveillance" })
    }

    @Test
    fun browser_skipsNetworkManipulator() {
        val findings = matrix.analyze(
            listOf("INTERNET", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE"), 0,
            appPurpose = "BROWSER"
        )
        assertFalse("BROWSER should skip Network Manipulator",
            findings.any { it.title == "Network Manipulator" })
    }

    @Test
    fun generalPurpose_noSkips() {
        val findings = matrix.analyze(
            listOf("MANAGE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES", "INTERNET"), 0,
            appPurpose = "GENERAL"
        )
        assertTrue("GENERAL purpose should detect Storage Dropper",
            findings.any { it.title == "Storage Dropper" })
    }

    @Test
    fun partialMatchAtThreshold_downgradesSeverity() {
        val findings = matrix.analyze(
            listOf("READ_SMS", "RECEIVE_BOOT_COMPLETED", "INTERNET"), 0
        )
        val finding = findings.find { it.title == "SMS Harvester" }
        assertNotNull(finding)
        assertEquals("Full match should keep CRITICAL severity",
            Severity.CRITICAL, finding!!.severity)
    }

    @Test
    fun privacyRiskScore_empty_returnsZero() {
        assertEquals(0, matrix.getPrivacyRiskScore(emptyList()))
    }

    @Test
    fun privacyRiskScore_criticalFindings_cappedAt100() {
        val findings = (1..10).map {
            Finding(FindingCategory.MANIFEST, Severity.CRITICAL, "SMS Harvester $it", "desc")
        }
        val score = matrix.getPrivacyRiskScore(findings)
        assertTrue(score <= 100)
    }
}
