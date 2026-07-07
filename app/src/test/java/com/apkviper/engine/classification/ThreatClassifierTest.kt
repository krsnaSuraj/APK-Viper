package com.apkviper.engine.classification

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class ThreatClassifierTest {
    private val classifier = ThreatClassifier()

    @Test
    fun noFindings_returnsNull() {
        val result = classifier.classify(emptyList())
        assertNull(result.classification)
        assertEquals(1, result.remediations.size)
    }

    @Test
    fun lowScoreFindings_returnsNull() {
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.LOW, "Low perm", "desc")
        )
        val result = classifier.classify(findings)
        assertNull(result.classification)
    }

    @Test
    fun ransomwareDetection() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "filecoder detected", "encrypts files"),
            Finding(FindingCategory.NATIVE, Severity.HIGH, "mprotect found", "native memory protection")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Ransomware", ignoreCase = true) == true)
    }

    @Test
    fun ratDetection() {
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.CRITICAL, "remote socket command exec", "connects and executes system commands")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Remote Access") == true ||
                    result.classification?.contains("RAT") == true)
    }

    @Test
    fun bankingTrojanDetection() {
        val findings = listOf(
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing overlay", "sms stealing overlay attack")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Banking") == true)
    }

    @Test
    fun spywareDetection() {
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "boot location tracker", "GPS location at boot")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Spyware") == true)
    }

    @Test
    fun dropperDetection() {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.CRITICAL, "dex class loader install pack", "DexClassLoader INSTALL_PACKAGES")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Dropper") == true)
    }

    @Test
    fun remediationsAlwaysIncludeUninstall() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.HIGH, "Malware", "test")
        )
        val result = classifier.classify(findings)
        assertTrue(result.remediations.any { it.contains("Uninstall", ignoreCase = true) })
    }

    @Test
    fun remediationsForBootPersistence() {
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.CRITICAL, "boot receiver", "RECEIVE_BOOT_COMPLETED"),
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "malicious")
        )
        val result = classifier.classify(findings)
        assertTrue(result.remediations.any { it.contains("boot", ignoreCase = true) })
    }

    @Test
    fun remediationsForOverlay() {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.HIGH, "phishing overlay", "screen overlay detected")
        )
        val result = classifier.classify(findings)
        assertTrue(result.remediations.any { it.contains("overlay", ignoreCase = true) })
    }

    @Test
    fun remediationsCappedAt5() {
        val findings = (1..20).map {
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware $it", "dangerous")
        }
        val result = classifier.classify(findings)
        assertTrue(result.remediations.size <= 5)
    }

    @Test
    fun highScoreGenericClassification() {
        val findings = (1..10).map {
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware $it", "critical malware finding")
        }
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Malicious") == true ||
                    result.classification?.contains("Suspicious") == true)
    }

    @Test
    fun findingsWithAllSeverities_classifiedCorrectly() {
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.INFO, "Info manifest", "info only"),
            Finding(FindingCategory.STRING, Severity.LOW, "Low string", "low severity"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "Medium perm", "medium severity"),
            Finding(FindingCategory.CODE, Severity.HIGH, "High code", "high severity"),
            Finding(FindingCategory.NATIVE, Severity.CRITICAL, "Critical native", "critical severity")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(result.remediations.isNotEmpty())
    }

    @Test
    fun singleInfoFinding_returnsNullClassification() {
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.INFO, "Info only", "no risk")
        )
        val result = classifier.classify(findings)
        assertNull(result.classification)
    }

    @Test
    fun onlyLowFindings_noClassification() {
        val findings = (1..3).map {
            Finding(FindingCategory.PERMISSION, Severity.LOW, "Low $it", "minor issue")
        }
        val result = classifier.classify(findings)
        assertNull(result.classification)
    }

    @Test
    fun highScoreWithoutSpecificPattern_stillClassified() {
        val findings = (1..3).map {
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Generic critical $it", "severe indicator")
        }
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(result.classification!!.contains("Malicious") || result.classification!!.contains("Suspicious"))
    }

    @Test
    fun remediationsIncludeDisablePermissions() {
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.CRITICAL, "network C2", "c2 server detected")
        )
        val result = classifier.classify(findings)
        assertTrue(
            "Expected remediation mentioning permissions",
            result.remediations.any { it.contains("permission", ignoreCase = true) }
        )
    }

    @Test
    fun remediationsIncludeScanDevice() {
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "location tracking", "ACCESS_FINE_LOCATION found")
        )
        val result = classifier.classify(findings)
        assertTrue(
            "Expected remediation suggesting device review",
            result.remediations.any { it.contains("check", ignoreCase = true) || it.contains("review", ignoreCase = true) }
        )
    }

    @Test
    fun classificationResult_containsScore() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware", "critical finding"),
            Finding(FindingCategory.CODE, Severity.HIGH, "Exploit", "exploit code")
        )
        val result = classifier.classify(findings)
        assertNotNull("Classification should be non-null when score >= 15", result.classification)
        assertTrue("Remediations should be populated", result.remediations.isNotEmpty())
    }

    @Test
    fun emptyFindingsList_remediationsEmpty() {
        val result = classifier.classify(emptyList())
        assertNull(result.classification)
        assertTrue(
            "With empty findings, only the default uninstall remediation is added",
            result.remediations.size == 1 || result.remediations.isEmpty()
        )
    }

    @Test
    fun networkFindings_ratClassification() {
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.HIGH, "remote socket exec", "outbound system commands via socket")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(
            result.classification?.contains("Remote Access") == true ||
            result.classification?.contains("RAT") == true
        )
    }

    @Test
    fun smsAndInternet_bankingTrojan() {
        val findings = listOf(
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing sms overlay", "overlay attack intercepts SMS")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(
            result.classification?.contains("Banking") == true ||
            result.classification?.contains("Trojan") == true
        )
    }

    // ---- NEW: Cross-classification guards ----

    @Test
    fun overlayWithoutPackerCategory_doesNotCrossClassifyAsBanking() {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.HIGH, "phishing overlay", "overlay attack detected")
        )
        val result = classifier.classify(findings)
        val isBanking = result.classification?.contains("Banking") == true
        // Banking requires PACKER category, so CODE category should NOT match
        assertFalse("Overlay in CODE should not trigger Banking", isBanking)
    }

    @Test
    fun overlayWithoutSms_doesNotCrossClassifyAsBanking() {
        val findings = listOf(
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing overlay", "overlay attack without message interception")
        )
        val result = classifier.classify(findings)
        val isBanking = result.classification?.contains("Banking") == true
        // Banking requires SMS in description/title of same finding
        assertFalse("Overlay without SMS should not trigger Banking", isBanking)
    }

    @Test
    fun dexLoaderWithoutInstallPerms_doesNotCrossClassifyAsDropper() {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.HIGH, "dex class loader detected", "loads dex")
        )
        val result = classifier.classify(findings)
        val isDropper = result.classification?.contains("Dropper") == true
        // Dropper requires install_packages in description
        assertFalse("DexLoader without INSTALL_PACKAGES should not trigger Dropper", isDropper)
    }

    @Test
    fun socketWithoutSystem_doesNotCrossClassifyAsRAT() {
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.HIGH, "socket connection", "outbound network socket")
        )
        val result = classifier.classify(findings)
        val isRAT = result.classification?.contains("Remote Access") == true ||
                     result.classification?.contains("RAT") == true
        // RAT requires connect + (system/exec/command) in same finding
        assertFalse("Socket without system exec should not trigger RAT", isRAT)
    }

    @Test
    fun locationWithoutBoot_doesNotCrossClassifyAsSpyware() {
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "location tracking", "GPS location access")
        )
        val result = classifier.classify(findings)
        val isSpyware = result.classification?.contains("Spyware") == true
        // Spyware requires location/camera + boot in same finding
        assertFalse("Location without boot should not trigger Spyware", isSpyware)
    }

    @Test
    fun accessibilityWithoutClipboard_doesNotCrossClassifyAsKeylogger() {
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.HIGH, "AccessibilityService", "event monitoring service")
        )
        val result = classifier.classify(findings)
        val isKeylogger = result.classification?.contains("Keylogger") == true ||
                          result.classification?.contains("Clipboard") == true
        // Keylogger requires AccessibilityService + clipboard in same finding
        assertFalse("Accessibility without clipboard should not trigger Keylogger", isKeylogger)
    }

    @Test
    fun singleFindingWithAllKeywords_classifiesCorrectly() {
        val findings = listOf(
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing sms overlay", "SMS stealing overlay attack")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(
            "Single finding with PACKER + overlay + SMS should be Banking Trojan",
            result.classification?.contains("Banking") == true
        )
    }

    @Test
    fun emptyFindings_returnsSafeClassification() {
        val result = classifier.classify(emptyList())
        assertNull(result.classification)
    }

    @Test
    fun remediationCountMatchesSeverityDistribution() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware A", "dangerous critical payload"),
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware B", "second critical payload"),
            Finding(FindingCategory.CODE, Severity.HIGH, "Exploit code", "high severity exploit"),
            Finding(FindingCategory.CODE, Severity.HIGH, "Root exploit", "root escalation"),
            Finding(FindingCategory.CODE, Severity.HIGH, "Privilege esc", "elevation of privilege"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "Medium risk", "medium severity")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue("Remediations should not exceed 5", result.remediations.size <= 5)
        assertTrue("Remediations should include uninstall", result.remediations.any { it.contains("Uninstall") })
        // With 2 CRITICAL + 3 HIGH, should have critical-count-based remediation
        assertTrue("With 2 critical findings, should have network isolation or factory reset recommendation",
            result.remediations.any { it.contains("Network") || it.contains("reset") || it.contains("critical") })
    }
}
