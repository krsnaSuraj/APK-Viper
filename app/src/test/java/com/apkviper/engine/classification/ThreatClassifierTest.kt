package com.apkviper.engine.classification

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class ThreatClassifierTest {
    private val classifier = ThreatClassifier()

    @Test
    fun emptyFindings_cleanClassification() {
        val result = classifier.classify(emptyList())
        assertEquals("Clean Application", result.classification)
        assertTrue(result.remediations.isEmpty())
    }

    @Test
    fun benignFindings_noMalwareLabel() {
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.LOW, "Low perm", "desc")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("No Malicious", ignoreCase = true) == true)
        assertTrue(result.remediations.isEmpty())
    }

    @Test
    fun ransomwareDetection() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "filecoder detected", "encrypts files"),
            Finding(FindingCategory.NATIVE, Severity.HIGH, "mprotect found", "native memory protection")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Ransomware", ignoreCase = true) == true)
        assertTrue(result.remediations.isNotEmpty())
    }

    @Test
    fun ratDetection() {
        val findings = listOf(
            // Corroborating strong evidence from another engine (e.g. MalwarePatternDetector).
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "confirmed"),
            Finding(FindingCategory.NETWORK, Severity.CRITICAL, "remote socket command exec", "connects and executes system commands")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Remote Access") == true ||
                    result.classification?.contains("RAT") == true)
    }

    @Test
    fun bankingTrojanDetection() {
        val findings = listOf(
            // A real banking trojan also trips a high-fidelity MALWARE rule (e.g. accessibility abuse).
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Accessibility Abuse", "performGlobalAction"),
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing overlay", "sms stealing overlay attack")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Banking") == true)
    }

    @Test
    fun spywareDetection() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "confirmed"),
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "boot location tracker", "GPS location at boot")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("Spyware") == true)
    }

    @Test
    fun dropperDetection() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "confirmed"),
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
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "confirmed"),
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
    fun benignAllSeverities_noRemediations() {
        // Mix of severities across benign categories, but NO strong malware evidence —
        // must NOT be labelled malicious or produce scary remediations.
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.INFO, "Info manifest", "info only"),
            Finding(FindingCategory.STRING, Severity.LOW, "Low string", "low severity"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "Medium perm", "medium severity"),
            Finding(FindingCategory.CODE, Severity.HIGH, "High code", "high severity"),
            Finding(FindingCategory.NATIVE, Severity.CRITICAL, "Critical native", "critical severity")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(result.classification?.contains("No Malicious", ignoreCase = true) == true)
        assertTrue(result.remediations.isEmpty())
    }

    @Test
    fun singleInfoFinding_benign() {
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.INFO, "Info only", "no risk")
        )
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("No Malicious", ignoreCase = true) == true)
        assertTrue(result.remediations.isEmpty())
    }

    @Test
    fun onlyLowFindings_benign() {
        val findings = (1..3).map {
            Finding(FindingCategory.PERMISSION, Severity.LOW, "Low $it", "minor issue")
        }
        val result = classifier.classify(findings)
        assertTrue(result.classification?.contains("No Malicious", ignoreCase = true) == true)
        assertTrue(result.remediations.isEmpty())
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
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "confirmed"),
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
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "confirmed"),
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
        assertNotNull("Classification should be non-null with strong evidence", result.classification)
        assertTrue("Remediations should be populated", result.remediations.isNotEmpty())
    }

    @Test
    fun networkFindings_ratClassification() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "malware", "confirmed"),
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
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Accessibility Abuse", "performGlobalAction"),
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing sms overlay", "overlay attack intercepts SMS")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(
            result.classification?.contains("Banking") == true ||
            result.classification?.contains("Trojan") == true
        )
    }

    // ---- Cross-classification guards ----

    @Test
    fun overlayWithoutPackerCategory_doesNotCrossClassifyAsBanking() {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.HIGH, "phishing overlay", "overlay attack detected")
        )
        val result = classifier.classify(findings)
        // No strong evidence (CODE is not a malicious category) → benign, and no Banking label.
        val isBanking = result.classification?.contains("Banking") == true
        assertFalse("Overlay in CODE should not trigger Banking", isBanking)
    }

    @Test
    fun overlayWithoutSms_doesNotCrossClassifyAsBanking() {
        val findings = listOf(
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing overlay", "overlay attack without message interception")
        )
        val result = classifier.classify(findings)
        val isBanking = result.classification?.contains("Banking") == true
        assertFalse("Overlay without SMS should not trigger Banking", isBanking)
    }

    @Test
    fun dexLoaderWithoutInstallPerms_doesNotCrossClassifyAsDropper() {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.HIGH, "dex class loader detected", "loads dex")
        )
        val result = classifier.classify(findings)
        val isDropper = result.classification?.contains("Dropper") == true
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
        assertFalse("Socket without system exec should not trigger RAT", isRAT)
    }

    @Test
    fun locationWithoutBoot_doesNotCrossClassifyAsSpyware() {
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "location tracking", "GPS location access")
        )
        val result = classifier.classify(findings)
        val isSpyware = result.classification?.contains("Spyware") == true
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
        assertFalse("Accessibility without clipboard should not trigger Keylogger", isKeylogger)
    }

    @Test
    fun singleFindingWithAllKeywords_classifiesCorrectly() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Accessibility Abuse", "performGlobalAction"),
            Finding(FindingCategory.PACKER, Severity.HIGH, "phishing sms overlay", "SMS stealing overlay attack")
        )
        val result = classifier.classify(findings)
        assertNotNull(result.classification)
        assertTrue(
            "PACKER + overlay + SMS corroborated by a high-fidelity MALWARE rule should be Banking Trojan",
            result.classification?.contains("Banking") == true
        )
    }

    @Test
    fun emptyFindings_returnsSafeClassification() {
        val result = classifier.classify(emptyList())
        assertEquals("Clean Application", result.classification)
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
        assertTrue("With 2 critical findings, should have network isolation or factory reset recommendation",
            result.remediations.any { it.contains("Network") || it.contains("reset") || it.contains("critical") })
    }

    @Test
    fun heuristicLowConfidenceMalware_moddedApp_notLabelledMalicious() {
        // Regression: noisy heuristic MALWARE findings (LOW confidence) from a modded game
        // with ad SDKs must NOT be labelled RAT / MALICIOUS.
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Overlay Phishing", "suspicious API chain",
                confidence = FindingConfidence.LOW),
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Confirmed Data Exfiltration Chain", "ad SDK signals",
                confidence = FindingConfidence.LOW),
            Finding(FindingCategory.NATIVE, Severity.CRITICAL, "Reverse Shell Capability", "system() in native lib"),
            Finding(FindingCategory.NETWORK, Severity.HIGH, "Suspicious Socket", "outbound socket")
        )
        val result = classifier.classify(findings)
        assertTrue(
            "Heuristic LOW-confidence MALWARE must not produce a malicious label (got ${result.classification})",
            result.classification?.contains("No Malicious", ignoreCase = true) == true
        )
        assertTrue("No scary remediations for a benign/modded app", result.remediations.isEmpty())
    }

    @Test
    fun twoMediumHighFidelityMalware_isLabelledMalicious() {
        // Regression: two high-fidelity MEDIUM MALWARE findings (e.g. Keylogger + Accessibility
        // Abuse combos from MalwarePatternDetector) are genuine malware and MUST be labelled
        // malicious — not "No Malicious Behavior Detected".
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.MEDIUM, "Keylogger", "KeyEvent + InputMethodService",
                confidence = FindingConfidence.MEDIUM),
            Finding(FindingCategory.MALWARE, Severity.MEDIUM, "Accessibility Abuse", "performGlobalAction",
                confidence = FindingConfidence.MEDIUM)
        )
        val result = classifier.classify(findings)
        assertFalse(
            "Two high-fidelity MEDIUM MALWARE findings must NOT be benign (got ${result.classification})",
            result.classification?.contains("No Malicious", ignoreCase = true) == true
        )
        assertNotNull("Genuine malware must have a non-null classification", result.classification)
        assertTrue("Genuine malware must produce remediations", result.remediations.isNotEmpty())
    }
}
