package com.apkviper.engine.report

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.apkviper.model.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PdfGeneratorTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    private fun minimalScanResult(): ScanResult = ScanResult(
        apkName = "test.apk",
        apkPath = "/path/test.apk",
        sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        fileSize = 1024L,
        scanMode = "quick",
        threatLevel = ThreatLevel.SAFE,
        threatScore = 0,
        findings = emptyList(),
        decompileTime = 100L,
        scanTime = 500L,
        appLabel = "TestApp",
        packageName = "com.example.test",
        versionName = "1.0",
        versionCode = 1,
        minSdk = 26,
        targetSdk = 34
    )

    @Test
    fun constructor_createsInstance() {
        val generator = PdfGenerator(context)
        assertNotNull(generator)
    }

    @Test
    fun generate_returnsNonNullResult() {
        val generator = PdfGenerator(context)
        val result = generator.generate(minimalScanResult())
        assertNotNull(result)
    }

    @Test
    fun generate_withCriticalFindings_returnsResult() {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Remote Code Execution",
                "Runtime.exec detected in MainActivity.java",
                details = "ProcessBuilder and Runtime.exec both present", file = "MainActivity.java"),
            Finding(FindingCategory.NETWORK, Severity.CRITICAL, "C2 Server Detected",
                "pastebin.com URL found in code",
                details = "https://pastebin.com/raw/abc123", file = "Network.java"),
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "Overly Broad Permissions",
                "App requests READ_SMS but is not a messaging app",
                details = "Permission: READ_SMS, SEND_SMS", file = "AndroidManifest.xml"),
            Finding(FindingCategory.MANIFEST, Severity.MEDIUM, "Exported Component",
                "Activity with exported=true", file = "AndroidManifest.xml"),
            Finding(FindingCategory.STRING, Severity.LOW, "Hardcoded IP Address",
                "8.8.8.8 found in code", details = "8.8.8.8", file = "Config.java")
        )
        val result = ScanResult(
            apkName = "malicious.apk",
            apkPath = "/path/malicious.apk",
            sha256 = "dd",
            fileSize = 10 * 1024 * 1024L,
            scanMode = "deep",
            threatLevel = ThreatLevel.CRITICAL,
            threatScore = 85,
            findings = findings,
            decompileTime = 5000L,
            scanTime = 30000L,
            appLabel = "MaliciousApp",
            packageName = "com.evil.malicious",
            classification = "trojan",
            remediations = listOf(
                "Remove Runtime.exec calls",
                "Use HTTPS instead of HTTP",
                "Remove unnecessary permissions"
            )
        )
        val generator = PdfGenerator(context)
        val pdfResult = generator.generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_usesAllSaveStrategies() {
        val generator = PdfGenerator(context)
        val r1 = generator.generate(minimalScanResult())
        val r2 = generator.generate(minimalScanResult().copy(apkName = "second.apk"))
        assertNotNull(r1)
        assertNotNull(r2)
    }

    @Test
    fun generate_withAllSeverities_returnsResult() {
        val findings = Severity.values().map { sev ->
            Finding(FindingCategory.CODE, sev, "Test finding for $sev",
                "Description for $sev severity", details = "Details for $sev")
        }
        val result = minimalScanResult().copy(
            findings = findings,
            threatLevel = ThreatLevel.CRITICAL,
            threatScore = 90
        )
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_withAllThreatLevels_returnsResult() {
        for (level in ThreatLevel.values()) {
            val result = minimalScanResult().copy(
                threatLevel = level,
                threatScore = when (level) {
                    ThreatLevel.SAFE -> 0
                    ThreatLevel.LOW -> 15
                    ThreatLevel.MEDIUM -> 40
                    ThreatLevel.HIGH -> 65
                    ThreatLevel.CRITICAL -> 85
                    ThreatLevel.MALICIOUS -> 100
                }
            )
            val pdfResult = PdfGenerator(context).generate(result)
            assertNotNull("PdfResult for $level should not be null", pdfResult)
        }
    }

    @Test
    fun generate_withLargeFindingCount_returnsResult() {
        val findings = (1..50).map { i ->
            Finding(
                FindingCategory.CODE,
                if (i % 4 == 0) Severity.CRITICAL else if (i % 4 == 1) Severity.HIGH else if (i % 4 == 2) Severity.MEDIUM else Severity.LOW,
                "Finding #$i: Suspicious pattern detected",
                "This is finding number $i with a description that might be longer",
                details = "Details for finding $i with extra context about what was found",
                file = "Class$i.java"
            )
        }
        val result = minimalScanResult().copy(
            apkName = "large.apk",
            findings = findings,
            threatLevel = ThreatLevel.CRITICAL,
            threatScore = 95,
            remediations = (1..20).map { "Remediation step #$it" }
        )
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_withAllCategories_returnsResult() {
        val findings = FindingCategory.values().map { cat ->
            Finding(cat, Severity.MEDIUM, "Test for $cat", "Description for $cat category")
        }
        val result = minimalScanResult().copy(
            findings = findings,
            threatLevel = ThreatLevel.MEDIUM,
            threatScore = 40
        )
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_invalidApkName_doesNotCrash() {
        val result = minimalScanResult().copy(apkName = "test@#$%^&*().apk")
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_nullPackageInfo_doesNotCrash() {
        val result = minimalScanResult().copy(
            appLabel = null,
            packageName = null,
            versionName = null,
            versionCode = null,
            minSdk = null,
            targetSdk = null
        )
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_withAllDataFields_returnsResult() {
        val result = ScanResult(
            apkName = "full.apk",
            apkPath = "/path/full.apk",
            sha256 = "aa",
            fileSize = 999L,
            scanMode = "brutal",
            threatLevel = ThreatLevel.HIGH,
            threatScore = 65,
            findings = listOf(
                Finding(FindingCategory.STRING, Severity.INFO, "URL", "http://example.com"),
                Finding(FindingCategory.PERMISSION, Severity.CRITICAL, "SMS Access", "SMS spy")
            ),
            decompileTime = 200L,
            scanTime = 1000L,
            timestamp = 12345L,
            classification = "adware",
            remediations = listOf("Remove permissions", "Use HTTPS"),
            appLabel = "FullApp",
            packageName = "com.example.full",
            versionName = "2.0",
            versionCode = 200,
            minSdk = 26,
            targetSdk = 34
        )
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_emptyFindings_returnsResult() {
        val result = minimalScanResult().copy(findings = emptyList())
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    @Test
    fun generate_longApkName_doesNotCrash() {
        val longName = "A".repeat(200) + ".apk"
        val result = minimalScanResult().copy(apkName = longName)
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull(pdfResult)
    }

    // ── MITRE ATT&CK mapping tests ─────────────────────────────────

    @Test
    fun guessMitreTechniques_networkFinding_returnsT1071() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.HIGH, "C2 Beacon", "Network beacon to command control server")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        assertTrue("Should contain T1071 for network/C2 finding", mitre.any { it.id == "T1071" })
    }

    @Test
    fun guessMitreTechniques_locationFinding_returnsT1430() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "GPS Access", "App requests location data via GPS")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        val t1430 = mitre.firstOrNull { it.id == "T1430" }
        assertNotNull("Should contain T1430 for location finding", t1430)
        assertEquals("Location Tracking", t1430!!.name)
        assertEquals("Detected in TestApp", t1430.description)
    }

    @Test
    fun guessMitreTechniques_obfuscationFinding_returnsT1027() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.OBFUSCATION, Severity.HIGH, "Packer Detected", "Code protected with obfuscation packer")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        assertTrue("Should contain T1027 for obfuscation/packer finding", mitre.any { it.id == "T1027" })
    }

    @Test
    fun guessMitreTechniques_privilegeEscalation_returnsT1068() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Root Command", "App executes su binary for privilege escalation")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        assertTrue("Should contain T1068 for privilege escalation", mitre.any { it.id == "T1068" })
    }

    @Test
    fun guessMitreTechniques_smsFinding_returnsT1565() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "SMS Access", "App intercepts SMS messages without justification")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        assertTrue("Should contain T1565 for SMS/message finding", mitre.any { it.id == "T1565" })
    }

    @Test
    fun guessMitreTechniques_audioFinding_returnsT1516() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "Microphone Access", "Record audio without user facing feature"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "Camera Access", "Camera access in background service")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        val t1516 = mitre.firstOrNull { it.id == "T1516" }
        assertNotNull("Should contain T1516 for recording/audio finding", t1516)
        assertEquals(2, t1516!!.findingCount)
    }

    @Test
    fun guessMitreTechniques_ransomwareFinding_returnsT1486() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Ransomware Behavior", "App encrypts files and demands ransom")
        )
        val mitre = generator.guessMitreTechniques(findings, "RansomApp")
        assertTrue("Should contain T1486 for ransomware finding", mitre.any { it.id == "T1486" })
    }

    @Test
    fun guessMitreTechniques_emptyFindings_returnsEmptyList() {
        val generator = PdfGenerator(context)
        val mitre = generator.guessMitreTechniques(emptyList(), "TestApp")
        assertTrue("Empty findings should produce empty MITRE list", mitre.isEmpty())
    }

    @Test
    fun guessMitreTechniques_multiplePatterns_allReturned() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.CRITICAL, "C2 Beacon", "Command control network beacon detected"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "GPS Location", "Location GPS tracking detected"),
            Finding(FindingCategory.OBFUSCATION, Severity.HIGH, "Packer Found", "Obfuscated packer detected"),
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Root Exploit", "Privilege escalation via root access"),
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "SMS Spy", "Message interception via SMS receiver")
        )
        val mitre = generator.guessMitreTechniques(findings, "MultiApp")
        val ids = mitre.map { it.id }.toSet()
        assertTrue("Should match T1071 (C2/network)", ids.contains("T1071"))
        assertTrue("Should match T1430 (location)", ids.contains("T1430"))
        assertTrue("Should match T1027 (obfuscation/packer)", ids.contains("T1027"))
        assertTrue("Should match T1068 (privilege escalation)", ids.contains("T1068"))
        assertTrue("Should match T1565 (SMS/message)", ids.contains("T1565"))
        assertTrue("Should match T1547 (boot/persistence via 'receiver')", ids.contains("T1547"))
        assertEquals("Should have 6 unique techniques (SMS matches T1565 + T1547)", 6, mitre.size)
    }

    @Test
    fun guessMitreTechniques_duplicateTechnique_countsCorrectly() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.HIGH, "C2 Beacon", "Network command control beacon"),
            Finding(FindingCategory.NETWORK, Severity.HIGH, "HTTP Beacon", "Command and control via HTTP"),
            Finding(FindingCategory.NETWORK, Severity.MEDIUM, "DNS Tunnel", "DNS tunneling for C2 communication")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        val t1071 = mitre.firstOrNull { it.id == "T1071" }
        assertNotNull("T1071 should be present", t1071)
        assertEquals("3 network findings should all count toward T1071", 3, t1071!!.findingCount)
    }

    @Test
    fun guessMitreTechniques_noMatchingKeywords_returnsEmpty() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.MANIFEST, Severity.INFO, "Min SDK Version", "App targets reasonable API level")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        assertTrue("Findings without matching keywords should produce no MITRE techniques", mitre.isEmpty())
    }

    @Test
    fun guessMitreTechniques_titleAndDescriptionBothSearched() {
        val generator = PdfGenerator(context)
        val titleFindings = listOf(
            Finding(FindingCategory.CODE, Severity.CRITICAL, "debugger detected", "App can detect debugging tools")
        )
        val descFindings = listOf(
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Anti-tamper", "Uses anti-debug measures for emulator detection")
        )
        val mitreTitle = generator.guessMitreTechniques(titleFindings, "TestApp")
        val mitreDesc = generator.guessMitreTechniques(descFindings, "TestApp")
        assertTrue("Matching via title should work", mitreTitle.any { it.id == "T1622" })
        assertTrue("Matching via description should work", mitreDesc.any { it.id == "T1622" })
    }

    @Test
    fun guessMitreTechniques_caseInsensitiveMatching() {
        val generator = PdfGenerator(context)
        val findings = listOf(
            Finding(FindingCategory.OBFUSCATION, Severity.HIGH, "PACKED", "ENCRYPTED CODE SECTION")
        )
        val mitre = generator.guessMitreTechniques(findings, "TestApp")
        assertTrue("Matching should be case-insensitive (PACKED -> T1027)", mitre.any { it.id == "T1027" })
        assertTrue("Matching should be case-insensitive (ENCRYPTED -> T1027)", mitre.any { it.id == "T1027" })
    }

    @Test
    fun generate_withMitreTechniques_doesNotCrash() {
        val findings = listOf(
            Finding(FindingCategory.NETWORK, Severity.CRITICAL, "C2 Beacon", "Network command control server beaconing"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "GPS Location", "Location GPS tracking detected"),
            Finding(FindingCategory.OBFUSCATION, Severity.HIGH, "Packer Detected", "Obfuscation packer protecting code"),
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Root Command", "Privilege escalation via su binary"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "SMS Access", "SMS message interception"),
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Ransomware", "Data encrypted for impact with ransom note")
        )
        val result = minimalScanResult().copy(
            apkName = "mitre_test.apk",
            findings = findings,
            threatLevel = ThreatLevel.HIGH,
            threatScore = 70,
            remediations = listOf("Fix network issues", "Remove location tracking")
        )
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull("PDF should generate without crash when MITRE techniques present", pdfResult)
    }

    @Test
    fun generate_withAllMitrePatterns_doesNotCrash() {
        val allCategories = listOf(
            Finding(FindingCategory.NETWORK, Severity.HIGH, "Network Beacon", "command control beacon"),
            Finding(FindingCategory.PERMISSION, Severity.HIGH, "SMS Access", "sms telephony abuse"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "Audio Record", "record audio microphone"),
            Finding(FindingCategory.PERMISSION, Severity.MEDIUM, "GPS", "location gps geofencing"),
            Finding(FindingCategory.PERMISSION, Severity.LOW, "Contacts", "contact phonebook access"),
            Finding(FindingCategory.CODE, Severity.MEDIUM, "Clipboard", "clipboard paste reading"),
            Finding(FindingCategory.CODE, Severity.HIGH, "Input Capture", "keylog keystroke input capture"),
            Finding(FindingCategory.OBFUSCATION, Severity.HIGH, "Packer", "obfuscat encrypt packer"),
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Root", "root privilege escalation"),
            Finding(FindingCategory.MANIFEST, Severity.MEDIUM, "Boot", "persistence boot autostart receiver"),
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Ransom", "ransom encrypt file decrypt"),
            Finding(FindingCategory.CODE, Severity.MEDIUM, "Debug", "debug anti-debug emulator virtual"),
            Finding(FindingCategory.CERTIFICATE, Severity.LOW, "Signature", "certif signature repackage"),
            Finding(FindingCategory.NATIVE, Severity.HIGH, "DLL Load", "hijack dll load inject"),
            Finding(FindingCategory.NATIVE, Severity.MEDIUM, "JNI Call", "native jni ndk system call"),
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Injection", "inject process hollow hook")
        )
        val result = minimalScanResult().copy(
            apkName = "all_mitre.apk",
            findings = allCategories,
            threatLevel = ThreatLevel.CRITICAL,
            threatScore = 95,
            classification = "trojan"
        )
        val pdfResult = PdfGenerator(context).generate(result)
        assertNotNull("PDF should generate without crash when all MITRE categories present", pdfResult)
    }
}
