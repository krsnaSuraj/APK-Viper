package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class BehavioralDetectorTest {
    private val detector = BehavioralDetector()

    @Test
    fun cleanCode_noBehavioralFindings() {
        val result = DecompileResult(
            javaSource = mapOf("Main.java" to "class Main { void run() { } }"),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).isEmpty())
    }

    @Test
    fun smsExfiltration_belowMinMatches_noTrigger() {
        val code = "sendTextMessage only"
        val result = DecompileResult(
            javaSource = mapOf("SMS.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "SMS Exfiltration" })
    }

    @Test
    fun smsExfiltration_meetsMinMatches_triggers() {
        val code = "sendTextMessage\ngetMessageBody\nSmsManager s;"
        val result = DecompileResult(
            javaSource = mapOf("SMS.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "SMS Exfiltration" })
        assertEquals(Severity.CRITICAL, findings.first { it.title == "SMS Exfiltration" }.severity)
    }

    @Test
    fun contactTheft_detected() {
        val code = "ContactsContract\nContentResolver.query\nREAD_CONTACTS"
        val result = DecompileResult(
            javaSource = mapOf("Contacts.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Contact Theft" })
    }

    @Test
    fun overlayAndAccessibilityChain_detected() {
        val code = """
            TYPE_APPLICATION_OVERLAY
            SYSTEM_ALERT_WINDOW
            AccessibilityService
            onAccessibilityEvent
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Overlay.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Overlay + Accessibility Chain" })
    }

    @Test
    fun bankingOverlayAttack_detected() {
        val code = """
            TYPE_APPLICATION_OVERLAY
            AccessibilityService
            WebView.loadUrl
            addJavascriptInterface
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Bank.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Banking Overlay Attack" })
    }

    @Test
    fun dropperBehavior_detected() {
        val code = "DexClassLoader loader\nPathClassLoader path"
        val result = DecompileResult(
            javaSource = mapOf("Dropper.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Dropper Behavior" })
    }

    @Test
    fun dropperBehavior_insufficientMatch() {
        val code = "DexClassLoader loader"
        val result = DecompileResult(
            javaSource = mapOf("Dropper.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "Dropper Behavior" })
    }

    @Test
    fun rootExploitAttempt_detected() {
        val code = "Runtime.getRuntime().exec(\"su -c id\")"
        val result = DecompileResult(
            javaSource = mapOf("Exploit.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Root Exploit Attempt" })
        assertEquals(Severity.CRITICAL, findings.first { it.title == "Root Exploit Attempt" }.severity)
    }

    @Test
    fun antiAnalysis_detected() {
        val code = "isDebuggerConnected\nfrida hook"
        val result = DecompileResult(
            javaSource = mapOf("Anti.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Anti-Analysis Suite" })
    }

    @Test
    fun emulatorEvasion_detected() {
        val code = "generic\ngoldfish"
        val result = DecompileResult(
            javaSource = mapOf("Evasion.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Emulator Evasion" })
    }

    @Test
    fun dataExfiltrationChain_all4Signals_triggers() {
        val code = """
            getDeviceId
            HttpURLConnection conn
            XOR obfuscation
            writeBytes output
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Exfil.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "Confirmed Data Exfiltration Chain" })
        assertEquals(Severity.CRITICAL, findings.first { it.title == "Confirmed Data Exfiltration Chain" }.severity)
    }

    @Test
    fun dataExfiltrationChain_missingOne_noTrigger() {
        val code = """
            getDeviceId
            HttpURLConnection conn
            XOR obfuscation
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Exfil.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title == "Confirmed Data Exfiltration Chain" })
    }

    @Test
    fun sequenceMatch_allInOrder_detected() {
        val code = """
            AccountManager am = getSystemService();
            am.getAuthToken(account, type, null, this, null, null);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Sequence.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title.contains("Auth Token") })
    }

    @Test
    fun sequenceMatch_wrongOrder_noMatch() {
        val code = """
            HttpURLConnection conn;
            AccountManager am;
            am.getAuthToken();
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Sequence.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title.contains("Auth Token") })
    }

    @Test
    fun sequenceMatch_partialSequence_noMatch() {
        val code = """
            AccountManager am = getSystemService();
        """.trimIndent()
        val result = DecompileResult(
            javaSource = mapOf("Sequence.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        assertTrue(detector.analyze(result).none { it.title.contains("Auth Token") })
    }

    @Test
    fun manifestAlsoSearched() {
        val code = "sendTextMessage\nSmsManager"
        val manifest = "READ_CONTACTS ContactsContract ContentResolver.query"
        val result = DecompileResult(
            javaSource = mapOf("SMS.java" to code),
            smaliSource = emptyMap(), manifest = manifest, resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        assertTrue(findings.any { it.title == "SMS Exfiltration" })
        assertTrue(findings.any { it.title == "Contact Theft" })
    }

    @Test
    fun confidencePercentage_inFindingDetails() {
        val code = "sendTextMessage\ngetMessageBody\nSmsManager"
        val result = DecompileResult(
            javaSource = mapOf("SMS.java" to code),
            smaliSource = emptyMap(), manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val findings = detector.analyze(result)
        val smsFinding = findings.first { it.title == "SMS Exfiltration" }
        assertTrue(smsFinding.details?.contains("Confidence:") == true)
        assertTrue(smsFinding.details?.contains("100%") == true)
    }
}
