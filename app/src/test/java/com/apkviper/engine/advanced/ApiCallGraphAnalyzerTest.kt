package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class ApiCallGraphAnalyzerTest {
    private val analyzer = ApiCallGraphAnalyzer()

    private fun decompile(javaSource: Map<String, String> = mapOf("A.java" to "")): DecompileResult =
        DecompileResult(javaSource, mapOf(), "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun emptyCode_noFindings() {
        assertTrue(analyzer.analyze(decompile()).isEmpty())
    }

    @Test
    fun singleApi_noFindings() {
        val code = "getDeviceId() used somewhere"
        assertTrue(analyzer.analyze(decompile(mapOf("A.java" to code))).isEmpty())
    }

    @Test
    fun twoApisFromChain_noFindings() {
        val code = "getDeviceId and HttpURLConnection but not enough"
        assertTrue(analyzer.analyze(decompile(mapOf("A.java" to code))).isEmpty())
    }

    @Test
    fun deviceIdExfiltrationPipeline_detected() {
        val code = "getDeviceId() getSubscriberId() HttpURLConnection getOutputStream()"
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Device ID Exfiltration") })
    }

    @Test
    fun contactListExfiltration_detected() {
        val code = "ContactsContract ContentResolver.query HttpURLConnection getOutputStream"
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Contact List Exfiltration") })
    }

    @Test
    fun locationTrackingPipeline_detected() {
        val code = "getLastKnownLocation requestLocationUpdates HttpURLConnection getOutputStream"
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Location Tracking") })
    }

    @Test
    fun smsInterception_detected() {
        val code = "SmsManager sendTextMessage getMessageBody BROADCAST_SMS"
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("SMS Interception") })
    }

    @Test
    fun sequenceConfirmed_bumpedSeverity() {
        val code = """getDeviceId() {
            getSubscriberId()
            HttpURLConnection
            getOutputStream()
        }""".trimIndent()
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.any { it.title.contains("SEQUENCE CONFIRMED") })
        val seqFinding = findings.first { it.title.contains("SEQUENCE CONFIRMED") }
        assertEquals(Severity.CRITICAL, seqFinding.severity)
    }

    @Test
    fun droppedPipeline_detected() {
        val code = "DexClassLoader openFileOutput writeBytes installPackage"
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Dropper") })
    }

    @Test
    fun authTokenTheft_detected() {
        val code = "AccountManager getAuthToken HttpURLConnection getOutputStream"
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Auth Token") })
    }

    @Test
    fun rootPrivilegeEscalation_detected() {
        val code = "getRuntime.exec su Runtime.exec mount remount"
        val findings = analyzer.analyze(decompile(mapOf("A.java" to code)))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Root Privilege") })
    }

    @Test
    fun crossClassDetection() {
        val findings = analyzer.analyze(decompile(mapOf(
            "A.java" to "getDeviceId getSubscriberId HttpURLConnection",
            "B.java" to "getOutputStream write"
        )))
        assertTrue(findings.any { it.title.contains("Device ID Exfiltration") })
    }
}
