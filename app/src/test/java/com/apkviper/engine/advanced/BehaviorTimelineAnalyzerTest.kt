package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class BehaviorTimelineAnalyzerTest {
    private val analyzer = BehaviorTimelineAnalyzer()

    private fun decompile(javaSource: Map<String, String> = mapOf("A.java" to ""),
                          manifest: String = ""): DecompileResult =
        DecompileResult(javaSource, mapOf(), manifest, mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun emptySource_noFindings() {
        assertTrue(analyzer.analyze(decompile()).isEmpty())
    }

    @Test
    fun bootPersistenceNetworkDataExfil_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
        """.trimIndent()
        val code = """
            httpurlconnection socket( url.openconnection okhttp
            fileoutputstream
        """.trimIndent()
        val findings = analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.any { it.title.contains("Boot Persistence") })
    }

    @Test
    fun smsInterceptionNetwork_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.RECEIVE_SMS"/>
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.SEND_SMS"/>
        """.trimIndent()
        val code = "httpurlconnection sendtextmessage smsreceiver"
        val findings = analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.any { it.title.contains("SMS Interception") })
        assertEquals(Severity.CRITICAL, findings.first { it.title.contains("SMS Interception") }.severity)
    }

    @Test
    fun cameraNetworkStorage_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.CAMERA"/>
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
        """.trimIndent()
        val code = "httpurlconnection fileoutputstream outputstream"
        val findings = analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.any { it.title.contains("Camera") })
    }

    @Test
    fun microphoneNetworkBoot_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.RECORD_AUDIO"/>
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
        """.trimIndent()
        val code = "httpurlconnection"
        val findings = analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.any { it.title.contains("Microphone") })
    }

    @Test
    fun locationNetworkForeground_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
        """.trimIndent()
        val code = "httpurlconnection startforeground"
        val findings = analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.any { it.title.contains("Location") })
    }

    @Test
    fun contactsNetworkSms_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.READ_CONTACTS"/>
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.SEND_SMS"/>
        """.trimIndent()
        val code = "httpurlconnection sendtextmessage"
        val findings = analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.any { it.title.contains("Contacts") })
        assertEquals(Severity.CRITICAL, findings.first { it.title.contains("Contacts") }.severity)
    }

    @Test
    fun overlayAccessibilityNetwork_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
            <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
            <uses-permission android:name="android.permission.INTERNET"/>
        """.trimIndent()
        val code = "httpurlconnection"
        val findings = analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.any { it.title.contains("Overlay") })
    }

    @Test
    fun partialChain_noFinding() {
        val manifest = """
            <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
            <uses-permission android:name="android.permission.INTERNET"/>
        """.trimIndent()
        assertTrue(analyzer.analyze(decompile(manifest = manifest)).isEmpty())
    }

    @Test
    fun apiMatchOnly_noFinding() {
        val manifest = ""
        val code = "httpurlconnection socket( url.openconnection"
        assertTrue(analyzer.analyze(decompile(javaSource = mapOf("A.java" to code), manifest = manifest)).isEmpty())
    }

    @Test
    fun manifestMatchOnly_noFinding() {
        val manifest = """
            <uses-permission android:name="android.permission.RECEIVE_SMS"/>
            <uses-permission android:name="android.permission.INTERNET"/>
        """.trimIndent()
        assertTrue(analyzer.analyze(decompile(manifest = manifest)).isEmpty())
    }
}
