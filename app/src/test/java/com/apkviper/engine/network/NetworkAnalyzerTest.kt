package com.apkviper.engine.network

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class NetworkAnalyzerTest {
    private val analyzer = NetworkAnalyzer()

    private fun decompileResult(
        javaSource: Map<String, String> = mapOf("A.java" to ""),
        smaliSource: Map<String, String> = mapOf()
    ): DecompileResult =
        DecompileResult(javaSource, smaliSource, "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun cleanCode_noFindings() {
        val result = decompileResult(mapOf("A.java" to "package com.example; class A {}"))
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun pastebinC2_detected() {
        val result = decompileResult(mapOf("A.java" to "https://pastebin.com/raw/abc123"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Pastebin") })
        assertEquals(Severity.CRITICAL, findings.find { it.title.contains("Pastebin") }!!.severity)
    }

    @Test
    fun ngrokC2_detected() {
        val result = decompileResult(mapOf("A.java" to "https://evil.ngrok.io/callback"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Ngrok") })
    }

    @Test
    fun serveo_detected() {
        val result = decompileResult(mapOf("A.java" to "https://tunnel.serveo.net/data"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Serveo") })
    }

    @Test
    fun localtunnel_detected() {
        val result = decompileResult(mapOf("A.java" to "localtunnel.me"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("LocalTunnel") })
    }

    @Test
    fun onionService_detected() {
        val result = decompileResult(mapOf("A.java" to "http://abc123.onion/"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Tor hidden") })
    }

    @Test
    fun dynamicDns_detected() {
        val result = decompileResult(mapOf("A.java" to "https://evil.dynu.com/"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Dynamic DNS") })
    }

    @Test
    fun noIp_detected() {
        val result = decompileResult(mapOf("A.java" to "http://evil.no-ip.com/"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("No-IP") })
    }

    @Test
    fun duckDns_detected() {
        val result = decompileResult(mapOf("A.java" to "evil.duckdns.org"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("DuckDNS") })
    }

    @Test
    fun discordWebhook_detected() {
        val result = decompileResult(mapOf("A.java" to "https://discord.com/api/webhooks/123456/abc"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Discord webhook") })
    }

    @Test
    fun telegramBot_detected() {
        val result = decompileResult(mapOf("A.java" to "https://telegram.org/bot123456:ABC/sendMessage"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Telegram bot") })
    }

    @Test
    fun sslPinningBypassTrustAllCerts_detected() {
        val result = decompileResult(mapOf("A.java" to "TrustAllCerts"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("SSL Pinning Bypass") })
        assertEquals(Severity.HIGH, findings.find { it.title.contains("SSL Pinning Bypass") }!!.severity)
    }

    @Test
    fun sslBypassAllowAllHostname_detected() {
        val result = decompileResult(mapOf("A.java" to "ALLOW_ALL_HOSTNAME"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("SSL Pinning Bypass") })
    }

    @Test
    fun sslBypassHostnameVerifierReturnTrue_detected() {
        val code = "HostnameVerifier\nreturn true"
        val result = decompileResult(mapOf("A.java" to code))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("SSL Pinning Bypass") })
    }

    @Test
    fun hostnameVerifierWithoutReturnTrue_notDetected() {
        val result = decompileResult(mapOf("A.java" to "HostnameVerifier"))
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title.contains("SSL Pinning Bypass") })
    }

    @Test
    fun suspiciousHttpEndpoint_detected() {
        val result = decompileResult(mapOf("A.java" to "http://pastebin.com/raw/abc"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Suspicious HTTP Endpoint") })
    }

    @Test
    fun normalHttp_notSuspicious() {
        val result = decompileResult(mapOf("A.java" to "http://example.com/data"))
        val findings = analyzer.analyze(result)
        assertFalse(findings.any { it.title.contains("Suspicious HTTP Endpoint") })
    }

    @Test
    fun multipleC2Patterns_allDetected() {
        val code = """
            https://pastebin.com/raw/abc
            https://evil.ngrok.io/callback
        """.trimIndent()
        val result = decompileResult(mapOf("A.java" to code))
        val findings = analyzer.analyze(result)
        val c2Findings = findings.filter { it.title.contains("C2 Server") }
        assertEquals(2, c2Findings.size)
    }

    @Test
    fun caseInsensitiveMatching() {
        val result = decompileResult(mapOf("A.java" to "PASTEBIN.COM/RAW/ABC"))
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Pastebin") })
    }

    @Test
    fun smaliSourceScanned() {
        val result = decompileResult(
            javaSource = mapOf("A.java" to "clean"),
            smaliSource = mapOf("A.smali" to "https://pastebin.com/raw/xyz")
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Pastebin") })
    }

    @Test
    fun findingsHaveCorrectCategory() {
        val result = decompileResult(mapOf("A.java" to "https://pastebin.com/raw/abc"))
        val findings = analyzer.analyze(result)
        findings.forEach { assertEquals(FindingCategory.NETWORK, it.category) }
    }

    @Test
    fun emptySources_noFindings() {
        assertTrue(analyzer.analyze(decompileResult(mapOf())).isEmpty())
        assertTrue(analyzer.analyze(decompileResult(mapOf("A.java" to ""))).isEmpty())
    }
}
