package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class NetworkBehaviorProfilerTest {
    private val profiler = NetworkBehaviorProfiler()

    @Test
    fun cleanCode_noFindings() {
        val code = "just a normal app with no networking indicators"
        assertTrue(profiler.analyze(code).isEmpty())
    }

    @Test
    fun socksProxy_detected() {
        val code = "socks5 proxy connection established"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun nonStandardPorts_detected() {
        val code = "connecting to 1337 and port 4444"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun doh_detected() {
        val code = "dns-over-https cloudflare-dns dns.google"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun userAgentSuspicious_detected() {
        val code = "User-Agent: curl/7.68.0"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun torNetwork_detected() {
        val code = "torproject onion 127.0.0.1:9050"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun pastebinC2_detected() {
        val code = "pastebin.com ghostbin paste.ee"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun dynamicDns_detected() {
        val code = "dyndns no-ip duckdns ngrok"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun darknetTld_detected() {
        val code = "something.onion hidden.i2p"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun rawSocketPattern_detected() {
        val code = "Socket() opened af_inet sock_raw"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun multipleIndicators_criticalSeverity() {
        val code = """
            socks5 proxy torch and torproject onion 127.0.0.1:9050
            dyndns no-ip duckdns pastebin
            nonStandardPort 1337 and 4444 and 6666
        """.trimIndent()
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.CRITICAL, findings[0].severity)
    }

    @Test
    fun singleIndicator_lowSeverity() {
        val code = "User-Agent: curl"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.LOW, findings[0].severity)
    }

    @Test
    fun twoIndicators_mediumSeverity() {
        val code = "pastebin User-Agent: curl"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.MEDIUM, findings[0].severity)
    }

    @Test
    fun threeIndicators_highSeverity() {
        val code = "pastebin User-Agent: null connecting to 1337"
        val findings = profiler.analyze(code)
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.HIGH, findings[0].severity)
    }
}
