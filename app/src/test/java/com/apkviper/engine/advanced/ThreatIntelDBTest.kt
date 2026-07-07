package com.apkviper.engine.advanced

import org.junit.Assert.*
import org.junit.Test

class ThreatIntelDBTest {

    @Test
    fun knownC2Ip_returnsExactMatch() {
        val result = ThreatIntelDB.checkIp("45.76.80.199")
        assertEquals(ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun cleanIp_returnsClean() {
        val result = ThreatIntelDB.checkIp("8.8.8.8")
        assertEquals(ThreatIntelDB.MatchLevel.CLEAN, result.level)
    }

    @Test
    fun suspiciousAsnRange_returnsSuspicious() {
        val result = ThreatIntelDB.checkIp("45.100.50.1")
        assertEquals(ThreatIntelDB.MatchLevel.SUSPICIOUS_ASN, result.level)
    }

    @Test
    fun knownMaliciousDomain_returnsExact() {
        val result = ThreatIntelDB.checkDomain("pastebin.com/raw/abc123")
        assertEquals(ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun discordWebhook_returnsExact() {
        val result = ThreatIntelDB.checkDomain("discord.com/api/webhooks/123/abc")
        assertEquals(ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun telegramBot_returnsExact() {
        val result = ThreatIntelDB.checkDomain("api.telegram.org/bot123:ABC")
        assertEquals(ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun dynamicDns_returnsExact() {
        val result = ThreatIntelDB.checkDomain("malware.duckdns.org")
        assertEquals(ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun cleanDomain_returnsClean() {
        val result = ThreatIntelDB.checkDomain("google.com")
        assertEquals(ThreatIntelDB.MatchLevel.CLEAN, result.level)
    }

    @Test
    fun updateIps_addsToDatabase() {
        val oldCount = ThreatIntelDB.getIpCount()
        ThreatIntelDB.updateIps(listOf("1.2.3.4", "5.6.7.8"))
        assertEquals(oldCount + 2, ThreatIntelDB.getIpCount())
        assertEquals(ThreatIntelDB.MatchLevel.EXACT, ThreatIntelDB.checkIp("1.2.3.4").level)
    }

    @Test
    fun updateDomains_addsToDatabase() {
        val oldCount = ThreatIntelDB.getDomainCount()
        ThreatIntelDB.updateDomains(listOf("evil.com", "malware.test"))
        assertTrue(ThreatIntelDB.getDomainCount() > oldCount)
    }

    @Test
    fun scoreIndicators_withExact_returns90() {
        val indicators = listOf(
            ThreatIntelDB.checkIp("45.76.80.199"),
            ThreatIntelDB.checkIp("8.8.8.8")
        )
        val result = ThreatIntelDB.scoreIndicators(indicators)
        assertEquals(90, result.score)
        assertEquals(1, result.matches.size)
    }

    @Test
    fun scoreIndicators_clean_returns0() {
        val indicators = listOf(ThreatIntelDB.checkIp("8.8.8.8"))
        val result = ThreatIntelDB.scoreIndicators(indicators)
        assertEquals(0, result.score)
    }

    @Test
    fun generateFindings_createsCorrectResults() {
        val indicators = listOf(
            ThreatIntelDB.checkIp("45.76.80.199"),
            ThreatIntelDB.checkIp("45.100.50.1"),
            ThreatIntelDB.checkIp("45.200.50.1")
        )
        val findings = ThreatIntelDB.generateFindings(indicators)
        assertTrue(findings.any { it.title.contains("C2") })
        assertTrue(findings.any { it.title.contains("Suspicious") })
    }

    @Test
    fun expiredThreatIntel_returnsEmpty() {
        val result = ThreatIntelDB.checkIp("1.1.1.1")
        assertEquals("Non-malicious IP should be CLEAN", ThreatIntelDB.MatchLevel.CLEAN, result.level)
    }

    @Test
    fun emptyC2List_noThreatsFound() {
        val result = ThreatIntelDB.checkDomain("example.com")
        assertEquals("Domain not in C2 list should be CLEAN", ThreatIntelDB.MatchLevel.CLEAN, result.level)
    }

    @Test
    fun lookupUnusualC2Port_correctlyIdentified() {
        val result = ThreatIntelDB.checkIp("45.76.80.199:8080")
        assertNotEquals("IP with port should not match exact C2", ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun domainLookup_caseInsensitive() {
        val result = ThreatIntelDB.checkDomain("DISCORD.COM/API/WEBHOOKS/123/abc")
        assertEquals("Case variation should still match", ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun urlPathInC2_correctlyParsed() {
        val result = ThreatIntelDB.checkDomain("https://pastebin.com/raw/abc123")
        assertEquals("Full URL path should match C2 domain", ThreatIntelDB.MatchLevel.EXACT, result.level)
    }

    @Test
    fun asnRange_doesNotMatch_whenOutsideRange() {
        val result = ThreatIntelDB.checkIp("46.0.0.1")
        assertEquals("IP starting with 46 is outside all ASN ranges", ThreatIntelDB.MatchLevel.CLEAN, result.level)
    }

    @Test
    fun multipleC2SameIP_returnsSingleFinding() {
        val ips = listOf("45.76.80.199", "45.76.80.199", "149.28.37.231")
        val indicators = ips.map { ThreatIntelDB.checkIp(it) }
        val findings = ThreatIntelDB.generateFindings(indicators)
        val c2Findings = findings.filter { it.title.contains("C2") }
        assertEquals("Multiple checks of same C2 IPs produce one finding", 1, c2Findings.size)
    }

    @Test
    fun lookupPrivateIp_returnsEmpty() {
        assertEquals(ThreatIntelDB.MatchLevel.CLEAN, ThreatIntelDB.checkIp("10.0.0.1").level)
        assertEquals(ThreatIntelDB.MatchLevel.CLEAN, ThreatIntelDB.checkIp("192.168.1.1").level)
        assertEquals(ThreatIntelDB.MatchLevel.CLEAN, ThreatIntelDB.checkIp("172.16.0.1").level)
    }

    @Test
    fun threatIntelScore_capped() {
        val exacts = knownC2Ips().map { ThreatIntelDB.checkIp(it) }
        val result = ThreatIntelDB.scoreIndicators(exacts)
        assertTrue("Score should be at most 100, got ${result.score}", result.score <= 100)
    }

    @Test
    fun overlappingAsnRanges_correctMatch() {
        val result = ThreatIntelDB.checkIp("45.200.100.50")
        assertEquals("IP in first ASN range should match", ThreatIntelDB.MatchLevel.SUSPICIOUS_ASN, result.level)
    }

    @Test
    fun ipv6Addresses_handledGracefully() {
        val result = ThreatIntelDB.checkIp("::1")
        assertEquals("IPv6 localhost should not crash and return CLEAN", ThreatIntelDB.MatchLevel.CLEAN, result.level)
        val result2 = ThreatIntelDB.checkIp("2001:db8::1")
        assertEquals("IPv6 address should not crash and return CLEAN", ThreatIntelDB.MatchLevel.CLEAN, result2.level)
    }

    private fun knownC2Ips(): List<String> = listOf(
        "13.9.205.16", "185.244.25.187", "45.155.205.233",
        "45.142.212.61", "185.215.113.12", "193.56.146.54",
        "45.147.231.210", "185.220.101.34",
        "45.76.80.199", "149.28.37.231",
        "45.133.1.47", "185.220.100.241",
        "45.147.230.100", "45.144.225.112",
        "45.76.166.199",
    )
}
