package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

/**
 * Local Threat Intelligence Scoring — embedded database of known
 * malicious IPs, domains, and C2 infrastructure. No API calls needed.
 * Updated with community threat feeds.
 */
object ThreatIntelDB {

    // Known malicious IPs — confirmed C2 infrastructure (can be updated from remote)
    private val knownMaliciousIps = mutableSetOf(
        "13.9.205.16", "185.244.25.187", "45.155.205.233",
        "45.142.212.61", "185.215.113.12", "193.56.146.54",
        "45.147.231.210", "185.220.101.34",
        "45.76.80.199", "149.28.37.231",
        "45.133.1.47", "185.220.100.241",
        "45.147.230.100", "45.144.225.112",
        "45.76.166.199",
    )

    // Known malicious domains (can be updated from remote)
    private val knownMaliciousDomains = mutableListOf(
        "pastebin.com/raw/",
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "api.telegram.org/bot",
        ".duckdns.org", ".ddns.net", ".hopto.org",
        ".myftp.org", ".no-ip.org", ".servehttp.com",
        ".ml", ".ga", ".cf", ".gq", ".tk",
    )

    @Synchronized
    fun updateIps(ips: List<String>) { knownMaliciousIps.addAll(ips) }

    @Synchronized
    fun updateDomains(domains: List<String>) { knownMaliciousDomains.addAll(domains) }

    @Synchronized
    fun getIpCount(): Int = knownMaliciousIps.size

    @Synchronized
    fun getDomainCount(): Int = knownMaliciousDomains.size

    // Suspicious ASN ranges (bulletproof hosting)
    private val suspiciousAsnRanges = listOf(
        Regex("""^45\.\d{1,3}\.\d{1,3}\.\d{1,3}"""),
        Regex("""^185\.\d{1,3}\.\d{1,3}\.\d{1,3}"""),
        Regex("""^193\.\d{1,3}\.\d{1,3}\.\d{1,3}"""),
        Regex("""^194\.\d{1,3}\.\d{1,3}\.\d{1,3}"""),
    )

    enum class MatchLevel { EXACT, SUSPICIOUS_ASN, CLEAN }

    data class IntelMatch(val indicator: String, val level: MatchLevel, val description: String)

    @Synchronized
    fun checkIp(ip: String): IntelMatch {
        // Exact match against known C2 IPs
        if (ip in knownMaliciousIps) {
            return IntelMatch(ip, MatchLevel.EXACT, "Known C2 infrastructure — confirmed malware command server")
        }
        // ASN range check
        for (range in suspiciousAsnRanges) {
            if (range.matches(ip)) {
                return IntelMatch(ip, MatchLevel.SUSPICIOUS_ASN, "IP in known bulletproof hosting range — frequently used for C2")
            }
        }
        return IntelMatch(ip, MatchLevel.CLEAN, "")
    }

    @Synchronized
    fun checkDomain(domain: String): IntelMatch {
        for (knownDomain in knownMaliciousDomains) {
            if (domain.contains(knownDomain, ignoreCase = true)) {
                return when (knownDomain) {
                    "pastebin.com/raw/" -> IntelMatch(domain, MatchLevel.EXACT, "Pastebin raw endpoint — commonly used for C2 config hosting")
                    "discord.com/api/webhooks", "discordapp.com/api/webhooks" -> IntelMatch(domain, MatchLevel.EXACT, "Discord webhook — data exfiltration to Discord server")
                    "api.telegram.org/bot" -> IntelMatch(domain, MatchLevel.EXACT, "Telegram bot API — C2 via Telegram")
                    else -> IntelMatch(domain, MatchLevel.EXACT, "Known malicious domain or dynamic DNS — C2 infrastructure")
                }
            }
        }
        return IntelMatch(domain, MatchLevel.CLEAN, "")
    }

    fun scoreIndicators(indicators: List<IntelMatch>): ScoreResult {
        val exactMatches = indicators.filter { it.level == MatchLevel.EXACT }
        val suspiciousMatches = indicators.filter { it.level == MatchLevel.SUSPICIOUS_ASN }

        val score = when {
            exactMatches.isNotEmpty() -> 90
            suspiciousMatches.size >= 2 -> 70
            suspiciousMatches.size == 1 -> 40
            else -> 0
        }

        return ScoreResult(score, exactMatches + suspiciousMatches)
    }

    data class ScoreResult(val score: Int, val matches: List<IntelMatch>)

    fun generateFindings(indicators: List<IntelMatch>): List<Finding> {
        val findings = mutableListOf<Finding>()
        val exact = indicators.filter { it.level == MatchLevel.EXACT }

        if (exact.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.NETWORK,
                severity = Severity.CRITICAL,
                title = "C2 Infrastructure Match",
                description = "${exact.size} indicators match known malware command servers",
                details = exact.joinToString("\n") { "${it.indicator}: ${it.description}" }
            ))
        }

        val suspicious = indicators.filter { it.level == MatchLevel.SUSPICIOUS_ASN }
        if (suspicious.size >= 2) {
            findings.add(Finding(
                category = FindingCategory.NETWORK,
                severity = Severity.HIGH,
                title = "Suspicious Hosting Infrastructure",
                description = "${suspicious.size} indicators in bulletproof hosting ranges",
                details = suspicious.joinToString("\n") { "${it.indicator}: ${it.description}" }
            ))
        }

        return findings
    }
}
