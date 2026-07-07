package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class NetworkBehaviorProfiler {

    fun analyze(allSource: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        val lower = allSource.lowercase()

        var riskScore = 0
        val indicators = mutableListOf<String>()

        if (lower.contains("socks5") || lower.contains("socks4") || lower.contains("proxyhost")) {
            riskScore += 3
            indicators.add("SOCKS proxy — possible C2 relay")
        }
        if (Regex("""Socket\(\s*\)""").containsMatchIn(lower) ||
            lower.contains("raw socket") || lower.contains("af_inet") && lower.contains("sock_raw")) {
            riskScore += 2
            indicators.add("Raw socket — custom protocol / VPN bypass")
        }
        val nonStandardPorts = Regex("""\b(666[0-9]|1337|4444|5555|8080|8888|9999|31337)\b""")
            .findAll(lower).map { it.value }.toSet()
        if (nonStandardPorts.isNotEmpty()) {
            riskScore += 2
            indicators.add("Non-standard ports: ${nonStandardPorts.joinToString()}")
        }
        if (lower.contains("doh:") || lower.contains("cloudflare-dns") ||
            lower.contains("dns.google") || lower.contains("dns-over-https")) {
            riskScore += 2
            indicators.add("DNS-over-HTTPS — bypasses corporate DNS filtering")
        }
        if (Regex("""User-Agent["']?:\s*["']?\s*(null|Mozilla/4|curl|Python|okhttp/)""",
                RegexOption.IGNORE_CASE).containsMatchIn(lower)) {
            riskScore += 1
            indicators.add("Suspicious or spoofed User-Agent")
        }
        if (lower.contains("torproject") || lower.contains("onion") ||
            lower.contains("127.0.0.1:9050") || lower.contains("127.0.0.1:9150")) {
            riskScore += 3
            indicators.add("Tor network — anonymized C2")
        }
        if (lower.contains("pastebin") || lower.contains("paste.ee") ||
            lower.contains("ghostbin") || lower.contains("0bin")) {
            riskScore += 2
            indicators.add("Pastebin — C2 dead-drop")
        }
        if (lower.contains("dyndns") || lower.contains("no-ip") ||
            lower.contains("duckdns") || lower.contains("ngrok")) {
            riskScore += 3
            indicators.add("Dynamic DNS — disposable C2 infrastructure")
        }
        if (Regex("""\.onion|\.i2p|\.bit""").containsMatchIn(lower)) {
            riskScore += 3
            indicators.add("Darknet TLD — anonymous hosting")
        }

        val severity = when {
            riskScore >= 6 -> Severity.CRITICAL
            riskScore >= 4 -> Severity.HIGH
            riskScore >= 2 -> Severity.MEDIUM
            else -> Severity.LOW
        }

        if (riskScore > 0) {
            findings.add(Finding(
                category = FindingCategory.NETWORK,
                severity = severity,
                title = "Suspicious Network Behavior Profile",
                description = "Score $riskScore/15 — ${indicators.joinToString("; ")}"
            ))
        }

        return findings
    }
}
