package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import kotlin.math.ln

class SecretLeakScanner {

    data class SecretMatch(
        val type: String,
        val value: String,
        val severity: Severity,
        val offset: Int,
        val context: String
    )

    // High-entropy secret patterns — tuned for common developer credential formats
    private val secretPatterns = listOf(
        // Google API keys (AIza + 35 chars)
        Regex("""AIza[0-9A-Za-z\-_]{35}""") to "Google API Key",
        // Google OAuth client ID
        Regex("""[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com""") to "Google OAuth Client ID",
        // Firebase URLs with database credentials
        Regex("""https?://[a-z0-9-]+\.firebaseio\.com""") to "Firebase Database URL",
        Regex("""https?://[a-z0-9-]+\.firebaseapp\.com""") to "Firebase App URL",

        // AWS keys
        Regex("""AKIA[0-9A-Z]{16}""") to "AWS Access Key ID",
        Regex("""aws\.secret_access_key["']?\s*[:=]\s*["']([A-Za-z0-9/+]{40})""") to "AWS Secret Key Pattern",

        // Private keys in PEM format
        Regex("""-----BEGIN (RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----""") to "Private Key (PEM)",
        Regex("""-----BEGIN CERTIFICATE-----""") to "Embedded Certificate",

        // Generic API key patterns (common key formats)
        Regex("""(?i)api[_-]?key["']?\s*[:=]\s*["'][A-Za-z0-9\-_]{20,64}["']""") to "Hardcoded API Key",
        Regex("""(?i)api[_-]?secret["']?\s*[:=]\s*["'][A-Za-z0-9\-_]{20,64}["']""") to "Hardcoded API Secret",
        Regex("""(?i)access[_-]?token["']?\s*[:=]\s*["'][A-Za-z0-9\-_]{20,128}["']""") to "Hardcoded Access Token",

        // Stripe keys
        Regex("""(sk|pk)_live_[0-9A-Za-z]{24,99}""") to "Stripe API Key",
        Regex("""(sk|pk)_test_[0-9A-Za-z]{24,99}""") to "Stripe Test Key",

        // Slack tokens
        Regex("""xox[baprs]-[0-9A-Za-z\-]{10,80}""") to "Slack Bot Token",

        // GitHub tokens
        Regex("""ghp_[0-9A-Za-z]{36}""") to "GitHub Personal Access Token",
        Regex("""github_pat_[0-9A-Za-z_]{22,82}""") to "GitHub Fine-grained Token",

        // JWT tokens
        Regex("""eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+""") to "JWT Token",

        // Database connection strings
        Regex("""(?i)(jdbc|mongodb|mysql|postgresql|redis)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+""") to "Database Connection String",

        // URL with embedded credentials
        Regex("""https?://[^:]+:[^@]+@[^\s\"']+""") to "URL with Embedded Credentials",

        // SHA256 private key/password hash pattern in code
        Regex("""(?i)(password|passwd|pwd|secret|token|credential)["']?\s*[:=]\s*["']([A-Za-z0-9@#$%^&*\-_+=!]{8,64})["']""") to "Hardcoded Password",

        // Cryptocurrency private keys
        Regex("""[5KL][1-9A-HJ-NP-Za-km-z]{50,51}""") to "Bitcoin Private Key (WIF)",
        Regex("""0x[0-9A-Fa-f]{64}""") to "Ethereum Private Key (Hex)",

        // Slack webhook URLs
        Regex("""https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+""") to "Slack Webhook URL",

        // Telegram bot tokens
        Regex("""[0-9]+:[A-Za-z0-9\-_]{35}""") to "Telegram Bot Token",
    )

    // Shannon entropy tracker for anomalous strings
    data class EntropyMatch(val value: String, val entropy: Double, val length: Int)

    fun scan(extractedStrings: List<String>, javaSource: Map<String, String>): Pair<List<Finding>, List<SecretMatch>> {
        val allText = javaSource.values.joinToString("\n") + "\n" + extractedStrings.joinToString("\n")
        return scanText(allText)
    }

    fun scanFromText(allSourceText: String): Pair<List<Finding>, List<SecretMatch>> {
        return scanText(allSourceText)
    }

    fun scan(javaSource: Map<String, String>, smaliSource: Map<String, String>): Pair<List<Finding>, List<SecretMatch>> {
        val allText = javaSource.values.joinToString("\n") + "\n" + smaliSource.values.joinToString("\n")
        return scanText(allText)
    }

    private fun scanText(allText: String): Pair<List<Finding>, List<SecretMatch>> {
        val findings = mutableListOf<Finding>()
        val allMatches = mutableListOf<SecretMatch>()

        for ((regex, secretType) in secretPatterns) {
            val matches = regex.findAll(allText)
            var matchCount = 0
            for (match in matches) {
                if (matchCount++ > 50) break // per-pattern cap
                val masked = maskValue(match.value, secretType)
                allMatches.add(SecretMatch(secretType, masked, classifySeverity(secretType), match.range.first, ""))

                findings.add(Finding(
                    category = FindingCategory.STRING,
                    severity = classifySeverity(secretType),
                    title = "Leaked Secret: $secretType",
                    description = "Found $masked in compiled code or assets. Leaked credentials enable lateral movement and privilege escalation."
                ))
            }
        }

        // High-entropy string scan — catch anything the regex patterns miss
        val highEntropy = findHighEntropyStrings(allText)
        for (em in highEntropy) {
            val alreadyCaught = allMatches.any { em.value.contains(it.value.take(12)) || it.value.contains(em.value.take(12)) }
            if (!alreadyCaught) {
                findings.add(Finding(category = FindingCategory.STRING, severity = Severity.MEDIUM,
                    title = "High-Entropy String Detected",
                    description = "Found ${em.length}-char string with entropy ${"%.2f".format(em.entropy)}. Possible unrecognized credential format."))
            }
        }

        return findings to allMatches
    }

    private fun findHighEntropyStrings(text: String): List<EntropyMatch> {
        val results = mutableListOf<EntropyMatch>()
        // Find contiguous base64-like strings: runs of 40+ chars with alphanumeric+symbols
        val base64Run = Regex("""[A-Za-z0-9+/=_-]{40,80}""")
        for (match in base64Run.findAll(text)) {
            val s = match.value
            if (s.length >= 40) {
                val e = shannonEntropy(s)
                if (e > 4.2) { // High entropy threshold for base64 strings
                    results.add(EntropyMatch(s.take(64), e, s.length))
                }
            }
        }
        return results.take(20)
    }

    private fun shannonEntropy(s: String): Double {
        val freq = IntArray(256)
        for (c in s) freq[c.code and 0xFF]++
        var entropy = 0.0
        val len = s.length.toDouble()
        for (count in freq) {
            if (count == 0) continue
            val p = count / len
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy
    }

    private fun classifySeverity(type: String): Severity = when {
        type.contains("Private Key") || type.contains("PEM") -> Severity.CRITICAL
        type.contains("Access Token") || type.contains("Secret") || type.contains("Password") -> Severity.HIGH
        type.contains("Stripe") || type.contains("Bitcoin") || type.contains("Ethereum") -> Severity.CRITICAL
        type.contains("Connection String") || type.contains("Credential") -> Severity.HIGH
        type.contains("GitHub") || type.contains("Slack") || type.contains("Telegram") -> Severity.MEDIUM
        type.contains("JWT") -> Severity.MEDIUM
        else -> Severity.MEDIUM
    }

    private fun maskValue(value: String, type: String): String = when {
        value.length <= 8 -> "***"
        type.contains("URL") -> value.take(30) + "..."
        value.contains("@") -> value.replace(Regex("://[^@]+@"), "://***@")
        else -> value.take(6) + "..." + value.takeLast(4)
    }
}
