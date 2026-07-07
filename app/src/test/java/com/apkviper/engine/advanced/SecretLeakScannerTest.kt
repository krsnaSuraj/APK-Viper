package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class SecretLeakScannerTest {
    private val scanner = SecretLeakScanner()

    @Test
    fun emptyInput_noFindings() {
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to ""))
        assertTrue(findings.isEmpty())
        assertTrue(matches.isEmpty())
    }

    @Test
    fun googleApiKey_detected() {
        val key = "AIzaSyD" + "FAKEKEY0123456789abcdefABCDEF_12345"
        val code = "const API_KEY = \"$key\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Google API Key") })
    }

    @Test
    fun googleOAuthClientId_detected() {
        val clientId = "999999999-" + "f".repeat(32) + ".apps.googleusercontent.com"
        val code = "client_id = \"$clientId\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Google OAuth") })
    }

    @Test
    fun awsKey_detected() {
        val key = "AKIA" + "F".repeat(16)
        val code = "val key = \"$key\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("AWS Access Key") })
    }

    @Test
    fun privateKeyPem_detected() {
        val code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Private Key") })
    }

    @Test
    fun hardcodedApiKey_detected() {
        val code = "api_key = \"abcdefghijklmnopqrstuvwxyz0123456\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Hardcoded API Key") })
    }

    @Test
    fun stripeLiveKey_detected() {
        val key = "sk_live_" + "F".repeat(24)
        val code = "stripe_key = \"$key\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Stripe API Key") })
    }

    @Test
    fun jwtToken_detected() {
        val code = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP"
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("JWT Token") })
    }

    @Test
    fun githubToken_detected() {
        val token = "ghp_" + "F".repeat(36)
        val code = "token = \"$token\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("GitHub Personal Access Token") })
    }

    @Test
    fun slackWebhook_detected() {
        val url = "https://hooks.slack.com/services/T" + "0".repeat(8) + "/B" + "0".repeat(8) + "/" + "x".repeat(24)
        val code = "webhook = \"$url\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Slack Webhook") })
    }

    @Test
    fun telegramBotToken_detected() {
        val code = "1234567890:ABCdefGHIjklmNOPqrstUVwxyz-abcdefgh"
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Telegram Bot Token") })
    }

    @Test
    fun firebaseUrl_detected() {
        val code = "https://myproject.firebaseio.com/"
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Firebase") })
    }

    @Test
    fun highEntropyString_detected() {
        val text = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
        val (findings, matches) = scanner.scan(listOf(text), mapOf())
        val highEnt = findings.find { it.title.contains("High-Entropy String") }
        assertNotNull(highEnt)
        assertEquals(Severity.MEDIUM, highEnt!!.severity)
    }

    @Test
    fun bitcoinPrivateKeyWIF_detected() {
        val code = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Bitcoin") || it.title.contains("Private Key") })
    }

    @Test
    fun hardcodedPassword_detected() {
        val code = "password = \"SuperSecret123!@#\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Hardcoded Password") })
    }

    @Test
    fun emptyJavaSource_usesExtractedStrings() {
        val fake = "AIzaSyD" + "FAKE0123456789abcdefABCDEF_99999"
        val (findings, matches) = scanner.scan(listOf(fake), mapOf())
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun slackBotToken_detected() {
        val token = "xoxb-" + "X".repeat(30)
        val code = "token = \"$token\""
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Slack Bot Token") })
    }

    @Test
    fun dbConnectionString_detected() {
        val code = "jdbc:mysql://user:pass@localhost:3306/db"
        val (findings, matches) = scanner.scan(emptyList(), mapOf("A.java" to code))
        assertTrue(findings.any { it.title.contains("Connection String") })
    }
}
