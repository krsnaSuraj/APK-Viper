package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import org.junit.Assert.*
import org.junit.Test

class StringExtractorTest {
    private val extractor = StringExtractor()

    private fun decompileResult(javaSource: Map<String, String> = mapOf("A.java" to ""),
                                smaliSource: Map<String, String> = mapOf()): DecompileResult =
        DecompileResult(javaSource, smaliSource, "", mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun cleanCode_noStringFindings() {
        val result = decompileResult(mapOf("A.java" to "package com.example; class A {}"))
        assertTrue(extractor.analyze(result).isEmpty())
    }

    @Test
    fun externalUrl_detected() {
        val result = decompileResult(mapOf("A.java" to "https://evil.com/payload"))
        val findings = extractor.analyze(result)
        assertTrue(findings.any { it.title.contains("External URL") })
    }

    @Test
    fun googleSourceUrl_filteredAsNoise() {
        val result = decompileResult(mapOf("A.java" to "https://android.googlesource.com/toolchain/abc"))
        val findings = extractor.analyze(result)
        assertFalse(findings.any { it.title.contains("External URL") })
    }

    @Test
    fun privateIp_filtered() {
        val result = decompileResult(mapOf("A.java" to "192.168.1.1"))
        val findings = extractor.analyze(result)
        assertFalse(findings.any { it.title.contains("Hardcoded IP") })
    }

    @Test
    fun publicIp_detected() {
        val result = decompileResult(mapOf("A.java" to "8.8.8.8"))
        val findings = extractor.analyze(result)
        assertTrue(findings.any { it.title.contains("Hardcoded IP") })
    }

    @Test
    fun publicIp_deduped() {
        val code = "8.8.8.8\n8.8.8.8"
        val result = decompileResult(mapOf("A.java" to code))
        val findings = extractor.analyze(result)
        val ipFinding = findings.find { it.title.contains("Hardcoded IP") }
        assertNotNull(ipFinding)
        assertTrue(ipFinding!!.title.startsWith("1"))
    }

    @Test
    fun apiKeySecret_detected() {
        val fake = "sk_live_" + "abc123def456"
        val result = decompileResult(mapOf("A.java" to "api_key = \"$fake\""))
        val findings = extractor.analyze(result)
        assertTrue(findings.any { it.title.contains("Hardcoded Secret") })
    }

    @Test
    fun passwordSecret_detected() {
        val result = decompileResult(mapOf("A.java" to "password = \"supersecret!\""))
        val findings = extractor.analyze(result)
        assertTrue(findings.any { it.title.contains("Hardcoded Secret") })
    }

    @Test
    fun tokenSecret_detected() {
        val result = decompileResult(mapOf("A.java" to "auth_token = \"eyJhbGciOiJIUzI1NiJ9\""))
        val findings = extractor.analyze(result)
        assertTrue(findings.any { it.title.contains("Hardcoded Secret") })
    }

    @Test
    fun base64Blobs_detected() {
        val b64 = "VGhpcyBpcyBhIHZlcnkgbG9uZyBCYXNlNjQgc3RyaW5nIHRoYXQgc2hvdWxkIGJlIGRldGVjdGVkIGJ5IHRoZSBzdHJpbmcgZXh0cmFjdG9yIGJlY2F1c2UgaXQgZXhjZWVkcyA4MCBjaGFyYWN0ZXJz"
        val lines = (1..10).map { b64 }
        val result = decompileResult(mapOf("A.java" to lines.joinToString("\n")))
        val findings = extractor.analyze(result)
        assertTrue(findings.any { it.title.contains("Base64") })
    }

    @Test
    fun base64CountBelowThreshold_noFinding() {
        val b64 = "VGhpcyBpcyBhIHZlcnkgbG9uZyBCYXNlNjQgc3RyaW5nIHRoYXQgc2hvdWxkIGJlIGRldGVjdGVkIGJ5IHRoZSBzdHJpbmcgZXh0cmFjdG9yIGJlY2F1c2UgaXQgZXhjZWVkcyA4MCBjaGFyYWN0ZXJz"
        val result = decompileResult(mapOf("A.java" to b64))
        val findings = extractor.analyze(result)
        assertFalse(findings.any { it.title.contains("Base64") })
    }

    @Test
    fun urls_limitedTo5InDescription() {
        val urls = (1..10).map { "https://example$it.com/path" }
        val result = decompileResult(mapOf("A.java" to urls.joinToString("\n")))
        val findings = extractor.analyze(result)
        val urlFinding = findings.find { it.title.contains("External URL") }
        assertNotNull(urlFinding)
        val lines = urlFinding!!.description.split("\n")
        assertTrue(lines.size <= 5)
    }

    @Test
    fun ips_showEllipsisWhenMoreThan5() {
        val ips = (1..10).map { "$it.$it.$it.$it" }
        val result = decompileResult(mapOf("A.java" to ips.joinToString("\n")))
        val findings = extractor.analyze(result)
        val ipFinding = findings.find { it.title.contains("Hardcoded IP") }
        assertNotNull(ipFinding)
        assertTrue(ipFinding!!.details!!.contains("more"))
    }

    @Test
    fun smaliSource_scannedForStrings() {
        val result = decompileResult(
            javaSource = mapOf("A.java" to "package clean;"),
            smaliSource = mapOf("A.smali" to "https://evil.com/smali")
        )
        val findings = extractor.analyze(result)
        assertTrue(findings.any { it.title.contains("External URL") })
    }
}
