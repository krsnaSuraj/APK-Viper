package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class PhishingOverlayAnalyzerTest {
    private val analyzer = PhishingOverlayAnalyzer()

    private fun decompile(javaSource: Map<String, String> = mapOf("A.java" to ""),
                          smaliSource: Map<String, String> = mapOf(),
                          manifest: String = ""): DecompileResult =
        DecompileResult(javaSource, smaliSource, manifest, mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun noOverlay_noAccessibility_noFindings() {
        val manifest = """<manifest package="com.test" />"""
        assertTrue(analyzer.analyze(decompile(manifest = manifest)).isEmpty())
    }

    @Test
    fun overlayWithoutBrands_noFindings() {
        val manifest = """
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
        """.trimIndent()
        val code = "just normal app code with no brand references"
        assertTrue(analyzer.analyze(decompile(
            javaSource = mapOf("A.java" to code),
            manifest = manifest
        )).isEmpty())
    }

    @Test
    fun overlayWithBrand_highSeverity() {
        val manifest = """
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
        """.trimIndent()
        val code = "google gmail accounts.google signin page"
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("A.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Phishing Overlay") })
        assertEquals(Severity.HIGH, findings[0].severity)
    }

    @Test
    fun overlayAndAccessibilityWithBrand_criticalSeverity() {
        val manifest = """
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
            <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
        """.trimIndent()
        val code = "paypal pay-pal login password credit card"
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("A.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.CRITICAL, findings[0].severity)
    }

    @Test
    fun accessibilityOnlyWithBrand_mediumSeverity() {
        val manifest = """
            <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
        """.trimIndent()
        val code = "facebook fb.com messenger login"
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("A.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.MEDIUM, findings[0].severity)
    }

    @Test
    fun brandInSmali_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
        """.trimIndent()
        val smali = "coinbase coin-base crypto wallet"
        val findings = analyzer.analyze(decompile(
            manifest = manifest,
            smaliSource = mapOf("A.smali" to smali)
        ))
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun brandReferenceInCode_detected() {
        val manifest = """
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
        """.trimIndent()
        val code = "metamask trust wallet phantom"
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("A.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun multipleBrands_combinedInDescription() {
        val manifest = """
            <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
        """.trimIndent()
        val code = "google facebook paypal instagram"
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("A.java" to code),
            manifest = manifest
        ))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings[0].description.contains("Google") || findings[0].description.contains("Facebook"))
    }

    @Test
    fun noOverlayButAccessibilityWithBrand_mediumSeverity() {
        val manifest = """
            <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
        """.trimIndent()
        val code = "gmail accounts.google signin"
        val findings = analyzer.analyze(decompile(
            javaSource = mapOf("A.java" to code),
            manifest = manifest
        ))
        assertEquals(Severity.MEDIUM, findings[0].severity)
    }
}
