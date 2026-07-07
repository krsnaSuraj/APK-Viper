package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class AccessibilityChainAnalyzerTest {
    private val analyzer = AccessibilityChainAnalyzer()

    private fun decompile(javaSource: Map<String, String> = mapOf("A.java" to ""),
                          manifest: String = ""): DecompileResult =
        DecompileResult(javaSource, mapOf(), manifest, mapOf(), emptyList(), emptyList(), 0)

    @Test
    fun emptyManifest_noFindings() {
        assertTrue(analyzer.analyze(decompile()).isEmpty())
    }

    @Test
    fun harmlessPermissions_noFindings() {
        val manifest = "android.permission.VIBRATE android.permission.INTERNET"
        assertTrue(analyzer.analyze(decompile(manifest = manifest)).isEmpty())
    }

    @Test
    fun singleToxicPerm_noFindings() {
        val manifest = "android.permission.BIND_ACCESSIBILITY_SERVICE"
        assertTrue(analyzer.analyze(decompile(manifest = manifest)).isEmpty())
    }

    @Test
    fun twoToxicPerms_noApi_mediumSeverity() {
        val manifest = ("android.permission.BIND_ACCESSIBILITY_SERVICE " +
            "android.permission.SYSTEM_ALERT_WINDOW android.permission.INTERNET")
        val findings = analyzer.analyze(decompile(manifest = manifest))
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.MEDIUM, findings[0].severity)
    }

    @Test
    fun twoToxicPerms_withApis_highSeverity() {
        val manifest = ("android.permission.BIND_ACCESSIBILITY_SERVICE " +
            "android.permission.SYSTEM_ALERT_WINDOW android.permission.INTERNET")
        val code = ("performGlobalAction getRootInActiveWindow " +
            "findAccessibilityNodeInfosByText dispatchGesture onAccessibilityEvent getWindows")
        val findings = analyzer.analyze(
            decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.isNotEmpty())
        assertTrue("Expected HIGH or CRITICAL, got ${findings[0].severity}",
            findings[0].severity == Severity.CRITICAL || findings[0].severity == Severity.HIGH)
    }

    @Test
    fun overlayNotificationInstallPackages_findsFinding() {
        val manifest = ("android.permission.SYSTEM_ALERT_WINDOW " +
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE " +
            "android.permission.REQUEST_INSTALL_PACKAGES")
        val findings = analyzer.analyze(decompile(manifest = manifest))
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.MEDIUM, findings[0].severity)
    }

    @Test
    fun caseInsensitivePermissionMatching() {
        val manifest = ("android.permission.bind_accessibility_service " +
            "android.permission.system_alert_window android.permission.internet")
        val findings = analyzer.analyze(decompile(manifest = manifest))
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun accessibilityCameraNetwork_findsFinding() {
        val manifest = ("android.permission.BIND_ACCESSIBILITY_SERVICE " +
            "android.permission.CAMERA android.permission.INTERNET")
        val code = "performGlobalAction getRootInActiveWindow findAccessibilityNodeInfosByText"
        val findings = analyzer.analyze(
            decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Accessibility + Camera + Network") })
    }

    @Test
    fun accessibilitySmsNetwork_findsFinding() {
        val manifest = ("android.permission.BIND_ACCESSIBILITY_SERVICE " +
            "android.permission.READ_SMS android.permission.INTERNET")
        val code = "performGlobalAction getRootInActiveWindow findAccessibilityNodeInfosByText"
        val findings = analyzer.analyze(
            decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.any { it.title.contains("Accessibility + SMS + Network") })
    }

    @Test
    fun codeWithoutAccessibilityApis_stillReturnsFinding() {
        val manifest = ("android.permission.BIND_ACCESSIBILITY_SERVICE " +
            "android.permission.SYSTEM_ALERT_WINDOW android.permission.INTERNET")
        val code = "just a plain class without any accessibility methods"
        val findings = analyzer.analyze(
            decompile(javaSource = mapOf("A.java" to code), manifest = manifest))
        assertTrue(findings.isNotEmpty())
        assertEquals(Severity.MEDIUM, findings[0].severity)
    }

    @Test
    fun chainNameMatchesExpectedFormat() {
        val manifest = ("android.permission.BIND_ACCESSIBILITY_SERVICE " +
            "android.permission.SYSTEM_ALERT_WINDOW android.permission.INTERNET")
        val findings = analyzer.analyze(decompile(manifest = manifest))
        assertTrue(findings.any { it.title.startsWith("Accessibility Abuse Chain:") })
    }
}
