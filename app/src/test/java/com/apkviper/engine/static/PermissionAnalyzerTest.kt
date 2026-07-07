package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class PermissionAnalyzerTest {
    private val analyzer = PermissionAnalyzer()

    private fun decompileResult(
        manifest: String,
        javaSource: Map<String, String> = mapOf("A.java" to ""),
        nativeLibs: List<String> = emptyList()
    ): DecompileResult = DecompileResult(javaSource, mapOf(), manifest, mapOf(), emptyList(), nativeLibs, 0)

    @Test
    fun emptyManifest_noFindings() {
        val result = decompileResult("")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun minimalPermissions_noFindings() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="android.permission.INTERNET"/>
                <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
            </manifest>"""
        val result = decompileResult(manifest)
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun knownLegitimateApp_skippedButSuspiciousChecked() {
        val manifest = """<manifest package="com.google.android.apps.maps">
                <uses-permission android:name="android.permission.INTERNET"/>
                <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
            </manifest>"""
        val findings = analyzer.analyze(decompileResult(manifest))
        assertTrue(findings.any { it.title.contains("Accessibility Service") })
        assertEquals(1, findings.size)
    }

    @Test
    fun knownAppWithNoSuspiciousPerms_noFindings() {
        val manifest = """<manifest package="com.google.android.gms">
                <uses-permission android:name="android.permission.INTERNET"/>
            </manifest>"""
        assertTrue(analyzer.analyze(decompileResult(manifest)).isEmpty())
    }

    @Test
    fun cameraAppWithJustifiedPerms_noUnusualFinding() {
        val manifest = """<manifest package="com.example.camera">
                <uses-permission android:name="android.permission.CAMERA"/>
                <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
            </manifest>"""
        val javaSource = mapOf("CameraActivity.java" to "Camera.open() CaptureRequest takePicture")
        val findings = analyzer.analyze(decompileResult(manifest, javaSource))
        assertFalse(findings.any { it.title.contains("Unusual Permissions") })
    }

    @Test
    fun multipleUnjustifiedPerms_flagged() {
        val manifest = """<manifest package="com.example.torch">
                <uses-permission android:name="android.permission.CAMERA"/>
                <uses-permission android:name="android.permission.READ_CONTACTS"/>
                <uses-permission android:name="android.permission.RECORD_AUDIO"/>
                <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
            </manifest>"""
        val javaSource = mapOf("Flashlight.java" to "Camera.open()")

        val findings = analyzer.analyze(decompileResult(manifest, javaSource))
        assertTrue(findings.any { it.title.contains("Unusual Permissions") })
    }

    @Test
    fun accessibilityService_critical() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
            </manifest>"""
        val findings = analyzer.analyze(decompileResult(manifest))
        assertTrue(findings.any { it.severity == Severity.CRITICAL && it.title.contains("Accessibility Service") })
    }

    @Test
    fun installPackages_critical() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
            </manifest>"""
        val findings = analyzer.analyze(decompileResult(manifest))
        assertTrue(findings.any { it.severity == Severity.CRITICAL && it.title.contains("Silent Package") })
    }

    @Test
    fun writeSecureSettings_critical() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS"/>
            </manifest>"""
        val findings = analyzer.analyze(decompileResult(manifest))
        assertTrue(findings.any { it.severity == Severity.CRITICAL && it.title.contains("System Settings") })
    }

    @Test
    fun processOutgoingCalls_critical() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="android.permission.PROCESS_OUTGOING_CALLS"/>
            </manifest>"""
        val findings = analyzer.analyze(decompileResult(manifest))
        assertTrue(findings.any { it.severity == Severity.CRITICAL && it.title.contains("Outgoing Call") })
    }

    @Test
    fun requestInstallPackages_high() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
            </manifest>"""
        val findings = analyzer.analyze(decompileResult(manifest))
        assertTrue(findings.any { it.severity == Severity.HIGH && it.title.contains("App Installation") })
    }

    @Test
    fun smsSpy_noMessagingApp_critical() {
        val manifest = """<manifest package="com.example.tool">
                <uses-permission android:name="android.permission.READ_SMS"/>
                <uses-permission android:name="android.permission.SEND_SMS"/>
            </manifest>"""
        val javaSource = mapOf("Tool.java" to "class Tool {}")
        val findings = analyzer.analyze(decompileResult(manifest, javaSource))
        assertTrue(findings.any { it.severity == Severity.CRITICAL && it.title.contains("SMS Spy") })
    }

    @Test
    fun smsInMessagingApp_notFlagged() {
        val manifest = """<manifest package="com.example.messenger">
                <uses-permission android:name="android.permission.READ_SMS"/>
                <uses-permission android:name="android.permission.SEND_SMS"/>
            </manifest>"""
        val javaSource = mapOf("SmsActivity.java" to "SmsManager.sendTextMessage")
        val findings = analyzer.analyze(decompileResult(manifest, javaSource))
        assertFalse(findings.any { it.title.contains("SMS Spy") })
    }

    @Test
    fun smsIn2faApp_notFlagged() {
        val manifest = """<manifest package="com.example.auth">
                <uses-permission android:name="android.permission.READ_SMS"/>
                <uses-permission android:name="android.permission.SEND_SMS"/>
            </manifest>"""
        val javaSource = mapOf("Auth.java" to "OTP verification 2fa code")
        val findings = analyzer.analyze(decompileResult(manifest, javaSource))
        assertFalse(findings.any { it.title.contains("SMS Spy") })
    }

    @Test
    fun cameraPlusAudioInNonMediaApp_high() {
        val manifest = """<manifest package="com.example.calculator">
                <uses-permission android:name="android.permission.CAMERA"/>
                <uses-permission android:name="android.permission.RECORD_AUDIO"/>
            </manifest>"""
        val javaSource = mapOf("Calc.java" to "class Calculator {}")
        val findings = analyzer.analyze(decompileResult(manifest, javaSource))
        assertTrue(findings.any { it.severity == Severity.HIGH && it.title.contains("Suspicious Media Access") })
    }

    @Test
    fun cameraPlusAudioInCameraApp_notFlagged() {
        val manifest = """<manifest package="com.example.camera">
                <uses-permission android:name="android.permission.CAMERA"/>
                <uses-permission android:name="android.permission.RECORD_AUDIO"/>
            </manifest>"""
        val javaSource = mapOf("Cam.java" to "Camera.open() takePicture photo gallery camera2")
        val findings = analyzer.analyze(decompileResult(manifest, javaSource))
        assertFalse(findings.any { it.title.contains("Suspicious Media Access") })
    }

    @Test
    fun duplicatePermissions_deduped() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="android.permission.INTERNET"/>
                <uses-permission android:name="android.permission.INTERNET"/>
            </manifest>"""
        assertTrue(analyzer.analyze(decompileResult(manifest)).isEmpty())
    }

    @Test
    fun generalPurposeApp_defaultPermsNotFlagged() {
        val manifest = """<manifest package="com.example.app">
                <uses-permission android:name="android.permission.INTERNET"/>
                <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
            </manifest>"""
        val javaSource = mapOf("App.java" to "class App {}")
        assertTrue(analyzer.analyze(decompileResult(manifest, javaSource)).isEmpty())
    }

    @Test
    fun allSuspiciousPermsTogether_allFlagged() {
        val manifest = """<manifest package="com.example.evil">
                <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
                <uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
                <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS"/>
                <uses-permission android:name="android.permission.PROCESS_OUTGOING_CALLS"/>
                <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
            </manifest>"""
        val findings = analyzer.analyze(decompileResult(manifest))
        assertEquals(5, findings.size)
        findings.forEach { assertTrue(it.severity.ordinal >= Severity.HIGH.ordinal) }
    }

    @Test
    fun extractPackageName_returnsUnknownForMissing() {
        val result = decompileResult("""<manifest><uses-permission android:name="android.permission.INTERNET"/></manifest>""")
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun nonAndroidPermissions_ignored() {
        val manifest = """<manifest package="com.example">
                <uses-permission android:name="com.example.custom.PERMISSION"/>
            </manifest>"""
        assertTrue(analyzer.analyze(decompileResult(manifest)).isEmpty())
    }
}
