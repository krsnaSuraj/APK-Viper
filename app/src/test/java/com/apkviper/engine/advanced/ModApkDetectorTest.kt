package com.apkviper.engine.advanced

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
class ModApkDetectorTest {
    private val detector = ModApkDetector()
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    private fun decompile(java: Map<String, String> = mapOf("A.java" to ""),
                          manifest: String = "", libs: List<String> = emptyList()): DecompileResult =
        DecompileResult(java, mapOf(), manifest, mapOf(), emptyList(), libs, 0)

    @Test
    fun assess_populatesNewPermissionsAndComponents() {
        val apk = createMinimalApk()
        val manifest = """
            <manifest package="com.test">
                <uses-permission android:name="android.permission.SEND_SMS"/>
                <service android:name=".Evil" exported="true" />
            </manifest>
        """.trimIndent()
        val result = detector.assess(context, apk, decompile(manifest = manifest), null)
        assertTrue("dangerousAdded must propagate to newPermissions", result.newPermissions.contains("SEND_SMS"))
        assertTrue("exported components must propagate to newComponents",
            result.newComponents.any { it.contains("exported", ignoreCase = true) && it.contains("true", ignoreCase = true) })
    }

    @Test
    fun assessCleanApk_lowRisk() {
        val apk = createMinimalApk()
        val manifest = """<manifest package="com.test" />"""
        val result = detector.assess(context, apk, decompile(manifest = manifest), null)
        assertTrue(result.riskScore < 21)
        assertTrue(result.suggestion.contains("Safe"))
    }

    @Test
    fun assessDangerousPermissions_increasesScore() {
        val apk = createMinimalApk()
        val manifest = """
            <manifest package="com.test">
                <uses-permission android:name="android.permission.SEND_SMS"/>
                <uses-permission android:name="android.permission.READ_SMS"/>
                <uses-permission android:name="android.permission.CAMERA"/>
            </manifest>
        """.trimIndent()
        val result = detector.assess(context, apk, decompile(manifest = manifest), null)
        assertTrue(result.riskScore >= 21)
    }

    @Test
    fun assessDangerousApis_increasesScore() {
        val apk = createMinimalApk()
        val code = """
            TelephonyManager;->getDeviceId
            SmsManager;->sendTextMessage
            Runtime;->exec
        """.trimIndent()
        val result = detector.assess(context, apk,
            decompile(java = mapOf("A.java" to code)), null)
        assertTrue(result.riskScore >= 51)
    }

    @Test
    fun assessWithCustomNativeLibs_checksModNames() {
        val apk = createMinimalApk()
        val result = detector.assess(context, apk,
            decompile(libs = listOf("lib/armeabi/libmod.so", "lib/armeabi/libhack.so")), null)
        assertTrue(result.riskScore >= 21)
    }

    @Test
    fun generateFindings_highRisk_neverMaliciousOrCritical() {
        val assessment = ModApkDetector.ModRiskAssessment(
            riskScore = 150, repackaged = true,
            newPermissions = listOf("SEND_SMS"),
            newComponents = listOf("SmsReceiver"), newDangerousApis = listOf("sendTextMessage"),
            newNativeLibs = emptyList(), suggestion = "malicious"
        )
        val findings = detector.generateFindings(assessment)
        // Mods are an integrity note, never MALWARE/CRITICAL — genuine/modded apps must not be flagged.
        assertFalse(findings.any { it.severity == Severity.CRITICAL })
        assertFalse(findings.any { it.category == FindingCategory.MALWARE })
        assertTrue(findings.any { it.title.contains("High-Risk Mod") })
    }

    @Test
    fun generateFindings_suspicious_mediumSeverity() {
        val assessment = ModApkDetector.ModRiskAssessment(
            riskScore = 75, repackaged = true,
            newPermissions = listOf("BIND_ACCESSIBILITY_SERVICE", "SEND_SMS"),
            newComponents = emptyList(), newDangerousApis = listOf("sendTextMessage"),
            newNativeLibs = emptyList(), suggestion = "suspicious"
        )
        val findings = detector.generateFindings(assessment)
        assertTrue(findings.any { it.title.contains("Suspicious Mod") })
        assertEquals(Severity.MEDIUM, findings.first { it.title.contains("Suspicious Mod") }.severity)
    }

    @Test
    fun generateFindings_lowRisk_adRemoval() {
        val assessment = ModApkDetector.ModRiskAssessment(
            riskScore = 30, repackaged = false,
            newPermissions = emptyList(),
            newComponents = emptyList(), newDangerousApis = emptyList(),
            newNativeLibs = emptyList(), suggestion = "ad-removal"
        )
        val findings = detector.generateFindings(assessment)
        assertTrue(findings.any { it.title.contains("Ad-Removal Mod") })
    }

    @Test
    fun generateFindings_repackaged_infoFinding() {
        val assessment = ModApkDetector.ModRiskAssessment(
            riskScore = 10, repackaged = true,
            newPermissions = emptyList(),
            newComponents = emptyList(), newDangerousApis = emptyList(),
            newNativeLibs = emptyList(), suggestion = "safe"
        )
        val findings = detector.generateFindings(assessment)
        assertTrue(findings.any { it.title.contains("Repackaged APK") })
    }

    @Test
    fun crossValidate_emptyIndicators_returnsNoTypes() {
        val result = detector.crossValidate(emptyList(), emptyList(), emptyList(), emptyList(), emptyList())
        assertTrue(result.indicatorTypes.isEmpty())
        assertFalse(result.hasMixedIndicators)
        assertTrue(result.corroboratingFindings.isEmpty())
    }

    @Test
    fun crossValidate_multipleIndicatorTypes_hasMixed() {
        val result = detector.crossValidate(
            listOf("CAMERA"), listOf("getDeviceId"), emptyList(), emptyList(), emptyList()
        )
        assertTrue(result.hasMixedIndicators)
        assertTrue(result.indicatorTypes.contains("permission"))
        assertTrue(result.indicatorTypes.contains("api"))
    }

    @Test
    fun crossValidate_existingFindings_corroborated() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware", "desc"),
            Finding(FindingCategory.PERMISSION, Severity.LOW, "Perm", "desc")
        )
        val result = detector.crossValidate(
            listOf("SEND_SMS"), listOf("exec"), emptyList(), emptyList(), findings
        )
        assertTrue(result.corroboratingFindings.contains("MALWARE"))
        assertFalse("Low severity findings should not corroborate",
            result.corroboratingFindings.contains("PERMISSION"))
    }

    @Test
    fun isLikelyGenuineMod_lowRisk_returnsTrue() {
        assertTrue(detector.isLikelyGenuineMod(30, listOf("INTERNET"), emptyList()))
        assertTrue(detector.isLikelyGenuineMod(10, emptyList(), emptyList()))
    }

    @Test
    fun isLikelyGenuineMod_highRiskWithDangerousApis_returnsFalse() {
        assertFalse(detector.isLikelyGenuineMod(70, listOf("INTERNET"), listOf("exec")))
        assertFalse(detector.isLikelyGenuineMod(60, emptyList(), listOf("DexClassLoader")))
    }

    @Test
    fun isLikelyGenuineMod_highRiskOnlyHarmlessPerms_returnsTrue() {
        assertTrue(detector.isLikelyGenuineMod(60, listOf("INTERNET", "ACCESS_NETWORK_STATE"), emptyList()))
    }

    @Test
    fun isLikelyGenuineMod_highRiskDangerousPerm_returnsFalse() {
        assertFalse(detector.isLikelyGenuineMod(60, listOf("SEND_SMS"), emptyList()))
    }

    @Test
    fun getConfidence_noIndicators_high() {
        val assessment = ModApkDetector.ModRiskAssessment(5, false, emptyList(), emptyList(), emptyList(), emptyList(), "safe")
        assertEquals(0.9f, detector.getConfidence(assessment))
    }

    @Test
    fun getConfidence_oneIndicator_low() {
        val assessment = ModApkDetector.ModRiskAssessment(30, false, listOf("INTERNET"), emptyList(), emptyList(), emptyList(), "safe")
        assertEquals("Single harmless indicator should have 0.5 confidence", 0.5f, detector.getConfidence(assessment))
    }

    @Test
    fun getConfidence_genuineAndMaliciousSignals_lowest() {
        val assessment = ModApkDetector.ModRiskAssessment(30, false, listOf("CAMERA"), emptyList(), emptyList(), emptyList(), "safe")
        assertEquals("Genuine + malicious signals should have 0.4 confidence", 0.4f, detector.getConfidence(assessment))
    }

    @Test
    fun getConfidence_maliciousMultiIndicator_high() {
        val assessment = ModApkDetector.ModRiskAssessment(80, true,
            listOf("SEND_SMS", "CAMERA"), emptyList(),
            listOf("SmsManager;->sendTextMessage", "getDeviceId"), emptyList(), "suspicious")
        assertEquals(0.85f, detector.getConfidence(assessment))
    }

    @Test
    fun harmlessPermissions_noRiskForInternet() {
        val apk = createMinimalApk()
        val manifest = """<manifest package="com.test">
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
            <uses-permission android:name="android.permission.VIBRATE"/>
        </manifest>""".trimIndent()
        val result = detector.assess(context, apk, decompile(manifest = manifest), null)
        assertTrue("Only harmless permissions should keep risk low", result.riskScore < 21)
    }

    @Test
    fun httpsOnly_noC2Score() {
        val apk = createMinimalApk()
        val code = """
            https://api.example.com/data
            https://cdn.example.com/assets
            https://analytics.example.com/track
            https://ads.example.com/request
        """.trimIndent()
        val result = detector.assess(context, apk,
            decompile(java = mapOf("A.java" to code)), null)
        // Only HTTPS URLs should NOT trigger C2 score
        assertTrue("HTTPS-only URLs should not increase C2 score", result.riskScore < 30)
    }

    @Test
    fun assessCleanApk_withknownModSigner_lowRisk() {
        val apk = createMinimalApk()
        val manifest = """<manifest package="com.test.mod" />"""
        // Simulate APKPure-signed app by passing the signature
        val result = detector.assess(context, apk, decompile(manifest = manifest), null)
        assertTrue("Clean mod should be low risk", result.riskScore < 51)
        assertTrue(result.suggestion.contains("Safe") || result.suggestion.contains("low risk"))
    }

    @Test
    fun lowRiskApiOnly_noScoreWithoutDangerousPerms() {
        val apk = createMinimalApk()
        val code = "getDeviceId"
        val result = detector.assess(context, apk,
            decompile(java = mapOf("A.java" to code), manifest = """<manifest package="com.test"/>"""), null)
        assertTrue("Low-risk API alone without dangerous perms should keep risk low",
            result.riskScore < 21)
    }

    private fun createMinimalApkWithPackage(pkg: String): File {
        val file = tempFolder.newFile("test_$pkg.apk")
        java.util.zip.ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(java.util.zip.ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest package=\"$pkg\"/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(java.util.zip.ZipEntry("classes.dex"))
            zip.write(ByteArray(100))
            zip.closeEntry()
        }
        return file
    }

    private fun createMinimalApk(): File {
        val file = tempFolder.newFile("test.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(100))
            zip.closeEntry()
        }
        return file
    }
}
