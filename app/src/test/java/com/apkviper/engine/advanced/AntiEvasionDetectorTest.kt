package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AntiEvasionDetectorTest {
    private val detector = AntiEvasionDetector()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    private fun decompile(java: Map<String, String> = mapOf("A.java" to ""),
                          smali: Map<String, String> = mapOf(),
                          libs: List<String> = emptyList()): DecompileResult =
        DecompileResult(java, smali, "", mapOf(), emptyList(), libs, 0)

    @Test
    fun cleanCode_noFindings() {
        val apk = createMinimalApk()
        assertTrue(detector.analyze(decompile(), apk).isEmpty())
    }

    @Test
    fun debuggerDetection_found() {
        val code = "Debug.isDebuggerConnected() called in method"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("Debugger Detection") })
    }

    @Test
    fun emulatorDetection_found() {
        val code = "Build.FINGERPRINT + Build.MODEL + qemu + goldfish detection"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("Emulator Detection") })
    }

    @Test
    fun rootDetection_found() {
        val code = "su binary check /system/bin/su test-keys magisk"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("Root Detection") })
    }

    @Test
    fun hookFrameworkDetection_found() {
        val code = "XposedBridge and frida-server detection in code"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("Hook Framework") })
    }

    @Test
    fun timingEvasion_found() {
        val code = "Thread.sleep(5000) SystemClock.sleep(1000) Handler.postDelayed delayed"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("Timing") })
    }

    @Test
    fun antiDisassembly_found() {
        val code = "obfuscate junk garbage xorDecrypt decryptPayload"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("Anti-Disassembly") })
    }

    @Test
    fun procBasedEvasion_found() {
        val code = "/proc/self/status TracerPid /proc/self/maps readlink(/proc"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("/proc") })
    }

    @Test
    fun multipleCategories_heavyEvasionSuite() {
        val code = """
            Debug.isDebuggerConnected Build.FINGERPRINT Build.MODEL qemu
            su /system/bin/su XposedBridge frida Thread.sleep SystemClock.sleep
            /proc/self/status TracerPid obfuscate
        """.trimIndent()
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("Heavy Evasion Suite") })
    }

    @Test
    fun evasionInSmaliSource_detected() {
        val smali = "isDebuggerConnected waitingForDebugger"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(smali = mapOf("A.smali" to smali)), apk)
        assertTrue(findings.isNotEmpty())
    }

    @Test
    fun ipcEvasionPattern_detected() {
        val code = "Intent.FLAG_ACTIVITY_NEW_TASK Intent.FLAG_INCLUDE_STOPPED_PACKAGES"
        val apk = createMinimalApk()
        val findings = detector.analyze(decompile(java = mapOf("A.java" to code)), apk)
        assertTrue(findings.any { it.title.contains("IPC") })
    }

    private fun createMinimalApk(): File {
        val apk = tempFolder.newFile("test.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest package='com.test'/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(100))
            zip.closeEntry()
        }
        return apk
    }
}
