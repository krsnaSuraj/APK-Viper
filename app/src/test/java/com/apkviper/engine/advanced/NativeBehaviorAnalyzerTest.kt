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

class NativeBehaviorAnalyzerTest {
    private val analyzer = NativeBehaviorAnalyzer()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    private fun decompile(javaSource: Map<String, String> = mapOf(),
                          libs: List<String> = emptyList()): DecompileResult =
        DecompileResult(javaSource, mapOf(), "", mapOf(), emptyList(), libs, 0)

    @Test
    fun emptyNativeLibs_noFindings() {
        val apk = createApk()
        assertTrue(analyzer.analyze(decompile(), apk).isEmpty())
    }

    @Test
    fun nativeLibNotInZip_skipped() {
        val apk = createApk()
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/x86/libnonexistent.so")), apk
        )
        assertTrue(findings.isEmpty())
    }

    @Test
    fun ptraceStringPattern_matched() {
        val apk = createApkWithLib("libnative.so",
            "This library contains ptrace and PTRACE_ATTACH symbols"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libnative.so")), apk
        )
        assertTrue(findings.any { it.title.contains("NAT-001") })
        assertTrue(findings.any { it.severity == Severity.CRITICAL })
    }

    @Test
    fun deviceInfoHarvesting_matched() {
        val apk = createApkWithLib("libharvest.so",
            "getDeviceId getSubscriberId getLine1Number getMacAddress"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libharvest.so")), apk
        )
        assertTrue(findings.any { it.title.contains("NAT-003") })
    }

    @Test
    fun dynamicLinkerHijack_matched() {
        val apk = createApkWithLib("libhijack.so",
            "LD_PRELOAD dlopen dlsym RTLD_NEXT"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libhijack.so")), apk
        )
        assertTrue(findings.any { it.title.contains("NAT-006") })
    }

    @Test
    fun antiDebugging_matched() {
        val apk = createApkWithLib("libdebug.so",
            "/proc/self/status TracerPid frida substrate xposed"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libdebug.so")), apk
        )
        assertTrue(findings.any { it.title.contains("NAT-008") })
    }

    @Test
    fun cryptoMiningString_matched() {
        val apk = createApkWithLib("libminer.so",
            "stratum mining cryptonight randomx"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libminer.so")), apk
        )
        assertTrue(findings.any { it.title.contains("NAT-004") })
    }

    @Test
    fun nativeSocketC2_matched() {
        val apk = createApkWithLib("libc2.so",
            "connect( send( recv( socket( gethostbyname"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libc2.so")), apk
        )
        assertTrue(findings.any { it.title.contains("NAT-005") })
    }

    @Test
    fun cpuMinerAffinity_matched() {
        val apk = createApkWithLib("libcpu.so",
            "sched_setaffinity pthread_create num_cores max_threads"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libcpu.so")), apk
        )
        assertTrue(findings.any { it.title.contains("NAT-010") })
    }

    @Test
    fun obfuscationIndicators_lowSeverity() {
        val apk = createApkWithLib("libobf.so",
            "__afl asan ubsan msan"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libobf.so")), apk
        )
        val obfFinding = findings.find { it.title.contains("NAT-009") }
        assertNotNull(obfFinding)
        assertEquals(Severity.LOW, obfFinding!!.severity)
    }

    @Test
    fun largeNativeLib_skipped() {
        val apk = tempFolder.newFile("large.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/libbig.so"))
            zip.write(ByteArray(25_000_000))
            zip.closeEntry()
        }
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libbig.so")), apk
        )
        assertTrue(findings.isEmpty())
    }

    @Test
    fun noMatch_noFinding() {
        val apk = createApkWithLib("libclean.so",
            "just some normal library code with nothing suspicious"
        )
        val findings = analyzer.analyze(
            decompile(libs = listOf("lib/armeabi-v7a/libclean.so")), apk
        )
        assertTrue(findings.isEmpty())
    }

    private fun createApk(): File {
        val file = tempFolder.newFile("test.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
        }
        return file
    }

    private fun createApkWithLib(libName: String, content: String): File {
        val file = tempFolder.newFile("test_$libName.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/$libName"))
            zip.write(content.toByteArray())
            zip.closeEntry()
        }
        return file
    }
}
