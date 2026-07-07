package com.apkviper.engine.native

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class NativeAnalyzerTest {
    private val analyzer = NativeAnalyzer()

    @Test
    fun emptyNativeLibs_noFindings() {
        val result = DecompileResult(mapOf(), mapOf(), "", mapOf(), emptyList(), emptyList(), 0)
        assertTrue(analyzer.analyze(result).isEmpty())
    }

    @Test
    fun whitelistedLibs_infoFinding() {
        val result = DecompileResult(
            javaSource = mapOf("A.java" to ""),
            smaliSource = mapOf(),
            manifest = "",
            resources = mapOf(),
            dexFiles = emptyList(),
            nativeLibs = listOf("lib/armeabi-v7a/libunity.so"),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Known Framework Libraries") })
        assertEquals(Severity.INFO, findings.find { it.title.contains("Known Framework") }!!.severity)
    }

    @Test
    fun unknownLib_obfuscatedName_detected() {
        val result = DecompileResult(
            javaSource = mapOf("A.java" to ""),
            smaliSource = mapOf(),
            manifest = "",
            resources = mapOf(),
            dexFiles = emptyList(),
            nativeLibs = listOf("lib/armeabi-v7a/liba1b2c3d4e5f6g7h8i9j0k1l2m3n.so"),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Unknown Obfuscated Native Library") })
        assertEquals(Severity.HIGH, findings.find { it.title.contains("Unknown Obfuscated") }!!.severity)
    }

    @Test
    fun knownFrameworkAndUnknownLibs_bothDetected() {
        val result = DecompileResult(
            javaSource = mapOf("A.java" to ""),
            smaliSource = mapOf(), manifest = "", resources = mapOf(),
            dexFiles = emptyList(),
            nativeLibs = listOf(
                "lib/armeabi-v7a/libflutter.so",
                "lib/armeabi-v7a/z.so"
            ),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        assertTrue(findings.any { it.title.contains("Known Framework") })
        assertTrue(findings.any { it.title.contains("Unknown Obfuscated") })
    }

    @Test
    fun normalLibName_notObfuscated() {
        val result = DecompileResult(
            javaSource = mapOf("A.java" to ""),
            smaliSource = mapOf(), manifest = "", resources = mapOf(),
            dexFiles = emptyList(),
            nativeLibs = listOf("lib/armeabi-v7a/libnative-lib.so"),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        val obfuscated = findings.filter { it.title.contains("Unknown Obfuscated") }
        assertEquals(0, obfuscated.size)
    }

    @Test
    fun deepScan_unknownLibWithSystemAndSocket_reverseShellCritical() {
        val elfBytes = buildElfWithStrings(listOf("system", "socket", "connect"))
        val tmp = createTempFile("payload", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libevil.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libevil.so"))
        assertTrue(results.any { it.title.contains("Reverse Shell Capability") })
        assertEquals(Severity.CRITICAL, results.find { it.title.contains("Reverse Shell") }!!.severity)
    }

    @Test
    fun deepScan_unknownLibWithSystemAndPtrace_codeInjectionCritical() {
        val elfBytes = buildElfWithStrings(listOf("system", "ptrace", "dlopen"))
        val tmp = createTempFile("inject", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libinject.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libinject.so"))
        assertTrue(results.any { it.title.contains("Code Injection + Execution") })
    }

    @Test
    fun deepScan_frameworkLib_symbolsDowngraded() {
        val elfBytes = buildElfWithStrings(listOf("system", "socket", "connect"))
        val tmp = createTempFile("framework", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libunity.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libunity.so"))
        assertTrue(results.any { it.title.contains("Unity Engine") })
        val symbolFindings = results.filter { it.title.contains("Native Symbol") }
        symbolFindings.forEach { finding ->
            assertTrue(
                "Framework symbol should be INFO or LOW, not ${finding.severity}",
                finding.severity == Severity.INFO || finding.severity == Severity.LOW
            )
        }
    }

    @Test
    fun deepScan_urlInUnknownLib_detected() {
        val elfBytes = buildElfWithStrings(listOf("http://evil.example.com/payload"))
        val tmp = createTempFile("url", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libbad.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libbad.so"))
        assertTrue(results.any { it.title.contains("Hardcoded URL") })
        assertEquals(Severity.HIGH, results.find { it.title.contains("Hardcoded URL") }!!.severity)
    }

    @Test
    fun deepScan_ipInUnknownLib_detected() {
        val elfBytes = buildElfWithStrings(listOf("203.0.113.42"))
        val tmp = createTempFile("ip_addr", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libip.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libip.so"))
        assertTrue(results.any { it.title.contains("Hardcoded IP") })
    }

    @Test
    fun deepScan_urlInFrameworkLib_notDetected() {
        val elfBytes = buildElfWithStrings(listOf("http://evil.example.com/payload"))
        val tmp = createTempFile("fwurl", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libunity.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libunity.so"))
        assertFalse(results.any { it.title.contains("Hardcoded URL") })
    }

    @Test
    fun deepScan_googleSourceUrl_filteredAsNoise() {
        val elfBytes = buildElfWithStrings(listOf("https://android.googlesource.com/toolchain/abc"))
        val tmp = createTempFile("noise", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libunknown.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libunknown.so"))
        assertFalse(results.any { it.title.contains("Hardcoded URL") })
    }

    @Test
    fun deepScan_privateIp_filteredAsNoise() {
        val elfBytes = buildElfWithStrings(listOf("192.168.1.1", "127.0.0.1", "10.0.0.1"))
        val tmp = createTempFile("privip", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libunknown.so"))
            zos.write(elfBytes)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libunknown.so"))
        assertFalse(results.any { it.title.contains("Hardcoded IP") })
    }

    @Test
    fun deepScan_emptyNativeLibs_returnsEmpty() {
        val tmp = createTempFile("empty", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write("dex".toByteArray())
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, emptyList())
        assertTrue(results.isEmpty())
    }

    @Test
    fun deepScan_nonexistentEntry_skipped() {
        val tmp = createTempFile("noentry", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write("dex".toByteArray())
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libnonexistent.so"))
        assertTrue(results.isEmpty())
    }

    @Test
    fun deepScan_highEntropyUnknownLib_detected() {
        val rng = java.util.Random(42)
        val highEntropy = ByteArray(1000).apply { rng.nextBytes(this) }
        val tmp = createTempFile("entropy", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libencrypted.so"))
            zos.write(highEntropy)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libencrypted.so"))
        assertTrue(results.any { it.title.contains("Highly Encrypted") || it.title.contains("Encrypted C2 Payload") })
    }

    @Test
    fun deepScan_correlationNetAndHighEntropy_encryptedC2() {
        val rng = java.util.Random(99)
        val stringPrefix = "socket connect sendto connect".toByteArray()
        val randomPart = ByteArray(2000).apply { rng.nextBytes(this) }
        val content = stringPrefix + randomPart
        val tmp = createTempFile("c2payload", ".apk")
        tmp.deleteOnExit()
        ZipOutputStream(FileOutputStream(tmp)).use { zos ->
            zos.putNextEntry(ZipEntry("lib/armeabi-v7a/libc2.so"))
            zos.write(content)
            zos.closeEntry()
        }
        val results = analyzer.deepScan(tmp, listOf("lib/armeabi-v7a/libc2.so"))
        val encryptedC2 = results.filter { it.title.contains("Encrypted C2 Payload") }
        assertFalse("Should detect C2 if entropy > 7.0", encryptedC2.isEmpty())
    }

    @Test
    fun findingsHaveCorrectCategory() {
        val result = DecompileResult(
            javaSource = mapOf("A.java" to ""),
            smaliSource = mapOf(), manifest = "", resources = mapOf(),
            dexFiles = emptyList(),
            nativeLibs = listOf("lib/armeabi-v7a/z.so"),
            decompileTimeMs = 0
        )
        val findings = analyzer.analyze(result)
        findings.forEach { assertEquals(FindingCategory.NATIVE, it.category) }
    }

    private fun buildElfWithStrings(strings: List<String>): ByteArray {
        val elfHeader = byteArrayOf(0x7F, 0x45, 0x4C, 0x46) // \x7fELF
        val sb = StringBuilder()
        sb.append(String(elfHeader, Charsets.US_ASCII))
        sb.append('\u0000')
        strings.forEach { sb.append(it).append('\u0000') }
        return sb.toString().toByteArray()
    }
}
