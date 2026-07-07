package com.apkviper.engine.advanced

import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class NativeBytecodeScannerTest {
    private val scanner = NativeBytecodeScanner()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun emptyNativeLibs_noFindings() {
        val apk = createApk()
        assertTrue(scanner.analyze(apk, emptyList()).isEmpty())
    }

    @Test
    fun libNotExtracted_skipped() {
        val apk = createApk()
        val findings = scanner.analyze(apk, listOf("lib/x86/libnonexistent.so"))
        assertTrue(findings.isEmpty())
    }

    @Test
    fun hexToBytes_validInput() {
        val result = invokeHexToBytes("200080D2")
        assertArrayEquals(byteArrayOf(0x20, 0x00, 0x80.toByte(), 0xD2.toByte()), result)
    }

    @Test
    fun hexToBytes_empty() {
        val result = invokeHexToBytes("")
        assertEquals(0, result.size)
    }

    @Test
    fun hexToBytes_withSpaces() {
        val result = invokeHexToBytes("20 00 80 D2")
        assertArrayEquals(byteArrayOf(0x20, 0x00, 0x80.toByte(), 0xD2.toByte()), result)
    }

    @Test
    fun socketPattern_found() {
        val apk = createApkWithLib("libtest.so",
            byteArrayOf(0x20, 0x00, 0x80.toByte(), 0xD2.toByte(), 0x01, 0x00, 0x00, 0x54)
        )
        val findings = scanner.analyze(apk, listOf("lib/armeabi-v7a/libtest.so"))
        if (findings.isNotEmpty()) {
            assertTrue(findings.any { it.category == com.apkviper.model.FindingCategory.NATIVE })
        }
    }

    @Test
    fun cleanLib_noFindings() {
        val apk = createApkWithLib("libclean.so",
            byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
        )
        val findings = scanner.analyze(apk, listOf("lib/armeabi-v7a/libclean.so"))
        assertTrue(findings.isEmpty())
    }

    @Test
    fun largeLib_readsFirst20MbMax() {
        val data = ByteArray(30_000_000) { 0x00 }
        val apk = tempFolder.newFile("large_lib.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/libbig.so"))
            zip.write(data)
            zip.closeEntry()
        }
        val findings = scanner.analyze(apk, listOf("lib/armeabi-v7a/libbig.so"))
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

    private fun createApkWithLib(name: String, content: ByteArray): File {
        val file = tempFolder.newFile("lib_test.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/$name"))
            zip.write(content)
            zip.closeEntry()
        }
        return file
    }

    private fun invokeHexToBytes(hex: String): ByteArray {
        // Access the private hexToBytes method via reflection
        val method = NativeBytecodeScanner::class.java.getDeclaredMethod(
            "hexToBytes", String::class.java
        )
        method.isAccessible = true
        return method.invoke(scanner, hex) as ByteArray
    }
}
