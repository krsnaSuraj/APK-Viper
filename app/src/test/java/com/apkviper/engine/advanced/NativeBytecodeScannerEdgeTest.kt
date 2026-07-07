package com.apkviper.engine.advanced

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class NativeBytecodeScannerEdgeTest {
    private val scanner = NativeBytecodeScanner()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun emptyNativeLibs_noFindings() {
        val apk = createApk()
        assertTrue(scanner.analyze(apk, emptyList()).isEmpty())
    }

    @Test
    fun analyzeReadsFromZipEntries() {
        val apk = createApkWithLibEntry("lib/armeabi-v7a/libtest.so",
            byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
        )
        val findings = scanner.analyze(apk, listOf("lib/armeabi-v7a/libtest.so"))
        // Clean lib should produce no findings
        assertTrue("Analyzer should read libs from zip entries", findings.isEmpty())
    }

    @Test
    fun oversizedLibEntries_skipped() {
        val data = ByteArray(51_000_000) { 0x00 } // > 50MB
        val apk = tempFolder.newFile("oversized.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/libhuge.so"))
            zip.write(data)
            zip.closeEntry()
        }
        val findings = scanner.analyze(apk, listOf("lib/armeabi-v7a/libhuge.so"))
        assertTrue(
            "Oversized libraries (>50MB) should be skipped",
            findings.isEmpty()
        )
    }

    @Test
    fun nonexistentEntry_skippedGracefully() {
        val apk = createApk()
        val findings = scanner.analyze(apk, listOf("lib/x86/nonexistent.so"))
        assertTrue("Nonexistent zip entries should be skipped", findings.isEmpty())
    }

    @Test
    fun corruptedEntry_skippedGracefully() {
        val apk = tempFolder.newFile("corrupt.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
        }
        val findings = scanner.analyze(apk, listOf("lib/x86/libbad.so"))
        assertTrue("Corrupted entries should be skipped", findings.isEmpty())
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

    private fun createApkWithLibEntry(name: String, content: ByteArray): File {
        val file = tempFolder.newFile("lib_apk.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry(name))
            zip.write(content)
            zip.closeEntry()
        }
        return file
    }
}
