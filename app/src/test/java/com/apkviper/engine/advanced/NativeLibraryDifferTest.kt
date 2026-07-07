package com.apkviper.engine.advanced

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.RandomAccessFile
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class NativeLibraryDifferTest {
    private val differ = NativeLibraryDiffer()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun emptyNativeLibs_noFindings() {
        val apk = createApk()
        assertTrue(differ.analyze(apk, emptyList()).isEmpty())
    }

    @Test
    fun libNotOnDisk_skipped() {
        val apk = createApk()
        assertTrue(differ.analyze(apk, listOf("libnative.so")).isEmpty())
    }

    @Test
    fun nonElfFile_skipped() {
        val apk = createApkWithOnDiskLib("libnative.so", "not an elf file")
        val findings = differ.analyze(apk, listOf("libnative.so"))
        assertTrue(findings.isEmpty())
    }

    @Test
    fun isElfFile_validElf_returnsTrue() {
        val elfBytes = createMinimalElf()
        val file = tempFolder.newFile("valid.elf")
        file.writeBytes(elfBytes)
        assertTrue(invokeIsElf(file))
    }

    @Test
    fun isElfFile_nonElf_returnsFalse() {
        val file = tempFolder.newFile("notelf.bin")
        file.writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03))
        assertFalse(invokeIsElf(file))
    }

    @Test
    fun isElfFile_tooSmall_returnsFalse() {
        val file = tempFolder.newFile("small.bin")
        file.writeBytes(byteArrayOf(0x01, 0x02))
        assertFalse(invokeIsElf(file))
    }

    @Test
    fun hexToBytes_validInput() {
        val result = invokeHexToBytes("E0031F2AE1031F2A010000D4")
        assertEquals(12, result.size)
        assertEquals(0xE0.toByte(), result[0])
        assertEquals(0xD4.toByte(), result[11])
    }

    @Test
    fun hexToBytes_empty() {
        assertTrue(invokeHexToBytes("").isEmpty())
    }

    @Test
    fun containsPattern_found() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val pattern = byteArrayOf(3, 4)
        assertTrue(invokeContainsPattern(data, pattern))
    }

    @Test
    fun containsPattern_notFound() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val pattern = byteArrayOf(6, 7)
        assertFalse(invokeContainsPattern(data, pattern))
    }

    @Test
    fun containsPattern_largerPattern() {
        val data = byteArrayOf(1, 2, 3)
        val pattern = byteArrayOf(1, 2, 3, 4)
        assertFalse(invokeContainsPattern(data, pattern))
    }

    @Test
    fun containsPattern_exactMatch() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val pattern = byteArrayOf(1, 2, 3, 4, 5)
        assertTrue(invokeContainsPattern(data, pattern))
    }

    @Test
    fun elfHeader_parsed() {
        val elf = createMinimalElf()
        val file = tempFolder.newFile("parsed.elf")
        file.writeBytes(elf)
        val header = invokeParseElfHeader(file)
        assertNotNull(header)
    }

    @Test
    fun entryPointMismatch_detected() {
        val apk = tempFolder.newFile("bad_entry.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
        }
        val findings = differ.analyze(apk, emptyList())
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

    private fun createApkWithOnDiskLib(libName: String, content: String): File {
        val libDir = tempFolder.newFolder("libs")
        val libFile = File(libDir, libName)
        libFile.writeText(content)

        val apkDir = tempFolder.newFolder("apk_parent")
        val apk = File(apkDir, "test.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
        }
        return apk
    }

    private fun createMinimalElf(): ByteArray {
        val data = ByteArray(64)
        // ELF magic
        data[0] = 0x7f
        data[1] = 'E'.code.toByte()
        data[2] = 'L'.code.toByte()
        data[3] = 'F'.code.toByte()
        data[4] = 2 // 64-bit
        data[5] = 1 // little endian
        return data
    }

    private fun invokeIsElf(file: File): Boolean {
        val method = NativeLibraryDiffer::class.java.getDeclaredMethod("isElfFile", File::class.java)
        method.isAccessible = true
        return method.invoke(differ, file) as Boolean
    }

    private fun invokeHexToBytes(hex: String): ByteArray {
        val method = NativeLibraryDiffer::class.java.getDeclaredMethod("hexToBytes", String::class.java)
        method.isAccessible = true
        return method.invoke(differ, hex) as ByteArray
    }

    private fun invokeContainsPattern(data: ByteArray, pattern: ByteArray): Boolean {
        val method = NativeLibraryDiffer::class.java.getDeclaredMethod(
            "containsPattern", ByteArray::class.java, ByteArray::class.java
        )
        method.isAccessible = true
        return method.invoke(differ, data, pattern) as Boolean
    }

    private fun invokeParseElfHeader(file: File): Any? {
        val method = NativeLibraryDiffer::class.java.getDeclaredMethod("parseElfHeader", File::class.java)
        method.isAccessible = true
        return method.invoke(differ, file)
    }
}
