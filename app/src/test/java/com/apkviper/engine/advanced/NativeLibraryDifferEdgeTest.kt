package com.apkviper.engine.advanced

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class NativeLibraryDifferEdgeTest {
    private val differ = NativeLibraryDiffer()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun emptyNativeLibs_noFindings() {
        val apk = createApk()
        assertTrue(differ.analyze(apk, emptyList()).isEmpty())
    }

    @Test
    fun analyzeReadsFromZipEntries() {
        val elfContent = createMinimalElf()
        val apk = createApkWithLibEntry("lib/armeabi-v7a/libtest.so", elfContent)
        val findings = differ.analyze(apk, listOf("lib/armeabi-v7a/libtest.so"))
        // Minimal ELF has no sections, so no findings expected — but the key is no crash
        assertNotNull("Analyzer should process zip entries without crashing", findings)
    }

    @Test
    fun intOverflowHandled() {
        // Create a valid ELF with section header that has: sh_size that overflows
        // when combined: fileOff + size > Long.MAX_VALUE
        // We test this by making a section with a huge size value
        val elfWithHugeSection = createElfWithHugeSizes()
        val apk = createApkWithLibEntry("lib/armeabi-v7a/libhuge.so", elfWithHugeSection)
        val findings = differ.analyze(apk, listOf("lib/armeabi-v7a/libhuge.so"))
        // Should not crash, even if overflow triggers exceptions — handle gracefully
        assertNotNull("Overflow scenarios should not crash the analyzer", findings)
    }

    @Test
    fun nonexistentZipEntry_skippedGracefully() {
        val apk = createApk()
        val findings = differ.analyze(apk, listOf("lib/armeabi-v7a/missing.so"))
        assertTrue("Missing zip entries should produce no findings", findings.isEmpty())
    }

    @Test
    fun zeroByteLibEntry_skipped() {
        val apk = tempFolder.newFile("zerolib.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(200))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/armeabi-v7a/libempty.so"))
            // No content written — entry size will be 0
            zip.closeEntry()
        }
        val findings = differ.analyze(apk, listOf("lib/armeabi-v7a/libempty.so"))
        assertTrue("Zero-byte entries should be skipped", findings.isEmpty())
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

    private fun createMinimalElf(): ByteArray {
        val data = ByteArray(64)
        data[0] = 0x7f
        data[1] = 'E'.code.toByte()
        data[2] = 'L'.code.toByte()
        data[3] = 'F'.code.toByte()
        data[4] = 2 // 64-bit
        data[5] = 1 // little endian
        return data
    }

    private fun createElfWithHugeSizes(): ByteArray {
        // 64-bit ELF with section header table pointing to very large offsets/sizes
        val data = ByteArray(512)
        data[0] = 0x7f
        data[1] = 'E'.code.toByte()
        data[2] = 'L'.code.toByte()
        data[3] = 'F'.code.toByte()
        data[4] = 2 // 64-bit
        data[5] = 1 // little endian
        data[6] = 1 // EV_CURRENT
        data[7] = 0 // ELFOSABI_SYSV

        // e_type = ET_REL (1)
        data[17] = 1
        // e_machine = EM_AARCH64 (183)
        data[19] = 0xB7.toByte()
        // e_entry = 0
        // e_phoff = 0
        // e_shoff = 0x40 (section header table at offset 64)
        data[40] = 0x40; data[41] = 0; data[42] = 0; data[43] = 0; data[44] = 0; data[45] = 0; data[46] = 0; data[47] = 0
        // e_flags = 0
        // e_ehsize = 64
        data[52] = 64
        // e_shentsize = 64 (section header entry size for 64-bit)
        data[58] = 64
        // e_shnum = 3 (enough entries to cause overflow check)
        data[60] = 3; data[61] = 0
        // e_shstrndx = 1

        // Section header entries at offset 0x40 (64)
        // Entry 0: SHT_NULL
        data[64] = 0; data[65] = 0  // sh_name
        data[68] = 0; data[69] = 0  // sh_type = SHT_NULL
        // Entry 1: .shstrtab
        data[128] = 0; data[129] = 0  // sh_name
        data[132] = 3; data[133] = 0  // sh_type = SHT_STRTAB
        // sh_flags = 0
        data[144] = 0x50; data[145] = 0; data[146] = 0; data[147] = 0; data[148] = 0; data[149] = 0; data[150] = 0; data[151] = 0  // sh_addr
        data[152] = 10; data[153] = 0; data[154] = 0; data[155] = 0; data[156] = 0; data[157] = 0; data[158] = 0; data[159] = 0  // sh_offset
        data[160] = 4; data[161] = 0; data[162] = 0; data[163] = 0; data[164] = 0; data[165] = 0; data[166] = 0; data[167] = 0  // sh_size
        // Entry 2: normal section with .text-like properties
        data[192] = 1; data[193] = 0  // sh_name
        data[196] = 1; data[197] = 0  // sh_type = SHT_PROGBITS
        data[200] = 0x06; data[201] = 0; data[202] = 0; data[203] = 0; data[204] = 0; data[205] = 0; data[206] = 0; data[207] = 0  // sh_flags (AX)
        // sh_addr
        data[208] = 0x00; data[209] = 0x10; data[210] = 0; data[211] = 0; data[212] = 0; data[213] = 0; data[214] = 0; data[215] = 0
        // sh_offset = small (within file)
        data[216] = 0x00; data[217] = 0x02; data[218] = 0; data[219] = 0; data[220] = 0; data[221] = 0; data[222] = 0; data[223] = 0
        // sh_size = huuuuuge (like 0xFFFFFFFFFFFFFFFF = -1L) — tests overflow
        data[224] = 0xFF.toByte(); data[225] = 0xFF.toByte(); data[226] = 0xFF.toByte(); data[227] = 0xFF.toByte()
        data[228] = 0xFF.toByte(); data[229] = 0xFF.toByte(); data[230] = 0xFF.toByte(); data[231] = 0xFF.toByte()

        return data
    }
}
