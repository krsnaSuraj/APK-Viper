package com.apkviper.engine.advanced

import com.apkviper.dex.DexParser
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class OpcodeNgramAnalyzerTest {
    private val analyzer = OpcodeNgramAnalyzer()

    @Rule @JvmField val tempFolder = TemporaryFolder()

    @Test
    fun nonExistentApk_noFindings() {
        assertTrue(analyzer.analyze(File("nonexistent.apk")).isEmpty())
    }

    @Test
    fun emptyApk_noFindings() {
        val apk = tempFolder.newFile("empty.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
        }
        assertTrue(analyzer.analyze(apk).isEmpty())
    }

    @Test
    fun opcodesTooFew_noFindings() {
        val apk = tempFolder.newFile("min.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            val dexHeader = ByteArray(40)
            dexHeader[0] = 0x64; dexHeader[1] = 0x65
            dexHeader[2] = 0x78; dexHeader[3] = 0x0A
            zip.write(dexHeader)
            zip.closeEntry()
        }
        val findings = analyzer.analyze(apk)
        assertTrue(findings.isEmpty())
    }

    @Test
    fun emptyOpcodeList_returnsNoFindings() {
        val apk = tempFolder.newFile("empty_op.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
        }
        assertTrue(analyzer.analyze(apk).isEmpty())
    }

    @Test
    fun veryShortOpcodeList_returnsNoFindings() {
        val apk = tempFolder.newFile("short.apk")
        val dexBytes = buildMinimalDex(
            insns = byteArrayOf(0x00, 0x00) // single nop = 1 code unit, too few opcodes
        )
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(dexBytes)
            zip.closeEntry()
        }
        assertTrue(analyzer.analyze(apk).isEmpty())
    }

    @Test
    fun patternThreshold_threeOfFourMatching_notMalicious() {
        val apk = tempFolder.newFile("thresh_match.apk")
        // Instructions: const-string(0x1A), invoke-virtual(0x6E), move-result-object(0x0C), nop(0x00)
        // Repeated to get >=10 opcodes. This resembles (but does NOT exactly match) a known
        // malware N-gram pattern. With strict exact-match matching this must NOT produce a
        // MALWARE/CRITICAL finding — proving the old fuzzy 3/4 match no longer false-positives.
        val opcodes = byteArrayOf(
            0x1A, 0x00, 0x00, 0x00,  // const-string v0
            0x6E.toByte(), 0x10, 0x00, 0x00, 0x00, 0x00, // invoke-virtual {v0}
            0x0C, 0x00,              // move-result-object v0
            0x00, 0x00,              // nop
            0x1A, 0x00, 0x00, 0x00,  // const-string v0
            0x6E.toByte(), 0x10, 0x00, 0x00, 0x00, 0x00, // invoke-virtual {v0}
            0x0C, 0x00,              // move-result-object v0
            0x00, 0x00,              // nop
            0x1A, 0x00, 0x00, 0x00,  // const-string v0
            0x6E.toByte(), 0x10, 0x00, 0x00, 0x00, 0x00, // invoke-virtual {v0}
            0x0C, 0x00,              // move-result-object v0
            0x00, 0x00,              // nop
        )
        val dexBytes = buildMinimalDex(insns = opcodes)
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(dexBytes)
            zip.closeEntry()
        }
        val findings = analyzer.analyze(apk)
        assertTrue(
            "Benign-looking opcode sequence must NOT yield a MALWARE/CRITICAL finding, got ${findings.size} findings",
            findings.none { it.category == FindingCategory.MALWARE && it.severity == Severity.CRITICAL }
        )
    }

    @Test
    fun patternThreshold_oneOfFourMatching_noFinding() {
        val apk = tempFolder.newFile("thresh_nomatch.apk")
        // Instructions: const-string(0x1A) then nops repeated — only 1/4 matches any pattern
        val opcodes = byteArrayOf(
            0x1A, 0x00, 0x00, 0x00,  // const-string v0
            0x00, 0x00,              // nop
            0x00, 0x00,              // nop
            0x00, 0x00,              // nop
            0x1A, 0x00, 0x00, 0x00,  // const-string v0
            0x00, 0x00,              // nop
            0x00, 0x00,              // nop
            0x00, 0x00,              // nop
            0x1A, 0x00, 0x00, 0x00,  // const-string v0
            0x00, 0x00,              // nop
            0x00, 0x00,              // nop
            0x00, 0x00,              // nop
        )
        val dexBytes = buildMinimalDex(insns = opcodes)
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(dexBytes)
            zip.closeEntry()
        }
        val findings = analyzer.analyze(apk)
        assertTrue(
            "Expected no findings for 1/4 threshold match, got ${findings.size}",
            findings.isEmpty()
        )
    }

    @Test
    fun nonMatchingOpcodes_producesNoFindings() {
        val apk = tempFolder.newFile("nonmatch.apk")
        // All nops — no opcode matches any pattern
        val opcodes = ByteArray(24) { 0x00 } // 12 nop instructions
        val dexBytes = buildMinimalDex(insns = opcodes)
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write("<manifest/>".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(dexBytes)
            zip.closeEntry()
        }
        val findings = analyzer.analyze(apk)
        assertTrue(
            "Expected no findings for non-matching opcodes, got ${findings.size}",
            findings.isEmpty()
        )
    }

    // ---- DEX builder helpers ----

    private fun buildMinimalDex(insns: ByteArray): ByteArray {
        if (insns.isEmpty()) {
            return buildHeaderOnlyDex()
        }
        val insnsSize = insns.size / 2
        val strData = buildStringData()
        val classDataSize = 8
        val codeItemSize = 16 + insns.size
        val stringDataStart = 0xB8 + classDataSize + codeItemSize
        val totalSize = stringDataStart + strData.size

        val buf = buildHeader(totalSize, stringDataStart)
        // String IDs (offset 0x70)
        writeInt(buf, 0x70, stringDataStart + 0)  // "V"
        writeInt(buf, 0x74, stringDataStart + 2)  // "test"
        writeInt(buf, 0x78, stringDataStart + 7)  // "LTest;"
        // Type IDs (offset 0x7C)
        writeInt(buf, 0x7C, 2)  // type 0 -> string idx 2 (LTest;)
        writeInt(buf, 0x80, 0)  // type 1 -> string idx 0 (V)
        // Proto IDs (offset 0x84)
        writeInt(buf, 0x84, 0)  // shorty_idx=0
        writeInt(buf, 0x88, 1)  // return_type_idx=1
        writeInt(buf, 0x8C, 0)  // params_off=0
        // Method IDs (offset 0x90)
        buf[0x90] = 0; buf[0x91] = 0  // class_idx=0
        buf[0x92] = 0; buf[0x93] = 0  // proto_idx=0
        writeInt(buf, 0x94, 1)         // name_idx=1 (test)
        // Class Def (offset 0x98)
        writeInt(buf, 0x98, 0)         // class_idx=0
        writeInt(buf, 0x9C, 1)         // access_flags=public
        writeInt(buf, 0xA0, -1)        // superclass_idx=NO_INDEX
        writeInt(buf, 0xA4, 0)         // interfaces_off=0
        writeInt(buf, 0xA8, -1)        // source_file_idx=NO_INDEX
        writeInt(buf, 0xAC, 0)         // annotations_off=0
        writeInt(buf, 0xB0, 0xB8)      // class_data_off
        writeInt(buf, 0xB4, 0)         // static_values_off=0
        // Class Data (offset 0xB8)
        buf[0xB8] = 0; buf[0xB9] = 0; buf[0xBA] = 0; buf[0xBB] = 1 // counts
        buf[0xBC] = 0; buf[0xBD] = 1                                 // method_idx_delta=0, access_flags=1
        // code_off ULEB128:
        val codeOff = 0xC0
        if (codeOff < 128) {
            buf[0xBE] = codeOff.toByte()
        } else {
            buf[0xBE] = (codeOff or 0x80).toByte()
            buf[0xBF] = (codeOff shr 7).toByte()
        }
        // Code Item (offset codeOff = 0xC0)
        val ci = codeOff
        writeShort(buf, ci, 1)      // registers=1
        writeShort(buf, ci + 2, 1)  // ins=1
        writeShort(buf, ci + 4, 0)  // outs=0
        writeShort(buf, ci + 6, 0)  // tries=0
        writeInt(buf, ci + 8, 0)    // debug_info_off=0
        writeInt(buf, ci + 12, insnsSize)  // insns_size
        insns.copyInto(buf, ci + 16)  // instructions
        // String data
        strData.copyInto(buf, stringDataStart)

        return buf
    }

    private fun buildHeaderOnlyDex(): ByteArray {
        val totalSize = 112
        return buildHeader(totalSize, totalSize)
    }

    private fun buildHeader(totalSize: Int, dataOff: Int): ByteArray {
        val buf = ByteArray(totalSize)
        // Magic: dex\n035\0
        buf[0] = 0x64; buf[1] = 0x65; buf[2] = 0x78; buf[3] = 0x0A
        buf[4] = 0x30; buf[5] = 0x33; buf[6] = 0x35; buf[7] = 0x00
        // Checksum = 0, signature = zeros
        // file_size
        writeInt(buf, 32, totalSize)
        writeInt(buf, 36, 112)           // header_size
        writeInt(buf, 40, 0x12345678)    // endian_tag
        // link = 0
        writeInt(buf, 56, 3)             // string_ids_size
        writeInt(buf, 60, 0x70)          // string_ids_off
        writeInt(buf, 64, 2)             // type_ids_size
        writeInt(buf, 68, 0x7C)          // type_ids_off
        writeInt(buf, 72, 1)             // proto_ids_size
        writeInt(buf, 76, 0x84)          // proto_ids_off
        writeInt(buf, 80, 0)             // field_ids_size
        writeInt(buf, 84, 0)             // field_ids_off
        writeInt(buf, 88, 1)             // method_ids_size
        writeInt(buf, 92, 0x90)          // method_ids_off
        writeInt(buf, 96, 1)             // class_defs_size
        writeInt(buf, 100, 0x98)         // class_defs_off
        writeInt(buf, 104, totalSize - dataOff)
        writeInt(buf, 108, dataOff)      // data_off
        return buf
    }

    private fun buildStringData(): ByteArray {
        return byteArrayOf(
            'V'.code.toByte(), 0,
            't'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), 0,
            'L'.code.toByte(), 'T'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), ';'.code.toByte(), 0
        )
    }

    private fun writeInt(buf: ByteArray, off: Int, value: Int) {
        buf[off] = (value and 0xFF).toByte()
        buf[off + 1] = (value shr 8 and 0xFF).toByte()
        buf[off + 2] = (value shr 16 and 0xFF).toByte()
        buf[off + 3] = (value shr 24 and 0xFF).toByte()
    }

    private fun writeShort(buf: ByteArray, off: Int, value: Int) {
        buf[off] = (value and 0xFF).toByte()
        buf[off + 1] = (value shr 8 and 0xFF).toByte()
    }

}
