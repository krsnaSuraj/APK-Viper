package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

class NativeLibraryDiffer {

    data class ElfHeader(
        val entryPoint: Long,
        val programHeaderOffset: Long,
        val sectionHeaderOffset: Long,
        val programHeaderCount: Int,
        val sectionHeaderCount: Int,
        val shstrtabIndex: Int
    )

    data class SectionInfo(
        val name: String,
        val address: Long,
        val size: Long,
        val flags: Long,
        val type: Int
    )

    // Known framework library name prefixes used for downgrading severity
    private val knownFrameworkPrefixes = listOf("libunity", "libil2cpp", "libflutter", "libreactnative",
        "libmono", "libapplovin", "libcocos2d", "libgodot")

    // Known shellcode signatures that shouldn't appear in framework .so files
    private val shellcodePatterns = listOf(
        // ARM64: svc #0 after setting up execve / mprotect / ptrace
        hexToBytes("E0031F2AE1031F2A010000D4") to "ARM64 Double SVC Pattern",
        // ARM THUMB: system() call chain
        hexToBytes("00F000F8") to "THUMB Branch-to-System",
        // x86_64: int 0x80 (direct syscall to avoid libc hooking)
        hexToBytes("CD80") to "x86 Direct Syscall",
        // ARM64: adrp + add + br register (code stager)
        hexToBytes("00000090001FFD9160001FD6") to "ARM64 Code Stager Pattern",
        // ARM64 mprotect shellcode preamble
        hexToBytes("E20080D2E10380D2010000D4") to "ARM64 mprotect + exec Chain",
    )

    fun analyze(apkFile: File, nativeLibNames: List<String>): List<Finding> {
        val findings = mutableListOf<Finding>()

        try {
            ZipFile(apkFile).use { zip ->
                for (libName in nativeLibNames) {
                    val entry = zip.getEntry(libName) ?: continue
                    if (entry.size == 0L || entry.size > 50L * 1024 * 1024) continue
                    val libFile = try {
                        val bytes = zip.getInputStream(entry).readBytes()
                        val temp = File.createTempFile("nld_", ".so")
                        temp.writeBytes(bytes)
                        temp
                    } catch (_: Exception) { continue }

                    try {
                        processLib(libFile, libName, findings)
                    } finally {
                        libFile.delete()
                    }
                }
            }
        } catch (_: Exception) {}

        return findings
    }

    private fun processLib(libFile: File, libName: String, findings: MutableList<Finding>) {
        if (!isElfFile(libFile)) return

        val header = parseElfHeader(libFile) ?: return
        val sections = parseSectionHeaders(libFile, header) ?: return

        // Check against known frameworks
        val baseName = libName.split(".").first().lowercase()
        val knownFramework = knownFrameworkPrefixes.any { baseName.contains(it, ignoreCase = true) }

        // 1. Section size anomaly check
        val textSec = sections.find { it.name == ".text" }
        val rodatSec = sections.find { it.name == ".rodata" }

        if (knownFramework && textSec != null && rodatSec != null) {
            if (textSec.size > 0 && textSec.size < 4096) {
                findings.add(Finding(category = FindingCategory.NATIVE, severity = Severity.HIGH,
                    title = "Suspicious .text Section", description = "$libName text section is only ${textSec.size} bytes — possible stub or injection wrapper"))
            }
            if (textSec.size > 0 && rodatSec.size > 0) {
                val ratio = rodatSec.size.toFloat() / textSec.size.toFloat()
                if (ratio > 50f) {
                    findings.add(Finding(category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                        title = "Anomalous Data/Code Ratio", description = "$libName has ${rodatSec.size / 1024}KB rodata for ${textSec.size / 1024}KB code (${"%.0f".format(ratio)}:1). Possible packed data."))
                }
            }
        }

        // 2. Entry point anomaly
        if (header.entryPoint != 0L && header.entryPoint > libFile.length()) {
            findings.add(Finding(category = FindingCategory.NATIVE, severity = Severity.HIGH,
                title = "ELF Entry Point Mismatch", description = "$libName entry point 0x${header.entryPoint.toString(16)} exceeds file size. Likely tampered."))
        }

        // 3. Dynamic symbol count anomaly
        val dynsym = sections.find { it.name == ".dynsym" }
        val dynstr = sections.find { it.name == ".dynstr" }
        if (dynsym != null && dynstr != null && dynsym.size > 0) {
            val entrySize = 24L
            val symCount = (dynsym.size / entrySize).toInt()
            if (knownFramework && symCount < 3 && libFile.length() > 100_000) {
                findings.add(Finding(category = FindingCategory.NATIVE, severity = Severity.HIGH,
                    title = "Stripped/Anomalous Symbols", description = "$libName has only $symCount dynamic symbols despite ${libFile.length() / 1024}KB size. Symbols stripped or injection."))
            }
        }

        // 4. Shellcode byte-pattern scan
        val rawBytes = readFileBytes(libFile, 1024 * 64)
        for ((pattern, label) in shellcodePatterns) {
            if (containsPattern(rawBytes, pattern)) {
                findings.add(Finding(category = FindingCategory.NATIVE, severity = Severity.HIGH,
                    title = "Shellcode Pattern: $label", description = "Detected $label byte pattern in $libName. Possible injected payload."))
            }
        }

        // 5. Plt/Got anomaly
        val plt = sections.find { it.name == ".plt" }
        val got = sections.find { it.name == ".got" } ?: sections.find { it.name == ".got.plt" }
        if (plt != null && got != null && plt.size > 0 && got.size > 0) {
            if (got.size < plt.size) {
                findings.add(Finding(category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                    title = "GOT/PLT Size Mismatch", description = "$libName GOT (${got.size}) smaller than PLT (${plt.size}). Possible hooking."))
            }
        }
    }

    private fun isElfFile(file: File): Boolean {
        return try {
            RandomAccessFile(file, "r").use { raf ->
                if (raf.length() < 4) return false
                val magic = ByteArray(4)
                raf.read(magic)
                magic[0] == 0x7f.toByte() && magic[1] == 'E'.code.toByte() && magic[2] == 'L'.code.toByte() && magic[3] == 'F'.code.toByte()
            }
        } catch (_: Exception) { false }
    }

    private fun parseElfHeader(file: File): ElfHeader? {
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val buf = ByteArray(64)
                raf.read(buf)
                val bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
                val klass = buf[4].toInt() and 0xFF // 1=32-bit, 2=64-bit
                if (klass == 2) {
                    // ELF64
                    bb.position(24); val entry = bb.long
                    bb.position(32); val phoff = bb.long
                    bb.position(40); val shoff = bb.long
                    bb.position(54); val phnum = bb.short.toInt() and 0xFFFF
                    bb.position(60); val shnum = bb.short.toInt() and 0xFFFF
                    bb.position(62); val shstrndx = bb.short.toInt() and 0xFFFF
                    ElfHeader(entry, phoff, shoff, phnum, shnum, shstrndx)
                } else if (klass == 1) {
                    // ELF32
                    bb.position(24); val entry = bb.int.toLong() and 0xFFFFFFFFL
                    bb.position(28); val phoff = bb.int.toLong() and 0xFFFFFFFFL
                    bb.position(32); val shoff = bb.int.toLong() and 0xFFFFFFFFL
                    bb.position(44); val phnum = bb.short.toInt() and 0xFFFF
                    bb.position(48); val shnum = bb.short.toInt() and 0xFFFF
                    bb.position(50); val shstrndx = bb.short.toInt() and 0xFFFF
                    ElfHeader(entry, phoff, shoff, phnum, shnum, shstrndx)
                } else null
            }
        } catch (_: Exception) { null }
    }

    private fun parseSectionHeaders(file: File, header: ElfHeader): List<SectionInfo>? {
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val sections = mutableListOf<SectionInfo>()
                raf.seek(4); val is64Bit = raf.readByte() == 2.toByte()
                val shEntrySize = if (is64Bit) 64 else 40

                // Read section name string table
                val shstrtabNameOff = header.sectionHeaderOffset + header.shstrtabIndex.toLong() * shEntrySize
                var shstrtab = ByteArray(0)
                if (shstrtabNameOff + shEntrySize <= raf.length()) {
                    try {
                        raf.seek(shstrtabNameOff)
                        val buf = ByteArray(shEntrySize); raf.read(buf)
                        val bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
                        bb.int // name offset
                        bb.int // type
                        if (is64Bit) { bb.position(8); bb.long } else { bb.position(8); bb.int }
                        if (is64Bit) { bb.long } else { bb.int } // addr
                        bb.position(if (is64Bit) 32 else 20)
                        val size = (if (is64Bit) bb.long else bb.int.toLong() and 0xFFFFFFFFL).toInt()
                        val fileOff = (if (is64Bit) bb.long else bb.int.toLong() and 0xFFFFFFFFL).toInt()
                        if (fileOff > 0 && size > 0 && fileOff.toLong() + size.toLong() <= raf.length()) {
                            raf.seek(fileOff.toLong()); shstrtab = ByteArray(size); raf.readFully(shstrtab)
                        }
                    } catch (_: Exception) {}
                }

                for (i in 0 until header.sectionHeaderCount.coerceAtMost(200)) {
                    val offset = header.sectionHeaderOffset + i.toLong() * shEntrySize
                    if (offset + shEntrySize > raf.length()) break
                    raf.seek(offset)
                    val buf = ByteArray(shEntrySize)
                    raf.read(buf)
                    val bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)

                    val nameOffset = bb.int
                    val type = bb.int
                    val flags = if (is64Bit) { bb.position(8); bb.long } else { bb.position(8); bb.int.toLong() and 0xFFFFFFFFL }
                    val addr = if (is64Bit) { bb.long } else { bb.int.toLong() and 0xFFFFFFFFL }
                    bb.position(if (is64Bit) 32 else 20)
                    val size = if (is64Bit) { bb.long } else { bb.int.toLong() and 0xFFFFFFFFL }

                    val name = if (nameOffset in 0 until shstrtab.size) {
                        val end = (nameOffset until shstrtab.size).firstOrNull { shstrtab[it] == 0.toByte() } ?: shstrtab.size
                        if (end > nameOffset) String(shstrtab, nameOffset, end - nameOffset, Charsets.UTF_8) else "sect_$i"
                    } else "sect_$i"

                    sections.add(SectionInfo(name, addr, size, flags, type))
                }
                sections
            }
        } catch (_: Exception) { null }
    }

    private fun readFileBytes(file: File, maxBytes: Int): ByteArray {
        return try {
            val size = minOf(file.length(), maxBytes.toLong()).toInt()
            val buf = ByteArray(size)
            RandomAccessFile(file, "r").use { it.read(buf) }
            buf
        } catch (_: Exception) { ByteArray(0) }
    }

    private fun containsPattern(data: ByteArray, pattern: ByteArray): Boolean {
        if (pattern.size > data.size) return false
        outer@ for (i in 0..data.size - pattern.size) {
            for (j in pattern.indices) {
                if (data[i + j] != pattern[j]) continue@outer
            }
            return true
        }
        return false
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "").replace("\n", "")
        val result = ByteArray(clean.length / 2)
        for (i in result.indices) {
            result[i] = ((clean[i * 2].digitToInt(16) shl 4) + clean[i * 2 + 1].digitToInt(16)).toByte()
        }
        return result
    }
}
