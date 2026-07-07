package com.apkviper.engine.advanced

import com.apkviper.engine.native.FrameworkWhitelist
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.zip.ZipFile

/**
 * Entropy Analyzer & Packer Detector — Shannon entropy calculation
 * for all .so files and DEX components. Detects encrypted/compressed
 * payloads and identifies unpacking routine stubs.
 */
class EntropyPackerDetector {

    data class FileEntropy(val path: String, val entropy: Double, val size: Long, val category: String)

    // Unpacking routine patterns — symbols commonly found in packer stub code
    private val unpackingSymbols = listOf(
        "dlopen", "dlsym", "mmap", "mprotect", "memalign",
        "posix_memalign", "memcpy", "memmove", "memcmp",
        "calloc", "malloc", "realloc", "free",
        "memfd_create", "shm_open", "shm_unlink"
    )

    fun analyze(apkFile: File, nativeLibs: List<String>, cachedLibBytes: Map<String, ByteArray> = emptyMap()): List<Finding> {
        val findings = mutableListOf<Finding>()
        val entropyResults = mutableListOf<FileEntropy>()

        ZipFile(apkFile).use { zip ->
            // Analyze native libraries
            for (libPath in nativeLibs) {
                try {
                    val entry = zip.getEntry(libPath) ?: continue
                    val bytes = cachedLibBytes[libPath] ?: if (entry.size > 50_000_000) {
                        zip.getInputStream(entry).use { it.readBytesMax(50_000_000) }
                    } else {
                        zip.getInputStream(entry).use { it.readBytes() }
                    }
                    val entropy = calculateEntropy(bytes)
                    val strings = extractStrings(bytes).lowercase()
                    val libName = libPath.substringAfterLast('/')
                    val isFramework = FrameworkWhitelist.match(libPath) != null

                    entropyResults.add(FileEntropy(libPath, entropy, entry.size, if (isFramework) "framework" else "unknown"))

                    // Check unpacking stub symbols
                    val foundUnpackStubs = unpackingSymbols.filter { sym ->
                        strings.lines().any { line -> line.contains(sym) }
                    }

                    // High entropy (>7.2) in unknown library = encrypted payload
                    if (!isFramework && entropy > 7.2) {
                        val severity = if (entropy > 7.8) Severity.CRITICAL else Severity.HIGH

                        findings.add(Finding(
                            category = FindingCategory.PACKER,
                            severity = severity,
                            title = "Highly Encrypted Native Payload",
                            description = "$libName has entropy ${"%.2f".format(entropy)} — likely encrypted or compressed malware payload",
                            details = "Entropy above 7.2 indicates randomized/encrypted content typical of packed malware",
                            file = libPath
                        ))

                        // Check if unpacking stubs also present — extremely strong indicator
                        if (foundUnpackStubs.size >= 3) {
                            findings.add(Finding(
                                category = FindingCategory.PACKER,
                                severity = Severity.CRITICAL,
                                title = "Packed Payload with Unpacking Stubs",
                                description = "$libName has high entropy (${"%.2f".format(entropy)}) AND unpacking routine symbols: ${foundUnpackStubs.take(3).joinToString(", ")}",
                                details = "This is the definitive signature of runtime-packed malware: encrypted payload + dlopen/dlsym/mmap/mprotect stubs for runtime decryption",
                                file = libPath
                            ))
                        }
                    }

                    // Framework libraries with suspiciously high entropy
                    if (isFramework && entropy > 7.2) {
                        val sizeMB = entry.size / 1_000_000
                        val isExpectedSize = when {
                            libName.startsWith("libil2cpp") -> sizeMB in 15..60
                            libName.startsWith("libunity") -> sizeMB in 5..25
                            libName.startsWith("libflutter") -> sizeMB in 5..30
                            else -> sizeMB in 1..30
                        }

                        if (!isExpectedSize) {
                            findings.add(Finding(
                                category = FindingCategory.PACKER,
                                severity = Severity.HIGH,
                                title = "Tampered Framework: $libName",
                                description = "Framework library has abnormal size (${sizeMB}MB) AND high entropy — possible payload injected into known framework",
                                file = libPath
                            ))
                        }
                    }

                } catch (_: Exception) {
                    continue
                }
            }

            // Analyze DEX files for entropy anomalies
            val dexEntries = zip.entries().asSequence()
                .filter { it.name.endsWith(".dex") }
                .toList()

            for (dexEntry in dexEntries) {
                try {
                    val bytes = if (dexEntry.size > 50_000_000) {
                        zip.getInputStream(dexEntry).use { it.readBytesMax(50_000_000) }
                    } else {
                        zip.getInputStream(dexEntry).use { it.readBytes() }
                    }
                    val entropy = calculateEntropy(bytes)

                    if (entropy > 6.5) { // DEX files typically have lower entropy than native code
                        findings.add(Finding(
                            category = FindingCategory.PACKER,
                            severity = Severity.HIGH,
                            title = "High Entropy DEX: ${dexEntry.name}",
                            description = "DEX file has entropy ${"%.2f".format(entropy)} — unusual for DEX bytecode, may contain encrypted payload",
                            details = "Normal DEX entropy is typically below 6.0. Higher values indicate packing or data embedding."
                        ))
                    }
                    entropyResults.add(FileEntropy(dexEntry.name, entropy, dexEntry.size, "dex"))
                } catch (_: Exception) {
                    continue
                }
            }
        }

        // Cross-file entropy analysis
        val unknownHighEntropy = entropyResults
            .filter { it.category == "unknown" && it.entropy > 7.0 }
        val frameworkNormalEntropy = entropyResults
            .filter { it.category == "framework" && it.entropy < 7.0 }

        if (unknownHighEntropy.size >= 2 && frameworkNormalEntropy.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.CRITICAL,
                title = "Mixed-File Packing Architecture",
                description = "${unknownHighEntropy.size} unknown encrypted files alongside ${frameworkNormalEntropy.size} normal framework libs — malicious payload hidden among legitimate code",
                details = "Tactic: embed encrypted malware payloads next to clean framework libs to reduce suspicion"
            ))
        }

        return findings
    }

    fun calculateEntropy(data: ByteArray): Double {
        val freq = IntArray(256)
        data.forEach { freq[it.toInt() and 0xFF]++ }
        var entropy = 0.0
        val n = data.size.toDouble()
        freq.forEach { count ->
            if (count > 0) {
                val p = count / n
                entropy -= p * kotlin.math.ln(p) / kotlin.math.ln(2.0)
            }
        }
        return entropy
    }

    private fun extractStrings(data: ByteArray, minLen: Int = 4): String {
        val sb = StringBuilder()
        var current = StringBuilder()
        data.forEach { byte ->
            if (byte in 0x20..0x7E.toByte()) {
                current.append(byte.toInt().toChar())
            } else {
                if (current.length >= minLen) { sb.append(current.toString()).append('\n') }
                current = StringBuilder()
            }
        }
        if (current.length >= minLen) sb.append(current.toString())
        return sb.toString()
    }
}

internal fun InputStream.readBytesMax(maxBytes: Int): ByteArray {
    val buf = ByteArray(8192)
    val output = ByteArrayOutputStream(maxBytes)
    var total = 0
    while (total < maxBytes) {
        val remaining = maxBytes - total
        val chunkSize = buf.size.coerceAtMost(remaining)
        val read = this.read(buf, 0, chunkSize)
        if (read == -1) break
        output.write(buf, 0, read)
        total += read
    }
    return output.toByteArray()
}
