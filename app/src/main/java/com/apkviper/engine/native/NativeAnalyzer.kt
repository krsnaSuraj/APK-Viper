package com.apkviper.engine.native

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.util.zip.ZipFile

class NativeAnalyzer {

    // Symbol → description — used for raw detection
    private val suspiciousSymbols = listOf(
        "ptrace" to SymbolInfo("Anti-debugging (ptrace)", Severity.HIGH),
        "fork" to SymbolInfo("Process forking", Severity.HIGH),
        "execve" to SymbolInfo("Command execution", Severity.CRITICAL),
        "execvp" to SymbolInfo("Command execution", Severity.CRITICAL),
        "execl" to SymbolInfo("Command execution", Severity.CRITICAL),
        "system" to SymbolInfo("Shell command execution", Severity.CRITICAL),
        "popen" to SymbolInfo("Pipe command execution", Severity.CRITICAL),
        "dlopen" to SymbolInfo("Dynamic library loading", Severity.MEDIUM),
        "dlsym" to SymbolInfo("Dynamic symbol resolution", Severity.MEDIUM),
        "syscall" to SymbolInfo("Direct syscall", Severity.HIGH),
        "socket" to SymbolInfo("Network socket", Severity.MEDIUM),
        "connect" to SymbolInfo("Network connection", Severity.MEDIUM),
        "sendto" to SymbolInfo("Data send", Severity.MEDIUM),
        "recvfrom" to SymbolInfo("Data receive", Severity.MEDIUM),
        "mmap" to SymbolInfo("Memory mapping", Severity.MEDIUM),
        "mprotect" to SymbolInfo("Memory protection change", Severity.HIGH),
        "memcpy" to SymbolInfo("Memory copy", Severity.LOW),
        "strcpy" to SymbolInfo("String copy (buffer overflow risk)", Severity.MEDIUM),
        "sprintf" to SymbolInfo("String format (buffer overflow risk)", Severity.MEDIUM),
        "getenv" to SymbolInfo("Environment variable read", Severity.LOW),
        "setenv" to SymbolInfo("Environment variable set", Severity.MEDIUM),
        "unlink" to SymbolInfo("File deletion", Severity.MEDIUM),
        "readdir" to SymbolInfo("Directory enumeration", Severity.MEDIUM),
        "access" to SymbolInfo("File access check", Severity.LOW)
    )

    // Regex noise filter — compiler/metadata URLs that are NOT indicators
    private val noiseUrlPatterns = listOf(
        Regex(".*googlesource\\.com/toolchain.*"),
        Regex(".*crashpad\\.chromium\\.org.*"),
        Regex(".*chromium\\.googlesource\\.com.*"),
        Regex(".*llvm\\.org.*"),
        Regex(".*gcc\\.gnu\\.org.*"),
        Regex(".*sourceware\\.org.*"),
        Regex(".*android\\.googlesource\\.com.*"),
        Regex(".*android\\.com.*"),
        Regex(".*freedesktop\\.org.*"),
        Regex(".*github\\.com.*"),
        Regex(".*gitlab\\.com.*"),
        Regex(".*bitbucket\\.org.*"),
        Regex(".*kotlinlang\\.org.*"),
        Regex(".*developer\\.android\\.com.*"),
    )

    // Symbols that are NORMAL in essentially every native library (C runtime, networking,
    // string handling). Emitting these as findings is the #1 cause of false positives on
    // genuine apps (Unity, Firebase, gstreamer, etc.). They are only meaningful as part of
    // a corroborated malicious combination (see correlation engine below).
    private val benignNativeSymbols = setOf(
        "socket", "connect", "sendto", "recvfrom", "mmap", "memcpy", "strcpy",
        "sprintf", "getenv", "setenv", "unlink", "readdir", "access", "dlopen", "dlsym"
    )

    // Noise IP filter — internal/loopback, not web endpoints
    private val noiseIpPatterns = listOf(
        Regex("""^127\.0\.0\.\d+$"""),
        Regex("""^0\.0\.0\.0$"""),
        Regex("""^255\.255\.255\.255$"""),
        Regex("""^10\.\d+\.\d+\.\d+$"""),
        Regex("""^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$"""),
        Regex("""^192\.168\.\d+\.\d+$"""),
        Regex("""^169\.254\.\d+\.\d+$"""),
        Regex("""^0\.0\.0\.\d+$"""),
    )

    private data class SymbolInfo(val description: String, val severity: Severity)

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()

        if (decompiled.nativeLibs.isEmpty()) return findings

        // Group libs: whitelisted vs unknown
        val whitelistedLibs = decompiled.nativeLibs.filter { FrameworkWhitelist.match(it) != null }
        val unknownLibs = decompiled.nativeLibs.filter { FrameworkWhitelist.match(it) == null }

        if (whitelistedLibs.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.NATIVE, severity = Severity.INFO,
                title = "Known Framework Libraries",
                description = "${whitelistedLibs.size} libraries matched known frameworks: ${whitelistedLibs.joinToString(", ") { it.substringAfterLast('/') }}",
                details = "Symbols from these libraries are downgraded — standard framework behavior"
            ))
        }

        // Flag truly unknown libraries
        unknownLibs.forEach { libPath ->
            val libName = libPath.substringAfterLast('/').removeSuffix(".so")
            if (libName.length < 2 || libName.matches(Regex("^[a-z0-9]{20,}$"))) {
                findings.add(Finding(
                    category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                    title = "Unknown Obfuscated Native Library",
                    description = "Unidentified library with obfuscated name: ${libPath.substringAfterLast('/')}",
                    file = libPath
                ))
            }
        }

        return findings
    }

    /**
     * Deep scan with framework whitelisting and correlation engine.
     * Unknown library with system+fork+socket → potential payload dropper.
     * Framework library with same symbols → downgraded to INFO.
     */
    fun deepScan(apkFile: File, nativeLibs: List<String>, cachedLibBytes: Map<String, ByteArray> = emptyMap()): List<Finding> {
        val findings = mutableListOf<Finding>()

        ZipFile(apkFile).use { zip ->
            // Per-library data for correlation
            data class LibAnalysis(
                val path: String,
                val isFramework: Boolean,
                val frameworkName: String?,
                val foundSymbols: MutableMap<String, Severity> = mutableMapOf(),
                val foundUrls: MutableList<String> = mutableListOf(),
                val foundIps: MutableList<String> = mutableListOf(),
                val entropy: Double = 0.0
            )

            val libAnalyses = nativeLibs.mapNotNull { libPath ->
                try {
                    val entry = zip.getEntry(libPath) ?: return@mapNotNull null
                    if (entry.size > 50 * 1024 * 1024) return@mapNotNull null
                    val bytes = cachedLibBytes[libPath] ?: zip.getInputStream(entry).readBytes()
                    val fw = FrameworkWhitelist.match(libPath)
                    val strings = extractStrings(bytes)
                    val lower = strings.lowercase()

                    val analysis = LibAnalysis(
                        path = libPath,
                        isFramework = fw != null,
                        frameworkName = fw?.name,
                        entropy = calculateEntropy(bytes)
                    )

                    // Detect symbols with severity override based on framework
                    suspiciousSymbols.forEach { (symbol, info) ->
                        if (lower.contains(symbol.lowercase())) {
                            val override = if (fw != null) {
                                FrameworkWhitelist.getSymbolSeverityOverride(symbol, libPath)
                            } else FrameworkWhitelist.SymbolOverride.USE_ORIGINAL

                            analysis.foundSymbols[symbol] = when (override) {
                                FrameworkWhitelist.SymbolOverride.DOWNGRADE_TO_INFO -> Severity.INFO
                                FrameworkWhitelist.SymbolOverride.DOWNGRADE_TO_LOW -> Severity.LOW
                                else -> info.severity
                            }
                        }
                    }

                    // Find URLs — filtered against noise patterns
                    val urlPattern = Regex("""https?://[^\s"'<>]+""")
                    urlPattern.findAll(strings).take(10).forEach { match ->
                        val url = match.value
                        val isNoise = noiseUrlPatterns.any { p -> p.matches(url) }
                        if (!isNoise) analysis.foundUrls.add(url)
                    }

                    // Find IPs — filtered against noise patterns
                    val ipPattern = Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""")
                    ipPattern.findAll(strings).take(10).forEach { match ->
                        val ip = match.value
                        val isNoise = noiseIpPatterns.any { p -> p.matches(ip) }
                        if (!isNoise) analysis.foundIps.add(ip)
                    }

                    analysis
                } catch (e: Exception) {
                    null
                }
            }

            // Per-library findings
            libAnalyses.forEach { analysis ->
                val libName = analysis.path.substringAfterLast('/')

                // Log framework context
                if (analysis.isFramework) {
                    findings.add(Finding(
                        category = FindingCategory.NATIVE, severity = Severity.INFO,
                        title = "${analysis.frameworkName}: $libName",
                        description = "Framework library — ${analysis.foundSymbols.size} standard symbols downgraded",
                        file = analysis.path
                    ))
                }

                // Only emit symbol findings that are genuinely meaningful. Common C-runtime /
                // networking symbols (socket, connect, memcpy, strcpy, dlopen, ...) are skipped
                // for non-framework libs — they appear in virtually every native library and
                // were the main source of false "Command & Control / Buffer Overflow" findings.
                analysis.foundSymbols.entries
                    .filter { !analysis.isFramework || it.value.ordinal >= Severity.HIGH.ordinal }
                    .filter { !(analysis.isFramework && it.value.ordinal < Severity.HIGH.ordinal) }
                    .filter { !(symbolIsBenign(it.key) && !analysis.isFramework) }
                    .forEach { (symbol, severity) ->
                        val effectiveSeverity = if (!analysis.isFramework) severity.coerceAtMost(Severity.MEDIUM) else severity
                        val desc = suspiciousSymbols.find { it.first == symbol }?.second?.description ?: symbol
                        findings.add(Finding(
                            category = FindingCategory.NATIVE, severity = effectiveSeverity,
                            title = "Native Symbol: $desc",
                            description = "$symbol in $libName${if (analysis.isFramework) " [Framework: ${analysis.frameworkName}]" else ""}",
                            file = analysis.path
                        ))
                    }

                // URL findings for non-framework libs only — informational, NOT malware evidence
                // on its own (many genuine apps hardcode CDN/API endpoints in native strings).
                if (!analysis.isFramework) {
                    analysis.foundUrls.take(3).forEach { url ->
                        findings.add(Finding(
                            category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                            title = "Hardcoded URL in Native Code",
                            description = url,
                            file = analysis.path
                        ))
                    }
                    analysis.foundIps.take(3).forEach { ip ->
                        findings.add(Finding(
                            category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                            title = "Hardcoded IP in Native Code",
                            description = ip,
                            file = analysis.path
                        ))
                    }
                }

                // High entropy for unknown libs — informational. Real packing needs unpacking
                // stubs AND corroboration (see EntropyPackerDetector); a high-entropy .so alone is
                // common for legit native libraries (game engines, media frameworks).
                if (!analysis.isFramework && analysis.entropy > 7.5) {
                    findings.add(Finding(
                        category = FindingCategory.NATIVE, severity = Severity.LOW,
                        title = "High Entropy Native Payload",
                        description = "$libName entropy: ${"%.2f".format(analysis.entropy)} — unknown library with high entropy (investigate if combined with packer stubs)",
                        file = analysis.path
                    ))
                }
            }

            // CORRELATION ENGINE — cross-library threat detection
            // Only analyze non-framework libraries
            val unknownAnalyses = libAnalyses.filter { !it.isFramework }

            for (analysis in unknownAnalyses) {
                val symbols = analysis.foundSymbols.map { it.key.lowercase() }.toSet()
                val libName = analysis.path.substringAfterLast('/')

                // Rule: execution capability + network capability in single unknown lib
                val hasExec = symbols.any { it in setOf("system", "execve", "execvp", "execl", "popen", "fork", "syscall") }
                val hasNet = symbols.any { it in setOf("socket", "connect", "sendto", "recvfrom") }
                val hasInject = symbols.any { it in setOf("ptrace", "dlopen", "dlsym", "mprotect") }

                if (hasExec && hasNet) {
                    val execSymbols = symbols.filter { it in setOf("system", "execve", "execvp", "execl", "popen") }.joinToString(", ")
                    val netSymbols = symbols.filter { it in setOf("socket", "connect", "sendto", "recvfrom") }.joinToString(", ")
                    findings.add(Finding(
                        category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                        title = "Reverse Shell Capability (Native)",
                        description = "Unknown lib $libName has execution ($execSymbols) AND network ($netSymbols) — potential reverse shell or payload dropper",
                        details = "This combination in an unidentified binary is suspicious; correlate with other engines (YARA / hash / C2 IOC) before concluding malware",
                        file = analysis.path
                    ))
                }

                // Rule: execution + process injection in single unknown lib
                if (hasExec && hasInject) {
                    findings.add(Finding(
                        category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                        title = "Code Injection + Execution (Native)",
                        description = "Unknown lib $libName combines process injection with command execution — advanced malware pattern",
                        file = analysis.path
                    ))
                }

                // Rule: network + high entropy + unknown = encrypted C2 payload (informational
                // unless corroborated by another engine — never alone a verdict driver)
                if (hasNet && analysis.entropy > 7.0) {
                    findings.add(Finding(
                        category = FindingCategory.NATIVE, severity = Severity.MEDIUM,
                        title = "Encrypted C2 Payload (Native)",
                        description = "Unknown lib $libName has networking AND high entropy (${"%.1f".format(analysis.entropy)}) — likely encrypted C2 logic",
                        file = analysis.path
                    ))
                }
            }
        }

        return findings
    }

    private fun symbolIsBenign(symbol: String): Boolean = symbol.lowercase() in benignNativeSymbols

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

    private fun calculateEntropy(data: ByteArray): Double {
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
}