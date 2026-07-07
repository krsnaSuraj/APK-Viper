package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.util.zip.ZipFile

class NativeBehaviorAnalyzer {

    data class NativeSignature(
        val id: String,
        val description: String,
        val category: String,
        val severity: Severity,
        val bytePatterns: List<ByteArray>,
        val stringPatterns: List<String>,
        val sectionCheck: ((String, ByteArray) -> Boolean)? = null
    )

    private val signatures = listOf(
        // CAPA-style behavioral signatures from Google 2025 research
        NativeSignature(
            id = "NAT-001", description = "ptrace process injection",
            category = "Process Injection", severity = Severity.CRITICAL,
            bytePatterns = emptyList(),
            stringPatterns = listOf("ptrace", "PTRACE_ATTACH", "PTRACE_POKETEXT")
        ),
        NativeSignature(
            id = "NAT-002", description = "JNI remote code download + dexload",
            category = "Remote Code Execution", severity = Severity.HIGH,
            bytePatterns = emptyList(),
            stringPatterns = listOf("DexClassLoader", "openConnection", "HttpGet", "downloadFile"),
            sectionCheck = { _, bytes ->
                val text = String(bytes).lowercase()
                text.contains("dexclassloader") && (text.contains("http") || text.contains("https"))
            }
        ),
        NativeSignature(
            id = "NAT-003", description = "Device information harvesting via JNI",
            category = "Information Theft", severity = Severity.MEDIUM,
            bytePatterns = emptyList(),
            stringPatterns = listOf("getDeviceId", "getSubscriberId", "getLine1Number", "getMacAddress"),
            sectionCheck = { _, bytes ->
                val text = String(bytes).lowercase()
                val count = listOf("getdeviceid", "getsubscriberid", "getline1number", "getmacaddress")
                    .count { text.contains(it) }
                count >= 2
            }
        ),
        NativeSignature(
            id = "NAT-004", description = "Cryptocurrency mining via native code",
            category = "Crypto Mining", severity = Severity.HIGH,
            bytePatterns = listOf(
                byteArrayOf(0x6E, 0x2E, 0x73, 0x74, 0x72, 0x61, 0x74, 0x75, 0x6D), // "n.stratum"
                byteArrayOf(0x63, 0x6E, 0x2F, 0x68, 0x65, 0x61, 0x76, 0x79, 0x2F, 0x78, 0x68, 0x76) // "cn/heavy/xhv"
            ),
            stringPatterns = listOf("stratum", "mining", "cryptonight", "randomx", "kawpow", "rx/0")
        ),
        NativeSignature(
            id = "NAT-005", description = "Native socket-based C2 communication",
            category = "Command & Control", severity = Severity.HIGH,
            bytePatterns = emptyList(),
            stringPatterns = listOf("connect", "send", "recv", "socket"),
            sectionCheck = { _, bytes ->
                val text = String(bytes).lowercase()
                val count = listOf("connect(", "send(", "recv(", "socket(", "gethostbyname")
                    .count { text.contains(it) }
                count >= 3
            }
        ),
        NativeSignature(
            id = "NAT-006", description = "Dynamic linker hijack (LD_PRELOAD style)",
            category = "Persistence", severity = Severity.HIGH,
            bytePatterns = emptyList(),
            stringPatterns = listOf("LD_PRELOAD", "dlopen", "dlsym", "RTLD_NEXT")
        ),
        NativeSignature(
            id = "NAT-007", description = "Memory region manipulation",
            category = "Anti-Debugging", severity = Severity.MEDIUM,
            bytePatterns = listOf(
                byteArrayOf(0x00, 0x00, 0x00, 0x19.toByte()), // ARM64 SVC #0x19 = mprotect
                byteArrayOf(0x00, 0x00, 0x00, 0x1E.toByte())  // ARM64 SVC #0x1E = mmap
            ),
            stringPatterns = listOf("mprotect", "mmap", "memfd_create")
        ),
        NativeSignature(
            id = "NAT-008", description = "Anti-debugging / anti-analysis",
            category = "Anti-Debugging", severity = Severity.MEDIUM,
            bytePatterns = emptyList(),
            stringPatterns = listOf("isDebuggerConnected", "Debug.isDebuggerConnected",
                "/proc/self/status", "TracerPid", "frida", "substrate", "xposed")
        ),
        NativeSignature(
            id = "NAT-009", description = "Native code obfuscation (OLLVM indicators)",
            category = "Obfuscation", severity = Severity.LOW,
            bytePatterns = emptyList(),
            stringPatterns = listOf("__afl", "asan", "ubsan", "msan", "bcf", "fla", "split", "sub")
        ),
        NativeSignature(
            id = "NAT-010", description = "CPU miner affinity + thread pooling",
            category = "Crypto Mining", severity = Severity.MEDIUM,
            bytePatterns = emptyList(),
            stringPatterns = listOf("sched_setaffinity", "pthread_create", "num_cores", "max_threads")
        )
    )

    fun analyze(decompiled: DecompileResult, apkFile: File): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (decompiled.nativeLibs.isEmpty()) return findings

        try {
            val cachedLibBytes = decompiled.nativeLibBytes
            ZipFile(apkFile).use { zip ->
                for (libPath in decompiled.nativeLibs) {
                    val entry = zip.getEntry(libPath) ?: continue
                    if (entry.size > 20 * 1024 * 1024 || entry.size == 0L || entry.size == -1L) continue

                    try {
                        val bytes = cachedLibBytes[libPath] ?: zip.getInputStream(entry).readBytes()
                        val text = String(bytes).lowercase()
                        val libName = libPath.substringAfterLast('/')

                        for (sig in signatures) {
                            var matched = false

                            for (pattern in sig.bytePatterns) {
                                if (bytes.size >= pattern.size) {
                                    var i = 0
                                    while (i <= bytes.size - pattern.size && !matched) {
                                        matched = (0 until pattern.size).all { bytes[i + it] == pattern[it] }
                                        i++
                                    }
                                }
                            }

                            if (!matched) {
                                for (sp in sig.stringPatterns) {
                                    if (text.contains(sp.lowercase())) {
                                        matched = true
                                        break
                                    }
                                }
                            }

                            if (!matched && sig.sectionCheck != null) {
                                matched = sig.sectionCheck.invoke(libName, bytes)
                            }

                            if (matched) {
                                findings.add(Finding(
                                    category = FindingCategory.NATIVE,
                                    severity = sig.severity,
                                    title = "[${sig.id}] ${sig.description}",
                                    description = "Detected in native library: $libName (${sig.category})"
                                ))
                                break
                            }
                        }
                    } catch (e: Exception) {
                        continue
                    }
                }
            }
        } catch (e: Exception) {
            findings.add(Finding(FindingCategory.NATIVE, Severity.INFO,
                "Native analysis error", e.message ?: "Unknown"))
        }

        return findings
    }
}
