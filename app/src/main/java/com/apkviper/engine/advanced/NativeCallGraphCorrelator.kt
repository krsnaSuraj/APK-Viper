package com.apkviper.engine.advanced

import com.apkviper.engine.native.FrameworkWhitelist
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.util.zip.ZipFile

/**
 * Native API Call-Graph Correlation — tracks the SEQUENCE of imported API calls
 * across native libraries. A single "system" or "socket" isn't suspicious,
 * but socket→connect→dup2→execve IS a definitive reverse shell chain.
 */
class NativeCallGraphCorrelator {

    // Critical call chains — the ORDER matters
    private val maliciousChains = listOf(
        // Reverse shell: socket → connect → dup2 stdin/stdout/stderr → execve shell
        CallChain(
            name = "Reverse Shell Chain",
            severity = Severity.CRITICAL,
            sequence = listOf("socket", "connect", "dup2", "execve"),
            description = "Socket opened → connected to remote host → redirected stdio → executed shell. Definitive reverse shell pattern."
        ),
        // Bind shell: socket → bind → listen → accept → dup2 → execve
        CallChain(
            name = "Bind Shell Chain",
            severity = Severity.CRITICAL,
            sequence = listOf("socket", "bind", "listen", "accept", "execve"),
            description = "Socket bound to port → listens → accepts connection → executes shell. Definitive bind shell."
        ),
        // Privilege escalation: ptrace → attach → get_regs → set_regs → detach
        CallChain(
            name = "Ptrace-based Injection Chain",
            severity = Severity.CRITICAL,
            sequence = listOf("ptrace", "PTRACE_ATTACH", "PTRACE_GETREGS", "PTRACE_SETREGS", "PTRACE_POKEDATA"),
            description = "Process attached → registers read → modified → injected. Code injection via ptrace."
        ),
        // Payload decryption+execution: dlopen → dlsym → mmap → mprotect → call
        CallChain(
            name = "Runtime Payload Decryption & Execution",
            severity = Severity.CRITICAL,
            sequence = listOf("dlopen", "dlsym", "mmap", "mprotect", "call"),
            description = "Lib loaded → symbol resolved → memory mapped → protection changed → executed. Runtime code injection."
        ),
        // Fileless dropper: pipe → fork → execve (parent/child) → connect back
        CallChain(
            name = "Fileless Dropper Chain",
            severity = Severity.CRITICAL,
            sequence = listOf("fork", "pipe", "execve", "connect"),
            description = "Process forked → pipes created → child executes → connects back. Fileless persistent dropper."
        ),
        // DNS tunnel: socket → gethostbyname → connect → send/sendto in loop
        CallChain(
            name = "DNS Tunneling Chain",
            severity = Severity.CRITICAL,
            sequence = listOf("gethostbyname", "socket", "connect", "send"),
            description = "DNS resolved → socket created → connected → data sent. DNS tunneling for C2."
        ),
    )

    private data class CallChain(
        val name: String,
        val severity: Severity,
        val sequence: List<String>,
        val description: String
    )

    fun analyze(apkFile: File, nativeLibs: List<String>, cachedLibBytes: Map<String, ByteArray> = emptyMap()): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allImports = mutableMapOf<String, MutableList<String>>() // libPath → list of imported symbols

        ZipFile(apkFile).use { zip ->
            for (libPath in nativeLibs) {
                try {
                    val entry = zip.getEntry(libPath) ?: continue
                    val bytes = cachedLibBytes[libPath] ?: zip.getInputStream(entry).readBytes()
                    val strings = extractStrings(bytes).lowercase()
                    val importsForLib = mutableListOf<String>()

                    // Extract imported symbols (stripped of leading underscores)
                    val importLines = strings.lines()
                        .filter { it.length in 2..40 && it.all { c -> c.isLetterOrDigit() || c == '_' } }
                        .map { it.removePrefix("_").lowercase() }

                    importsForLib.addAll(importLines)
                    allImports[libPath] = importsForLib
                } catch (_: Exception) {
                    continue
                }
            }
        }

        // Check each library against known malicious call chains
        for ((libPath, imports) in allImports) {
            val isFramework = FrameworkWhitelist.match(libPath) != null
            if (isFramework) continue // Skip framework libraries

            val libName = libPath.substringAfterLast('/')

            for (chain in maliciousChains) {
                // Check if all symbols in the chain are present in this library
                val allPresent = chain.sequence.all { symbol ->
                    imports.any { imported -> imported.contains(symbol.lowercase()) }
                }

                if (allPresent) {
                    findings.add(Finding(
                        category = FindingCategory.NATIVE,
                        severity = chain.severity,
                        title = "CRITICAL: ${chain.name}",
                        description = "Unknown library $libName contains the complete ${chain.name.lowercase()} call chain",
                        details = "${chain.description}\nChain: ${chain.sequence.joinToString(" → ")}",
                        file = libPath
                    ))
                }
            }
        }

        // Cross-library correlation: if one lib opens sockets and another calls execve,
        // that's suspicious even if not in the same binary
        val libsWithNetworking = allImports.filter { (_, imports) ->
            imports.any { it.contains("socket") || it.contains("connect") }
        }.keys
        val libsWithExecution = allImports.filter { (_, imports) ->
            imports.any { it.contains("execve") || it.contains("system") || it.contains("fork") }
        }.keys

        if (libsWithNetworking.isNotEmpty() && libsWithExecution.isNotEmpty()) {
            // Check if either set contains unknown (non-framework) libraries
            val unknownNetLibs = libsWithNetworking.filter { FrameworkWhitelist.match(it) == null }
            val unknownExecLibs = libsWithExecution.filter { FrameworkWhitelist.match(it) == null }

            if (unknownNetLibs.isNotEmpty() && unknownExecLibs.isNotEmpty()) {
                findings.add(Finding(
                    category = FindingCategory.NATIVE,
                    severity = Severity.CRITICAL,
                    title = "Cross-Library C2 Architecture",
                    description = "Networking in unknown libs (${unknownNetLibs.joinToString { it.substringAfterLast('/') }}) + execution in unknown libs (${unknownExecLibs.joinToString { it.substringAfterLast('/') }})",
                    details = "Malware often splits networking and execution across separate libraries to evade single-file detection"
                ))
            }
        }

        return findings
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
