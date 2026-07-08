package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.util.zip.ZipFile

class NativeBytecodeScanner {

    data class BytePattern(
        val name: String,
        val description: String,
        val severity: Severity,
        val bytes: ByteArray,
        val maxOffset: Int = 4096
    )

    private val patterns = listOf(
        // Socket setup: socket() → connect() — arm64 mov x0, #2; svc #0x198 (sys_socket)
        // Common in any app with a native networking layer — informational only.
        BytePattern("Socket Setup (ARM64)", "Raw socket() syscall bytecode detected in stripped native code",
            Severity.LOW, hexToBytes("200080D201000054"), maxOffset = 2048),
        // connect() syscall on arm64: mov x8, #203; svc #0
        BytePattern("Connect Syscall (ARM64)", "Raw connect() syscall — outbound network connection from native code",
            Severity.LOW, hexToBytes("E8B3A0F2010000D4"), maxOffset = 2048),
        // execve() or system() call chain on arm: bl system@plt pattern byte sequence
        // `bl` to a PLT stub is ubiquitous in native code — informational, not malicious by itself.
        BytePattern("Dynamic Code Execution (ARM)", "Native code execution pattern in stripped library",
            Severity.LOW, hexToBytes("0000009400000094"), maxOffset = 1024),
        // Process forking on ARM: fork() syscall pattern
        BytePattern("Process Fork (ARM)", "Fork syscall in stripped native code — process spawning",
            Severity.LOW, hexToBytes("0000A0E3000050E3"), maxOffset = 1024),
        // ARM THUMB inline hook trampoline: bx pc; nop; .word pattern — code injection capability.
        BytePattern("Inline Hook Trampoline (THUMB)", "Inline hooking/trampoline pattern — code injection capability",
            Severity.HIGH, hexToBytes("78F000F80000F8DF"), maxOffset = 512),
        // ptrace() anti-debugging on ARM: svc #26 (sys_ptrace) — mov r7, #26
        BytePattern("Anti-Debug Ptrace (ARM32)", "ptrace syscall in stripped native library — anti-debugging",
            Severity.LOW, hexToBytes("1A70A0E3000000EF"), maxOffset = 1024),
        // dlopen + dlsym dynamic loading: blx r3 pattern in THUMB after library name string
        BytePattern("Dynamic Library Load (dlopen)", "Dynamic native library loading in stripped binary",
            Severity.LOW, hexToBytes("9847"), maxOffset = 256),
        // ARM64 mprotect + memcpy shellcode loading pattern
        BytePattern("Memory Protection Change (ARM64)", "mprotect syscall — memory region protection modification in native code",
            Severity.MEDIUM, hexToBytes("E20080D201000054"), maxOffset = 2048),
        // open() syscall on ARM64: mov x8, #56; svc #0 — file access from native code
        BytePattern("File Open Syscall (ARM64)", "Raw open() syscall — file system access from native code",
            Severity.LOW, hexToBytes("0858A0F2010000D4"), maxOffset = 2048),
        // ARM32 AES encryption rounds — ARM v7 AES instructions
        BytePattern("AES Encryption Rounds (ARMv7)", "Hardware AES encryption instructions — crypto operations in native code",
            Severity.LOW, hexToBytes("0030B0F100C0B0F1"), maxOffset = 4096),
        // ARM32 getprop / property_get in native code
        BytePattern("System Property Access (ARM32)", "Direct Android property_get call in native code",
            Severity.LOW, hexToBytes("00802DE90030A0E1"), maxOffset = 1024),
        // x86_64 syscall instruction with common malware rax values — direct syscall bypasses libc.
        BytePattern("x86_64 Syscall Gateway", "Direct syscall instruction in x86_64 native code (bypassing libc)",
            Severity.MEDIUM, hexToBytes("0F05"), maxOffset = 256),
        // ARM64 getauxval / AT_HWCAP detection for exploit targeting
        BytePattern("Hardware Capability Probe (ARM64)", "getauxval(AT_HWCAP) in native code — hardware feature detection for exploit targeting",
            Severity.LOW, hexToBytes("600A00F0"), maxOffset = 1024),
        // ARM64 memfd_create — anonymous in-memory file for fileless execution (genuinely suspicious).
        BytePattern("memfd_create Syscall (ARM64)", "Anonymous file descriptor creation — fileless malware execution vector",
            Severity.HIGH, hexToBytes("FFFF000101000054"), maxOffset = 2048),
        // ARM64 process_vm_writev — cross-process memory injection.
        BytePattern("process_vm_writev (ARM64)", "Cross-process memory write — code injection or process hollowing",
            Severity.HIGH, hexToBytes("0000A0D2FFFF0001"), maxOffset = 2048),
        // ARM64 inotify_add_watch — file system monitoring for anti-analysis
        BytePattern("inotify_add_watch (ARM64)", "File system monitoring — anti-analysis or file stealing behavior",
            Severity.LOW, hexToBytes("0000A0D2E50080D2"), maxOffset = 2048),
        // ARM64 ptrace — process tracing for anti-debug or code injection
        BytePattern("ptrace Syscall (ARM64)", "Process tracing syscall — anti-debugging or process manipulation",
            Severity.MEDIUM, hexToBytes("01000014EBFFFF54"), maxOffset = 2048),
        // ARM64 clone syscall — process/thread creation from native code
        BytePattern("clone Syscall (ARM64)", "Direct clone syscall — process/thread spawning from native code",
            Severity.LOW, hexToBytes("2000801210000054"), maxOffset = 2048),
    )

    private val MAX_NATIVE_LIB_SIZE = 50L * 1024 * 1024

    fun analyze(apkFile: File, nativeLibs: List<String>): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (nativeLibs.isEmpty()) return findings

        try {
            ZipFile(apkFile).use { zip ->
                for (libName in nativeLibs) {
                    val entry = zip.getEntry(libName) ?: continue
                    if (entry.size > MAX_NATIVE_LIB_SIZE) continue
                    val bytes = try {
                        zip.getInputStream(entry).readBytes()
                    } catch (_: Exception) { continue }
                    if (bytes.isEmpty()) continue
                    val results = scanBytes(bytes)
                    for (match in results) {
                        findings.add(Finding(
                            category = FindingCategory.NATIVE,
                            severity = match.pattern.severity,
                            title = match.pattern.name,
                            description = "${match.pattern.description} | Lib: $libName | Offset: 0x${match.offset.toString(16)}"
                        ))
                    }
                }
            }
        } catch (_: Exception) {}
        return findings
    }

    private data class PatternMatch(val pattern: BytePattern, val offset: Long)

    private fun scanBytes(bytes: ByteArray): List<PatternMatch> {
        val matches = mutableListOf<PatternMatch>()
        val maxBytes = bytes.size.coerceAtMost(20 * 1024 * 1024)
        var offset = 0
        val buf = ByteArray(4096)

        while (offset < maxBytes) {
            val chunkSize = minOf(buf.size, maxBytes - offset)
            System.arraycopy(bytes, offset, buf, 0, chunkSize)

            for (pattern in patterns) {
                val matchOffset = findPattern(buf, chunkSize, pattern)
                if (matchOffset >= 0) {
                    matches.add(PatternMatch(pattern, offset + matchOffset.toLong()))
                }
            }
            offset += (chunkSize - 128).coerceAtLeast(1)
        }
        return matches.distinctBy { "${it.pattern.name}@${it.offset}" }.take(20)
    }

    private fun findPattern(data: ByteArray, length: Int, pattern: BytePattern): Int {
        val searchBytes = pattern.bytes
        if (searchBytes.size > length) return -1

        val maxCheck = minOf(length - searchBytes.size, pattern.maxOffset)
        for (i in 0..maxCheck) {
            if (matchAt(data, i, searchBytes)) return i
        }
        return -1
    }

    private fun matchAt(data: ByteArray, offset: Int, pattern: ByteArray): Boolean {
        for (i in pattern.indices) {
            if (data[offset + i] != pattern[i]) return false
        }
        return true
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "").replace("\n", "")
        val result = ByteArray(clean.length / 2)
        for (i in result.indices) {
            result[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }
}
