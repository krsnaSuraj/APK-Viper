package com.apkviper.engine.dex

import com.apkviper.dex.DexParser
import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import java.io.File

/**
 * Deep DEX bytecode analysis — opcode frequency, anti-analysis patterns,
 * control flow anomalies, and suspicious instruction sequences.
 * Catches what string-based detection misses.
 */
class DexOpcodeAnalyzer {

    private val suspiciousOpcodeSequences = listOf(
        listOf(0x1a, 0x71) to "const-string → invoke-static (encrypted string decryption)",
        listOf(0x13, 0x22, 0x70) to "const/16 → new-instance → invoke-direct (payload construction)",
        listOf(0x28, 0x0e) to "goto → return-void (dead code after jump)",
        listOf(0x23, 0x26) to "new-array → fill-array-data (encrypted array payload)",
        listOf(0x1a, 0x70, 0x22, 0x70) to "const-string → invoke-direct → new-instance → invoke-direct (reflective loading)",
        listOf(0x1d, 0x1e) to "monitor-enter → monitor-exit (anti-debug timing)",
        listOf(0x27) to "throw (always-throws — obfuscated dead code)"
    )

    fun analyze(decompiled: DecompileResult, @Suppress("UNUSED_PARAMETER") apkFile: File? = null): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (decompiled.smaliSource.isEmpty()) return findings

        var totalInstr = 0
        val opcodeFreq = mutableMapOf<Int, Int>()
        var suspiciousCount = 0
        var reflectionCalls = 0
        var dynamicLoads = 0
        var antiAnalysisBlocks = 0

        decompiled.smaliSource.entries.forEach { (fileName, smali) ->
            // Skip known benign obfuscation frameworks (e.g. Facebook Audience Network's
            // "redex" tooling produces classes like Lcom_facebook_ads_redexgen_X_*) whose
            // new-array/fill-array-data and dead-code patterns are SDK artifacts, not malware.
            // Treating them as suspicious would massively inflate scores for any app that
            // simply bundles the Facebook ads SDK (a false RAT/MALICIOUS verdict).
            if (isBenignObfuscation(fileName)) return@forEach

            val lines = smali.lines()
            val opcodeSequence = mutableListOf<Int>()
            lines.forEach { line ->
                val trimmed = line.trim()

                // Parse opcode from smali
                if (trimmed.contains(invokeVirtual)) {
                    totalInstr++
                    opcodeFreq[0x6e] = (opcodeFreq[0x6e] ?: 0) + 1
                    opcodeSequence.add(0x6e)
                } else if (trimmed.contains(invokeStatic)) {
                    totalInstr++
                    opcodeFreq[0x71] = (opcodeFreq[0x71] ?: 0) + 1
                    opcodeSequence.add(0x71)
                } else if (trimmed.contains(invokeDirect)) {
                    totalInstr++
                    opcodeFreq[0x70] = (opcodeFreq[0x70] ?: 0) + 1
                    opcodeSequence.add(0x70)
                } else if (trimmed.contains(constString)) {
                    totalInstr++
                    opcodeFreq[0x1a] = (opcodeFreq[0x1a] ?: 0) + 1
                    opcodeSequence.add(0x1a)
                } else if (trimmed.contains(newInstance)) {
                    totalInstr++
                    opcodeFreq[0x22] = (opcodeFreq[0x22] ?: 0) + 1
                    opcodeSequence.add(0x22)
                } else if (trimmed.contains(goto16) || trimmed.contains(goto32)) {
                    totalInstr++
                    opcodeFreq[0x28] = (opcodeFreq[0x28] ?: 0) + 1
                    opcodeSequence.add(0x28)
                } else if (trimmed.contains(returnVoid)) {
                    totalInstr++
                    opcodeFreq[0x0e] = (opcodeFreq[0x0e] ?: 0) + 1
                    opcodeSequence.add(0x0e)
                } else if (trimmed.contains(throwClass)) {
                    totalInstr++
                    opcodeFreq[0x27] = (opcodeFreq[0x27] ?: 0) + 1
                    opcodeSequence.add(0x27)
                } else if (trimmed.contains(fillArrayData)) {
                    totalInstr++
                    opcodeFreq[0x26] = (opcodeFreq[0x26] ?: 0) + 1
                    opcodeSequence.add(0x26)
                } else if (trimmed.contains(newArray)) {
                    totalInstr++
                    opcodeFreq[0x23] = (opcodeFreq[0x23] ?: 0) + 1
                    opcodeSequence.add(0x23)
                } else if (trimmed.contains(monitorEnter)) {
                    totalInstr++
                    opcodeFreq[0x1d] = (opcodeFreq[0x1d] ?: 0) + 1
                    opcodeSequence.add(0x1d)
                } else if (trimmed.contains(monitorExit)) {
                    totalInstr++
                    opcodeFreq[0x1e] = (opcodeFreq[0x1e] ?: 0) + 1
                    opcodeSequence.add(0x1e)
                } else if (trimmed.startsWith("#") || trimmed.startsWith(".")) {
                    // Skip comments and directives
                } else if (trimmed.isNotEmpty() && !trimmed.startsWith("//")) {
                    totalInstr++
                }

                // Detect dynamic DEX loading references
                if (trimmed.contains("DexClassLoader") || trimmed.contains("PathClassLoader") ||
                    trimmed.contains("InMemoryDexClassLoader")) {
                    dynamicLoads++
                }

                // Detect reflection
                if (trimmed.contains("Class.forName") || trimmed.contains("Method.invoke") ||
                    trimmed.contains("Field.get") || trimmed.contains("Constructor.newInstance")) {
                    reflectionCalls++
                }

                // Anti-analysis
                if (trimmed.contains("isDebuggerConnected") || trimmed.contains("android/os/Debug") ||
                    trimmed.contains("Build/FINGERPRINT") || trimmed.contains("ro.build.tags") ||
                    trimmed.contains("which su") || trimmed.contains("superuser")) {
                    antiAnalysisBlocks++
                }
            }

            // Check for suspicious opcode sequences
            suspiciousOpcodeSequences.forEach { (sequence, description) ->
                if (containsSequence(opcodeSequence, sequence)) {
                    suspiciousCount++
                    findings.add(Finding(
                        category = FindingCategory.CODE,
                        severity = Severity.HIGH,
                        title = "Suspicious Opcode Sequence",
                        description = description,
                        file = fileName,
                        details = "Sequence: ${sequence.joinToString(" → ")}"
                    ))
                }
            }
        }

        // Heavy reflection
        if (reflectionCalls > 20) {
            findings.add(Finding(
                category = FindingCategory.OBFUSCATION,
                severity = Severity.HIGH,
                title = "Heavy Reflection Usage",
                description = "$reflectionCalls reflection calls detected — likely obfuscation or payload loading"
            ))
        }

        // Dynamic loading
        if (dynamicLoads > 0) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.HIGH,
                title = "Dynamic DEX Loading",
                description = "$dynamicLoads DEX class loader references — potential packed/encrypted payload"
            ))
        }

        // Anti-analysis count
        if (antiAnalysisBlocks > 3) {
            findings.add(Finding(
                category = FindingCategory.MALWARE,
                severity = Severity.HIGH,
                confidence = FindingConfidence.LOW,
                title = "Anti-Analysis Detection",
                description = "$antiAnalysisBlocks anti-analysis checks detected — app evades debugging/emulation"
            ))
        }

        // Opcode frequency anomalies
        val gotoCount = opcodeFreq[0x28] ?: 0
        if (gotoCount > 50 && totalInstr > 0) {
            val ratio = gotoCount.toFloat() / totalInstr
            if (ratio > 0.15f) {
                findings.add(Finding(
                    category = FindingCategory.OBFUSCATION,
                    severity = Severity.MEDIUM,
                    title = "Control Flow Obfuscation",
                    description = "High goto density: ${"%.1f".format(ratio * 100)}% — likely obfuscated control flow"
                ))
            }
        }

        val throwCount = opcodeFreq[0x27] ?: 0
        if (throwCount > 10 && totalInstr > 0) {
            val ratio = throwCount.toFloat() / totalInstr
            if (ratio > 0.05f) {
                findings.add(Finding(
                    category = FindingCategory.OBFUSCATION,
                    severity = Severity.MEDIUM,
                    title = "Dead Code Injection",
                    description = "High throw count: $throwCount — possibly dead code for obfuscation"
                ))
            }
        }

        // Fill-array-data with potential encrypted payloads
        val fillArrayCount = opcodeFreq[0x26] ?: 0
        if (fillArrayCount > 5) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.HIGH,
                title = "Encrypted Array Payloads",
                description = "$fillArrayCount fill-array-data instructions — possible encrypted DEX or config in arrays"
            ))
        }

        return findings
    }

    private fun containsSequence(haystack: List<Int>, needle: List<Int>): Boolean {
        if (needle.size > haystack.size) return false
        for (i in 0..haystack.size - needle.size) {
            if (haystack.subList(i, i + needle.size) == needle) return true
        }
        return false
    }

    companion object {
        /**
         * Known benign obfuscation packages. These are NOT malware — they are third-party SDK
         * obfuscators (notably Facebook Audience Network's `redex` tool which emits classes named
         * `Lcom_facebook_ads_redexgen_X_*`). Their code patterns (encrypted-array payloads,
         * always-throws dead code, string decryption) are SDK artifacts and must never be scored
         * as malicious. This mirrors the native-framework downgrade list in [FrameworkWhitelist].
         */
        private val benignObfuscationPackages = listOf(
            "redexgen",
            "com_facebook_ads_redexgen",
            "com_facebook_ads_redex",
            "Lcom/facebook/ads/",
            "Lcom/facebook/"
        )

        private fun isBenignObfuscation(fileName: String): Boolean {
            return benignObfuscationPackages.any { fileName.contains(it, ignoreCase = true) }
        }

        private val invokeVirtual = Regex("invoke-virtual\\s")
        private val invokeStatic = Regex("invoke-static\\s")
        private val invokeDirect = Regex("invoke-direct\\s")
        private val constString = Regex("const-string\\s")
        private val newInstance = Regex("new-instance\\s")
        private val goto16 = Regex("goto(?:/16|/32)?\\s")
        private val goto32 = Regex("goto/32\\s")
        private val returnVoid = Regex("return-void")
        private val throwClass = Regex("throw\\s")
        private val fillArrayData = Regex("fill-array-data\\s")
        private val newArray = Regex("new-array\\s")
        private val monitorEnter = Regex("monitor-enter\\s")
        private val monitorExit = Regex("monitor-exit\\s")
    }
}
