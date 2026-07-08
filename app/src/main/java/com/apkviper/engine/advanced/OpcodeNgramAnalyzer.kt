package com.apkviper.engine.advanced

import com.apkviper.dex.DexParser
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File

/**
 * Dalvik Opcode N-Gram Frequency Analyzer — strips code to raw opcode streams
 * and detects malware by opcode frequency distributions rather than text patterns.
 * Polymorphic malware that renames variables still produces identical opcode fingerprints.
 */
class OpcodeNgramAnalyzer {

    // Known malware opcode N-gram fingerprints (4-gram sequences)
    // Each fingerprint is a sequence of opcode names that indicate malicious behavior
    private val malwareNgrams = listOf(
        // Banking trojan inject pattern: const → invoke → move-result → monitor-enter
        listOf("const-string", "invoke-virtual", "move-result-object", "monitor-enter") to MalwareSig("Banking Trojan Injection Pattern", Severity.CRITICAL),
        // SMS exfil: new-instance → invoke-direct → invoke-virtual → invoke-virtual (send)
        listOf("new-instance", "invoke-direct", "invoke-virtual", "invoke-virtual") to MalwareSig("SMS Exfiltration N-Gram", Severity.CRITICAL),
        // Dynamic loading: const-string → invoke-static → move-result-object → invoke-virtual
        listOf("const-string", "invoke-static", "move-result-object", "check-cast") to MalwareSig("Dynamic Code Loading Chain", Severity.CRITICAL),
        // Reflection evasion: const-string → invoke-virtual → move-result-object → invoke-virtual
        listOf("const-string", "invoke-virtual", "move-result-object", "invoke-virtual") to MalwareSig("Reflection Evasion Chain", Severity.HIGH),
        // Crypto: const/4 → invoke-static → move-result-object → invoke-virtual
        listOf("const/4", "invoke-static", "move-result-object", "array-length") to MalwareSig("Crypto Operation N-Gram", Severity.MEDIUM),
    )

    private data class MalwareSig(val description: String, val severity: Severity)

    fun analyze(apkFile: File): List<Finding> {
        val findings = mutableListOf<Finding>()
        val parser = DexParser()
        val parseResult = try {
            parser.parseApk(apkFile)
        } catch (e: Exception) {
            return findings
        }

        // Extract raw opcode streams from all methods
        val allOpcodes = mutableListOf<String>()
        parseResult.classes.forEach { cls ->
            cls.methods.forEach { method ->
                method.bytecode?.instructions?.forEach { instr ->
                    allOpcodes.add(instr.opcodeName)
                }
            }
        }

        if (allOpcodes.size < 10) return findings

        // Build tri-grams (sliding window of 3)
        val ngrams = allOpcodes.windowed(4, 1).map { it.toList() }
        // Check against known malware N-grams. Require an EXACT contiguous match of the full
        // opcode sequence (not a fuzzy 2/4 match) — fuzzy matching fired on ordinary apps whose
        // opcodes merely resembled malware. Matches are surfaced as a supporting CODE signal
        // (not MALWARE/CRITICAL) so they can never alone produce a MALICIOUS verdict.
        malwareNgrams.forEach { (pattern, sig) ->
            val matches = countExactSequence(allOpcodes, pattern)
            if (matches >= 1) {
                findings.add(Finding(
                    category = FindingCategory.CODE,
                    severity = Severity.MEDIUM,
                    title = sig.description,
                    description = "Matched $matches exact opcode N-gram sequence(s) (supporting signal)",
                    details = "Pattern: ${pattern.joinToString(" → ")}"
                ))
            }
        }

        // Frequency anomaly detection
        val totalInstr = allOpcodes.size
        val invokeCount = allOpcodes.count { it.startsWith("invoke") }
        val monitorCount = allOpcodes.count { it == "monitor-enter" || it == "monitor-exit" }

        // Heavy invocation ratio can indicate obfuscated malware
        if (invokeCount > totalInstr * 0.6 && totalInstr > 100) {
            findings.add(Finding(
                FindingCategory.CODE, Severity.MEDIUM,
                "Dense Invocation Pattern",
                "${"%.0f".format(invokeCount.toDouble() / totalInstr * 100)}% of instructions are invoke — possible obfuscated dispatch"
            ))
        }

        // Monitor usage (synchronization abuse common in RAT malware)
        if (monitorCount > 5 && totalInstr > 50) {
            findings.add(Finding(
                FindingCategory.CODE, Severity.HIGH,
                "Synchronization Heavy Pattern",
                "$monitorCount monitor-enter/exit instructions — possible thread-based C2 or keylogging"
            ))
        }

        // Opcode frequency distribution comparison against malware profile. Opcode distributions
        // are remarkably similar across ALL Android apps, so a naive cosine match is a classic
        // false-positive trap. We only surface it as a low-confidence informational signal and
        // require an exceptionally high similarity (>0.9) — it can never drive a verdict.
        val similarity = profileSimilarity(allOpcodes, totalInstr)
        if (similarity > 0.9f) {
            findings.add(Finding(
                FindingCategory.CODE, Severity.LOW,
                "Malware Opcode Profile Match (${"%.0f".format(similarity * 100)}%)",
                description = "Opcode frequency distribution closely matches known malware profiles (supporting signal only)",
                details = "Cosine similarity: ${"%.2f".format(similarity)}"
            ))
        }

        return findings
    }

    /** Counts exact contiguous occurrences of [pattern] within [opcodes]. */
    private fun countExactSequence(opcodes: List<String>, pattern: List<String>): Int {
        if (pattern.isEmpty() || opcodes.size < pattern.size) return 0
        var count = 0
        for (i in 0..opcodes.size - pattern.size) {
            var ok = true
            for (j in pattern.indices) {
                if (opcodes[i + j] != pattern[j]) { ok = false; break }
            }
            if (ok) count++
        }
        return count
    }

    // Known malware opcode frequency profile (normalized distribution)
    private val malwareProfile = mapOf(
        "invoke-virtual" to 0.14f, "invoke-static" to 0.10f, "invoke-direct" to 0.08f,
        "const-string" to 0.07f, "const/4" to 0.06f, "const/16" to 0.04f,
        "move-result-object" to 0.09f, "new-instance" to 0.05f,
        "if-eqz" to 0.04f, "if-nez" to 0.04f, "goto" to 0.03f,
        "array-length" to 0.02f, "aget-object" to 0.02f, "aput-object" to 0.02f,
        "check-cast" to 0.03f, "monitor-enter" to 0.01f, "monitor-exit" to 0.01f,
        "sput-object" to 0.03f, "sget-object" to 0.03f, "iput-object" to 0.02f,
        "iget-object" to 0.02f, "return-void" to 0.03f, "throw" to 0.02f
    )

    private fun profileSimilarity(opcodes: List<String>, total: Int): Float {
        if (total == 0) return 0f
        val freq = opcodes.groupingBy { it }.eachCount()
        var dotProduct = 0f
        var profileMag = 0f
        var appMag = 0f
        for ((op, mFreq) in malwareProfile) {
            val aFreq = (freq[op] ?: 0).toFloat() / total
            dotProduct += mFreq * aFreq
            profileMag += mFreq * mFreq
            appMag += aFreq * aFreq
        }
        val denominator = kotlin.math.sqrt(profileMag) * kotlin.math.sqrt(appMag)
        return if (denominator > 0f) dotProduct / denominator else 0f
    }
}
