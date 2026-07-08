package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import java.security.MessageDigest

/**
 * Control Flow Graph (CFG) Structural Analyzer — generates structural hashes
 * from decompiled code blocks instead of text signatures. Renamed methods
 * and variables still produce the same structural fingerprint.
 */
class CfgStructuralAnalyzer {

    data class BlockFingerprint(
        val className: String,
        val methodName: String,
        val structuralHash: String,
        val blockCount: Int,
        val branchCount: Int,
        val loopCount: Int,
        val callCount: Int
    )

    // Known malware CFG fingerprints — metric-based structural matching
    // Matches the SHAPE of the code by comparing block/branch/loop/call counts
    private data class CfgPattern(
        val description: String,
        val severity: Severity,
        val minBlocks: Int, val maxBlocks: Int,
        val minBranches: Int, val maxBranches: Int,
        val minLoops: Int, val maxLoops: Int,
        val minCalls: Int, val maxCalls: Int
    )

    private val malwarePatterns = listOf(
        CfgPattern("Potential Keylogger (Structural Match)", Severity.CRITICAL, 2, 6, 2, 4, 2, 5, 3, 6),
        CfgPattern("Potential Remote Access Trojan (Structural Match)", Severity.CRITICAL, 3, 8, 2, 5, 1, 3, 4, 8),
        CfgPattern("Potential Cryptocurrency Miner (Structural Match)", Severity.CRITICAL, 3, 10, 1, 3, 3, 6, 6, 12),
        CfgPattern("Potential Infostealer (Structural Match)", Severity.CRITICAL, 2, 8, 3, 6, 1, 4, 4, 8),
        CfgPattern("Potential Banking Overlay Trojan (Structural Match)", Severity.CRITICAL, 3, 8, 4, 7, 1, 3, 5, 10),
        CfgPattern("Potential Payload Dropper (Structural Match)", Severity.CRITICAL, 2, 6, 2, 5, 1, 3, 4, 8),
    )



    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val blocks = mutableListOf<BlockFingerprint>()

        for ((fileName, code) in decompiled.javaSource) {
            val className = fileName.removeSuffix(".java")
            val methods = extractMethods(code)

            for (method in methods) {
                val cfg = analyzeControlFlow(method.body)
                if (cfg.blockCount < 2) continue

                val structuralHash = generateStructuralHash(cfg)
                val fingerprint = BlockFingerprint(
                    className = className,
                    methodName = method.name,
                    structuralHash = structuralHash,
                    blockCount = cfg.blockCount,
                    branchCount = cfg.branchCount,
                    loopCount = cfg.loopCount,
                    callCount = cfg.callCount
                )
                blocks.add(fingerprint)

                // Match against known malware CFG patterns using metric-based comparison
                for (pattern in malwarePatterns) {
                    if (cfg.blockCount in pattern.minBlocks..pattern.maxBlocks &&
                        cfg.branchCount in pattern.minBranches..pattern.maxBranches &&
                        cfg.loopCount in pattern.minLoops..pattern.maxLoops &&
                        cfg.callCount in pattern.minCalls..pattern.maxCalls) {
                        findings.add(Finding(
                            category = FindingCategory.MALWARE,
                            severity = pattern.severity,
                            confidence = FindingConfidence.LOW,
                            title = pattern.description,
                            description = "Method: ${method.name} in $className",
                            details = "CFG: ${cfg.blockCount} blocks, ${cfg.branchCount} branches, ${cfg.loopCount} loops, ${cfg.callCount} calls\nStructural hash: $structuralHash",
                            file = fileName
                        ))
                    }
                }
            }
        }

        // Suspicious CFG patterns even without known hash match
        for (block in blocks) {
            // Methods with many nested loops + many calls are normal in game engines,
            // but suspicious in simple utility classes
            if (block.loopCount >= 3 && block.callCount >= 8 && block.branchCount >= 4) {
                val className = block.className.lowercase()
                val isGameCode = className.contains("game") || className.contains("render") ||
                    className.contains("engine") || className.contains("scene")

                if (!isGameCode) {
                    findings.add(Finding(
                        category = FindingCategory.CODE,
                        severity = Severity.HIGH,
                        title = "Suspicious Control Flow Structure",
                        description = "${block.methodName} in ${block.className} has complex CFG (${block.loopCount} loops, ${block.branchCount} branches)",
                        details = "Heavy branching with many method calls — possible obfuscated malware behavior",
                        file = block.className
                    ))
                }
            }
        }

        return findings
    }

    private data class MethodInfo(val name: String, val body: String)
    private data class CfgInfo(val blockCount: Int, val branchCount: Int, val loopCount: Int, val callCount: Int)

    private fun extractMethods(code: String): List<MethodInfo> {
        val methods = mutableListOf<MethodInfo>()
        val lines = code.lines()
        var i = 0
        var braceDepth = 0
        var methodName = ""
        var methodStart = 0

        while (i < lines.size) {
            val line = lines[i].trim()
            // Detect method signatures: access_flags return_type name(params) {
            if (braceDepth == 0 && (line.contains("(") && line.contains(")") && (line.contains("{") || (i + 1 < lines.size && lines[i + 1].trim() == "{")))) {
                // Extract method name
                val beforeParen = line.substringBefore("(")
                val name = beforeParen.split(Regex("\\s+")).lastOrNull()?.trim() ?: "unknown"
                if (name in listOf("if", "while", "for", "switch", "catch", "synchronized", "class", "return")) {
                    i++
                    continue
                }
                methodName = name
                methodStart = i
                if (line.contains("{")) braceDepth++
            } else if (braceDepth > 0) {
                braceDepth += line.count { it == '{' }
                braceDepth -= line.count { it == '}' }
                if (braceDepth <= 0) {
                    val body = lines.subList(methodStart + 1, i).joinToString("\n")
                    methods.add(MethodInfo(methodName, body))
                    braceDepth = 0
                }
            }
            i++
        }
        return methods
    }

    private fun analyzeControlFlow(body: String): CfgInfo {
        var blockCount = 1
        var branchCount = 0
        var loopCount = 0
        var callCount = 0

        body.lines().forEach { line ->
            val trimmed = line.trim()
            when {
                trimmed.startsWith("if") || trimmed.startsWith("else if") || trimmed.startsWith("switch") -> {
                    blockCount++
                    branchCount++
                }
                trimmed.startsWith("for") || trimmed.startsWith("while") -> {
                    blockCount++
                    loopCount++
                }
                trimmed.startsWith("else") || trimmed.startsWith("case") || trimmed.startsWith("default:") -> blockCount++
                trimmed.contains("(") && !trimmed.startsWith("//") && !trimmed.startsWith("if") &&
                    !trimmed.startsWith("for") && !trimmed.startsWith("while") -> callCount++
                trimmed.startsWith("try") || trimmed.startsWith("catch") -> blockCount++
            }
        }

        return CfgInfo(blockCount, branchCount, loopCount, callCount)
    }

    private fun generateStructuralHash(cfg: CfgInfo): String {
        val data = "${cfg.blockCount}|${cfg.branchCount}|${cfg.loopCount}|${cfg.callCount}"
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data.toByteArray()).take(8).joinToString("") { "%02x".format(it) }
    }}
