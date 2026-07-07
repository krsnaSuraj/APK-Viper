package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class ObfuscationDetector {

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val javaCode = decompiled.allSourceText ?: decompiled.javaSource.values.joinToString("\n")

        // ProGuard/R8 is standard for Android — only flag extreme cases
        val singleLetterVars = Regex("""\b[a-z]\b\s*=\s*""")
        val singleLetterCount = singleLetterVars.findAll(javaCode).count()
        if (singleLetterCount > 500) {
            findings.add(Finding(
                category = FindingCategory.OBFUSCATION,
                severity = Severity.INFO,
                title = "Heavy Obfuscation",
                description = "Found $singleLetterCount obfuscated variable names — possible standard ProGuard/R8"
            ))
        }

        // Check for string encryption patterns
        if (javaCode.contains("StringBuilder") && javaCode.contains("charAt")) {
            findings.add(Finding(
                category = FindingCategory.OBFUSCATION,
                severity = Severity.MEDIUM,
                title = "String Construction Pattern",
                description = "Strings built dynamically - possible string encryption"
            ))
        }

        // Check for control flow obfuscation
        if (Regex("""\bgoto\b""").containsMatchIn(javaCode) || javaCode.contains("switch")) {
            val switchCount = Regex("""switch\s*\(""").findAll(javaCode).count()
            if (switchCount > 20) {
                findings.add(Finding(
                    category = FindingCategory.OBFUSCATION,
                    severity = Severity.LOW,
                    title = "Control Flow Obfuscation",
                    description = "Heavy switch-based control flow detected"
                ))
            }
        }

        // Check for Base64 encoded strings
        val base64Pattern = Regex("""[A-Za-z0-9+/]{50,}={0,2}""")
        val base64Count = base64Pattern.findAll(javaCode).count { match ->
            val s = match.value
            s.contains("+") || s.contains("/") || s.endsWith("==") || s.endsWith("=")
        }
        if (base64Count > 10) {
            findings.add(Finding(
                category = FindingCategory.OBFUSCATION,
                severity = Severity.MEDIUM,
                title = "Base64 Encoded Strings",
                description = "Found $base64Count potentially encoded strings"
            ))
        }

        // Check for unicode-escaped strings in Java (\\uXXXX) or hex-encoded in smali
        val hexPattern = Regex("""\\u[0-9a-fA-F]{4}""")
        val hexCount = hexPattern.findAll(javaCode).count()
        val smaliHexCount = decompiled.smaliSource.values.sumOf { smali ->
            Regex("""const-string.*0x[0-9a-fA-F]""").findAll(smali).count()
        }
        if (hexCount + smaliHexCount > 20) {
            findings.add(Finding(
                category = FindingCategory.OBFUSCATION,
                severity = Severity.MEDIUM,
                title = "Obfuscated Strings",
                description = "Found ${hexCount + smaliHexCount} hex/unicode-encoded strings"
            ))
        }

        return findings
    }
}
