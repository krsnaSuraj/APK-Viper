package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class StringDeobfuscator {

    fun analyze(decompiled: DecompileResult, allSource: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (decompiled.javaSource.isEmpty() && decompiled.smaliSource.isEmpty()) return findings

        val redirects = mutableListOf<String>()

        // Detect reflection abuse
        for ((cls, code) in decompiled.javaSource) {
            val reflected = detectReflection(code, cls)
            if (reflected != null) {
                redirects.add("${reflected.first} in $cls → ${reflected.second}")
            }
        }
        for ((cls, code) in decompiled.smaliSource) {
            val reflected = detectReflection(code, cls)
            if (reflected != null) {
                redirects.add("${reflected.first} in $cls → ${reflected.second}")
            }
        }

        if (redirects.isNotEmpty()) {
            findings.add(Finding(
                category = FindingCategory.CODEGEN,
                severity = if (redirects.size >= 5) Severity.HIGH else Severity.MEDIUM,
                title = "Reflection API Abuse Detected",
                description = redirects.joinToString("; ")
            ))
        }

        // Detect string obfuscation patterns
        val rots = detectROT13(allSource)
        if (rots >= 5) {
            findings.add(Finding(
                category = FindingCategory.OBFUSCATION,
                severity = Severity.MEDIUM,
                title = "ROT13 String Obfuscation",
                description = "Found $rots likely ROT13-encoded strings"
            ))
        }

        val base64Encoded = detectBase64Strings(allSource)
        if (base64Encoded >= 10) {
            findings.add(Finding(
                category = FindingCategory.OBFUSCATION,
                severity = Severity.LOW,
                title = "Base64-Encoded String Blobs",
                description = "Found $base64Encoded base64-encoded strings — may be hidden payloads"
            ))
        }

        return findings
    }

    private fun detectReflection(code: String, className: String): Pair<String, String>? {
        val lower = code.lowercase()
        val hasClassForName = lower.contains("class.forname")
        val hasMethodInvoke = lower.contains("method.invoke") || lower.contains(".invoke(")
        val hasDexLoader = lower.contains("dexclassloader")
        val hasLoadClass = lower.contains("loadclass")
        val hasAccessible = lower.contains("setaccessible(true)")

        val redFlags = listOf(
            hasClassForName, hasMethodInvoke, hasDexLoader, hasLoadClass, hasAccessible
        ).count { it }

        if (redFlags >= 2) {
            var desc = "Uses "
            val flags = mutableListOf<String>()
            if (hasClassForName) flags.add("Class.forName")
            if (hasDexLoader) flags.add("DexClassLoader")
            if (hasLoadClass) flags.add("loadClass")
            if (hasMethodInvoke) flags.add("method.invoke")
            if (hasAccessible) flags.add("setAccessible")
            desc += flags.joinToString(" + ")
            return Pair(desc, className)
        }
        return null
    }

    private fun detectROT13(source: String): Int {
        var count = 0
        val hexRegex = Regex("""\\x[0-9a-fA-F]{2}""")
        for (line in source.lines()) {
            if (hexRegex.findAll(line).count() >= 3 && line.contains("new String")) {
                count++
            }
        }
        return count
    }

    private fun detectBase64Strings(source: String): Int {
        val base64BlockRegex = Regex("""["'][A-Za-z0-9+/]{40,}={0,2}["']""")
        return base64BlockRegex.findAll(source).count()
    }
}
