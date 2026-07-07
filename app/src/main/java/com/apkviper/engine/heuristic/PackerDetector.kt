package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class PackerDetector {

    private val packerIndicators = listOf(
        "com.secneo.apkwrapper",
        "com.bangcle",
        "com.ijiami",
        "com.tencent.StubShell",
        "com.baidu.protect",
        "com.alibaba.wireless",
        "com.alibaba.china.guard",
        "com.alibaba.china.mobisec",
        "com.netease.mobisec",
        "com.SecShell.SecApplication",
        "com.secneo.apkapplication",
        "com.qihoo.util",
        "com.stub.StubApp",
        "com.bangcle.util"
    )

    fun detect(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: (decompiled.javaSource.values + decompiled.smaliSource.values)
            .joinToString("\n")

        // Check for packer class names
        packerIndicators.forEach { indicator ->
            if (allCode.contains(indicator, ignoreCase = true)) {
                val packerName = indicator.substringAfterLast(".")
                findings.add(Finding(
                    category = FindingCategory.PACKER,
                    severity = Severity.HIGH,
                    title = "Packer Detected: $packerName",
                    description = "Known packer/protector signature found: $indicator"
                ))
            }
        }

        // Check for encrypted DEX
        if (allCode.contains("DexClassLoader") || allCode.contains("PathClassLoader")) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.HIGH,
                title = "Dynamic DEX Loading",
                description = "App uses DexClassLoader/PathClassLoader - potential DEX decryption"
            ))
        }

        // Check for reflection-based loading
        if (allCode.contains("Class.forName") && allCode.contains("Method.invoke")) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.MEDIUM,
                title = "Reflection-based Loading",
                description = "Heavy reflection usage detected — may indicate obfuscation"
            ))
        }

        // ELF packing detection — check native libs for packer indicators
        if (decompiled.nativeLibs.isNotEmpty()) {
            val nativeCode = decompiled.nativeLibs.joinToString("\n") { it.lowercase() }
            val elfPackers = listOf("upx!", "upack", ".loader", ".unpack", "segment_", "packed",
                "shiva", "libpacker", ".encrypt", "decrypt_stub")
            val packerHits = elfPackers.filter { nativeCode.contains(it) }
            if (packerHits.isNotEmpty()) {
                findings.add(Finding(
                    FindingCategory.PACKER, Severity.HIGH,
                    "ELF Packing Indicators",
                    "Native library references: ${packerHits.joinToString(", ")} — possible packed ELF"
                ))
            }
        }

        // DEX structural anomaly — stub classes with zero methods
        val stubCount = decompiled.smaliSource.values.count { smali ->
            val methodCount = Regex("""\.method\s""").findAll(smali).count()
            val fieldCount = Regex("""\.field\s""").findAll(smali).count()
            methodCount == 0 && fieldCount > 0
        }
        if (stubCount > 10) {
            findings.add(Finding(
                FindingCategory.PACKER, Severity.HIGH,
                "$stubCount Stub Classes Detected",
                "Classes with fields but zero methods — typical packer proxy/stub pattern"
            ))
        }

        return findings
    }
}
