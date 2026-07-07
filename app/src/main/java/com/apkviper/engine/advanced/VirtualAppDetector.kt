package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class VirtualAppDetector {

    companion object {
        private const val MAX_SOURCE_SIZE = 50 * 1024 * 1024
    }

    private val virtualAppPatterns = listOf(
        "com.lbe.parallel" to "Parallel Space",
        "com.parallel.space" to "Parallel Space Pro",
        "com.qihoo.magic" to "Virtual App (Qihoo)",
        "io.va.exposed" to "VirtualXposed",
        "com.android.virtual" to "Virtual App Generic",
        "VirtualCore" to "VirtualApp SDK",
        "VirtualApp" to "VirtualApp Framework",
        "com.pspace.virtual" to "PSpace Virtual",
        "com.dual.space" to "Dual Space",
        "com.excelliance" to "MultiDroid",
        "Lbe.Secrity" to "LBE Security Virtualization",
        "com.tencent.qqpimsecure" to "Tencent Virtual Environment",
        "clone.app" to "App Cloner",
        "com.drweb" to "Dr.Web Space",
    )

    private val escapePatterns = listOf(
        "getPackageManager", "getInstalledPackages",
        "Intent.FLAG_ACTIVITY_NEW_TASK",
        "Intent.FLAG_ACTIVITY_MULTIPLE_TASK",
        "startActivity", "startActivityForResult",
        "android.app.ActivityManager"
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: run {
            val combined = (decompiled.javaSource.values + decompiled.smaliSource.values)
            if (combined.sumOf { it.length } > MAX_SOURCE_SIZE) {
                (decompiled.javaSource.values.take(200) + decompiled.smaliSource.values.take(100)).joinToString("\n")
            } else {
                combined.joinToString("\n")
            }
        }

        val matches = virtualAppPatterns.filter { (pattern, _) ->
            allCode.contains(pattern, ignoreCase = true)
        }

        if (matches.isNotEmpty()) {
            val appNames = matches.map { it.second }
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.MEDIUM,
                title = "Virtual App Environment Detected",
                description = "App is designed to run inside a virtual container: ${appNames.joinToString(", ")}",
                details = "Virtual app environments can bypass security controls and hide malicious behavior from device-level detection"
            ))

            val escapeCount = escapePatterns.count { allCode.contains(it, ignoreCase = true) }
            if (escapeCount >= 4) {
                findings.add(Finding(
                    category = FindingCategory.CODE,
                    severity = Severity.HIGH,
                    title = "Virtual App Escape Attempt",
                    description = "App contains APIs ($escapeCount) that can be used to escape virtual container and execute code outside it"
                ))
            }
        }

        return findings
    }
}
