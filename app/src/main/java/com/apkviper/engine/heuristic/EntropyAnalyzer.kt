package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import kotlin.math.ln

class EntropyAnalyzer {

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()

        // Check manifest for encrypted assets
        if (decompiled.manifest.contains("encrypted") || decompiled.manifest.contains("decrypt")) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.HIGH,
                title = "Encrypted Assets Detected",
                description = "Manifest references encrypted/decrypted content"
            ))
        }

        // Analyze resource files for high entropy
        decompiled.resources.forEach { (name, data) ->
            val entropy = calculateShannonEntropy(data)
            if (entropy > 7.0) {
                findings.add(Finding(
                    category = FindingCategory.PACKER,
                    severity = Severity.HIGH,
                    title = "High Entropy Resource: $name",
                    description = "Entropy: ${"%.2f".format(entropy)} - likely encrypted/packed",
                    file = name
                ))
            }
        }

        return findings
    }

    fun calculateShannonEntropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0

        val frequency = IntArray(256)
        data.forEach { byte ->
            frequency[(byte.toInt() and 0xFF)]++
        }

        var entropy = 0.0
        val size = data.size.toDouble()

        frequency.forEach { count ->
            if (count > 0) {
                val probability = count / size
                entropy -= probability * ln(probability) / ln(2.0)
            }
        }

        return entropy
    }

    fun calculateShannonEntropy(data: String): Double {
        return calculateShannonEntropy(data.toByteArray())
    }
}
