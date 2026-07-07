package com.apkviper.engine.scoring

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import com.apkviper.model.ThreatLevel
import kotlin.math.ln

class ThreatScorer {

    private val severityWeights = mapOf(
        Severity.CRITICAL to 15,
        Severity.HIGH to 10,
        Severity.MEDIUM to 5,
        Severity.LOW to 2,
        Severity.INFO to 0
    )

    private val categoryWeights = mapOf(
        FindingCategory.MALWARE to 2.5,
        FindingCategory.CRYPTO_MINER to 2.0,
        FindingCategory.PACKER to 1.8,
        FindingCategory.CODE to 1.5,
        FindingCategory.CODEGEN to 1.5,
        FindingCategory.BEHAVIORAL to 1.4,
        FindingCategory.NETWORK to 1.4,
        FindingCategory.PERMISSION to 1.3,
        FindingCategory.NATIVE to 1.3,
        FindingCategory.OBFUSCATION to 1.2,
        FindingCategory.MANIFEST to 1.1,
        FindingCategory.CERTIFICATE to 1.1,
        FindingCategory.STRING to 1.0,
        FindingCategory.CLOUD to 1.0
    )

    fun calculate(findings: List<Finding>): Int {
        var raw = 0.0
        val categoryCounts = mutableMapOf<FindingCategory, Int>()
        val severityCounts = mutableMapOf<Severity, Int>()

        findings.forEach { finding ->
            val sevW = severityWeights[finding.severity] ?: 0
            val catW = categoryWeights[finding.category] ?: 1.0
            raw += sevW * catW
            categoryCounts[finding.category] = (categoryCounts[finding.category] ?: 0) + 1
            severityCounts[finding.severity] = (severityCounts[finding.severity] ?: 0) + 1
        }

        // Logarithmic curve with better differentiation across wide range
        val criticalCount = severityCounts[Severity.CRITICAL] ?: 0
        val highCount = severityCounts[Severity.HIGH] ?: 0
        val mediumCount = severityCounts[Severity.MEDIUM] ?: 0
        val base = raw.coerceAtLeast(0.0)
        val logScore = 12.0 * ln(base + 1.0)
        val densityBoost = minOf((criticalCount * 1.5 + highCount * 0.8 + mediumCount * 0.3), 30.0)
        val score = minOf(logScore + densityBoost, 100.0)

        return score.toInt().coerceIn(0, 100)
    }

    fun getThreatLevel(score: Int): ThreatLevel = when {
        score >= 91 -> ThreatLevel.MALICIOUS
        score >= 81 -> ThreatLevel.CRITICAL
        score >= 66 -> ThreatLevel.HIGH
        score >= 51 -> ThreatLevel.MEDIUM
        score >= 26 -> ThreatLevel.LOW
        else -> ThreatLevel.SAFE
    }
}
