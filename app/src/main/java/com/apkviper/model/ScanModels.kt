package com.apkviper.model

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class ThreatLevel {
    SAFE, LOW, MEDIUM, HIGH, CRITICAL, MALICIOUS
}

enum class Severity {
    INFO, LOW, MEDIUM, HIGH, CRITICAL
}

/**
 * Confidence attached to a finding. Drives how much weight the scorer gives it.
 *  - HIGH:    curated, high-fidelity signal (our own ruleset, known-malware hash, confirmed C2).
 *  - MEDIUM:  corroborating signal (framework-aware native correlation, ML moderate).
 *  - LOW:     community / auto-updated rule that matched on a single loose string; never by
 *             itself sufficient to produce a MALICIOUS verdict (defense against false positives).
 */
enum class FindingConfidence {
    HIGH, MEDIUM, LOW
}

enum class FindingCategory {
    MANIFEST, PERMISSION, CODE, STRING, CERTIFICATE, PACKER,
    OBFUSCATION, NATIVE, NETWORK, CLOUD, MALWARE, CRYPTO_MINER,
    CODEGEN, BEHAVIORAL
}

@Entity(tableName = "scan_results")
data class ScanResult(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val apkName: String,
    val apkPath: String,
    val sha256: String? = null,
    val fileSize: Long,
    val scanMode: String, // quick, deep, brutal
    val threatLevel: ThreatLevel,
    val threatScore: Int, // 0-100
    val findings: List<Finding>,
    val decompileTime: Long,
    val scanTime: Long,
    val timestamp: Long = System.currentTimeMillis(),
    val classification: String? = null,
    val remediations: List<String> = emptyList(),
    val appLabel: String? = null,
    val packageName: String? = null,
    val versionName: String? = null,
    val versionCode: Long? = null,
    val minSdk: Int? = null,
    val targetSdk: Int? = null
)

data class Finding(
    val category: FindingCategory,
    val severity: Severity,
    val title: String,
    val description: String,
    val details: String? = null,
    val file: String? = null,
    val line: Int? = null,
    val confidence: FindingConfidence = FindingConfidence.HIGH,
    val ruleSource: String? = null
)

data class DecompileResult(
    val javaSource: Map<String, String>, // filename -> content
    val smaliSource: Map<String, String>,
    val manifest: String,
    val resources: Map<String, ByteArray>,
    val dexFiles: List<String>,
    val nativeLibs: List<String>,
    val decompileTimeMs: Long,
    // Performance: shared pre-computed context (populated by ScanPipeline)
    val allSourceText: String? = null,
    val permissions: List<String> = emptyList(),
    val exportedServiceCount: Int = 0,
    val nativeLibBytes: Map<String, ByteArray> = emptyMap()
)
