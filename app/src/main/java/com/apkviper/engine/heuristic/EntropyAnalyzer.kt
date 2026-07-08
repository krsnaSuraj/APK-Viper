package com.apkviper.engine.heuristic

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import kotlin.math.ln

class EntropyAnalyzer {

    // Extensions that are inherently compressed/encoded — high Shannon entropy is EXPECTED and
    // must NEVER be flagged as "packed/encrypted". Flagging these is the classic false-positive
    // (e.g. a normal PNG drawable reporting entropy ~7.9).
    private val COMPRESSED_EXT = setOf(
        "png", "jpg", "jpeg", "webp", "gif", "bmp", "mp3", "ogg", "oga", "wav", "flac",
        "ttf", "otf", "woff", "woff2", "zip", "apk", "jar", "dex", "so", "bin",
        "webm", "mp4", "m4a", "aac", "opus"
    )

    private fun extOf(name: String): String =
        name.substringAfterLast('.', "").lowercase()

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()

        // Check manifest for encrypted assets — downgraded: many legitimate apps reference
        // "encrypted"/"decrypt" in benign contexts (e.g. android:encrypted). Only informational.
        if (decompiled.manifest.contains("encrypted") || decompiled.manifest.contains("decrypt")) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.LOW,
                title = "Manifest References Encryption",
                description = "Manifest references encrypted/decrypted content (common in legit apps too)"
            ))
        }

        // Analyze resource files for high entropy — but NEVER flag known-compressed formats.
        decompiled.resources.forEach { (name, data) ->
            if (extOf(name) in COMPRESSED_EXT) return@forEach
            val entropy = calculateShannonEntropy(data)
            // Plain, uncompressed resources with very high entropy are suspicious (e.g. an
            // embedded payload in a .txt/.xml/.json/.bin-less asset). Use a high bar.
            if (entropy > 7.6 && data.size > 1024) {
                findings.add(Finding(
                    category = FindingCategory.PACKER,
                    severity = Severity.MEDIUM,
                    title = "Suspicious High Entropy Resource: $name",
                    description = "Entropy: ${"%.2f".format(entropy)} - unusually high for an uncompressed resource",
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
