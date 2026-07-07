package com.apkviper.engine.advanced

import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.util.zip.ZipFile

/**
 * APK Integrity Verifier — checks if the APK file is valid, tampered with,
 * or structurally malformed before decompilation begins.
 */
class ApkIntegrityVerifier {

    data class IntegrityResult(
        val isValid: Boolean,
        val isApk: Boolean,
        val isZip: Boolean,
        val hasManifest: Boolean,
        val hasDexFiles: Boolean,
        val hasSignature: Boolean,
        val totalFiles: Int,
        val totalSize: Long,
        val signatureFiles: List<String>,
        val findings: List<Finding>,
        val error: String?,
        val isSplitApk: Boolean = false
    )

    fun verify(file: File, isSplitApk: Boolean = false): IntegrityResult {
        val findings = mutableListOf<Finding>()

        // Check file exists and has minimum size
        if (!file.exists()) {
            return IntegrityResult(false, false, false, false, false, false, 0, 0, emptyList(), emptyList(), "File does not exist")
        }

        val fileSize = file.length()
        if (fileSize < 1024 && !isSplitApk) {
            return IntegrityResult(false, false, false, false, false, false, 0, fileSize, emptyList(), emptyList(), "File is too small to be a valid APK")
        }

        // Check if it's a valid ZIP (APK is ZIP format)
        return try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                var totalFiles = 0
                var hasManifest = false
                var hasDexFiles = false
                var hasSignature = false
                val signatureFiles = mutableListOf<String>()
                var hasResourcesArsc = false
                var hasZlibErrors = false

                var errorCount = 0
                val MAX_ZIP_ERRORS = 10

                while (entries.hasMoreElements()) {
                    val entry = try {
                        entries.nextElement()
                    } catch (e: Exception) {
                        hasZlibErrors = true
                        errorCount++
                        if (errorCount > MAX_ZIP_ERRORS) break
                        continue
                    }
                    totalFiles++

                    when {
                        entry.name == "AndroidManifest.xml" -> hasManifest = true
                        entry.name.endsWith(".dex") -> hasDexFiles = true
                        entry.name.startsWith("META-INF/") && (entry.name.endsWith(".SF") || entry.name.endsWith(".RSA") || entry.name.endsWith(".DSA") || entry.name.endsWith(".EC")) -> {
                            hasSignature = true
                            signatureFiles.add(entry.name)
                        }
                        entry.name == "resources.arsc" -> hasResourcesArsc = true
                    }

                    // Check for suspicious entries
                    if (entry.name.contains("..")) {
                        findings.add(Finding(
                            FindingCategory.PACKER, Severity.HIGH,
                            "Zip Path Traversal: ${entry.name}",
                            "Malformed entry name may indicate tampering"
                        ))
                    }
                }

                val isValid = if (isSplitApk) {
                    hasManifest && totalFiles >= 2
                } else {
                    hasManifest && hasDexFiles && totalFiles >= 3
                }

                // Validation findings
                if (!hasManifest) {
                    findings.add(Finding(FindingCategory.MANIFEST, if (isSplitApk) Severity.HIGH else Severity.CRITICAL, "Missing AndroidManifest.xml", "APK does not contain a manifest — file is corrupt or not a real APK"))
                }
                if (!hasDexFiles && !isSplitApk) {
                    findings.add(Finding(FindingCategory.CODE, Severity.CRITICAL, "Missing DEX Files", "APK has no DEX bytecode — file may be empty or incomplete"))
                }
                if (!hasSignature) {
                    findings.add(Finding(FindingCategory.CERTIFICATE, if (isSplitApk) Severity.LOW else Severity.CRITICAL, "Unsigned APK", "APK has no signature — may be tampered or custom-built"))
                }
                if (hasZlibErrors) {
                    findings.add(Finding(FindingCategory.PACKER, Severity.HIGH, "Corrupted ZIP Entries", "Some entries could not be read — file may be damaged"))
                }
                if (!hasResourcesArsc) {
                    findings.add(Finding(FindingCategory.MANIFEST, Severity.LOW, "Missing resources.arsc", "APK may have minimal resources — may be a system or test package"))
                }

                IntegrityResult(
                    isValid = isValid,
                    isApk = !isSplitApk && isValid,
                    isZip = true,
                    hasManifest = hasManifest,
                    hasDexFiles = hasDexFiles,
                    hasSignature = hasSignature,
                    totalFiles = totalFiles,
                    totalSize = fileSize,
                    signatureFiles = signatureFiles,
                    findings = findings,
                    error = if (!isValid) if (isSplitApk) "Split APK may be incomplete" else "Invalid APK structure" else null,
                    isSplitApk = isSplitApk
                )
            }
        } catch (e: Exception) {
            if (isSplitApk) {
                IntegrityResult(
                    isValid = true, isApk = false, isZip = false,
                    hasManifest = false, hasDexFiles = false, hasSignature = false,
                    totalFiles = 0, totalSize = fileSize, signatureFiles = emptyList(),
                    findings = emptyList(), error = null, isSplitApk = true
                )
            } else {
                IntegrityResult(
                    isValid = false, isApk = false, isZip = false,
                    hasManifest = false, hasDexFiles = false, hasSignature = false,
                    totalFiles = 0, totalSize = fileSize, signatureFiles = emptyList(),
                    findings = listOf(Finding(FindingCategory.PACKER, Severity.CRITICAL, "Corrupt ZIP / APK", "File is not a valid ZIP archive — cannot be an APK")),
                    error = "Not a valid ZIP file: ${e.message}"
                )
            }
        }
    }

}
