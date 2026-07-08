package com.apkviper.engine.xapk

import android.content.Context
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.zip.ZipFile

data class XapkManifestData(
    val packageName: String,
    val versionCode: String,
    val versionName: String,
    val minSdkVersion: String?,
    val targetSdkVersion: String?,
    val expansions: List<XapkExpansion>
)

data class XapkExpansion(
    val file: String,
    val installLocation: String?,
    val installPath: String?
)

class XapkExtractor {

    data class ExtractedXapk(
        val baseApk: File,
        val splitApks: List<File>,
        val success: Boolean,
        val error: String? = null
    )

    companion object {
        private const val MAX_EXTRACTION_SIZE = 2L * 1024 * 1024 * 1024 // 2GB
        private const val MAX_COMPRESSION_RATIO = 100
        private const val TAG = "XapkExtractor"

        fun parseManifestFromZip(zip: java.util.zip.ZipFile): XapkManifestData? {
            return try {
                val entry = zip.getEntry("manifest.json") ?: return null
                val json = zip.getInputStream(entry).use { it.bufferedReader().readText() }
                parseManifestJsonStatic(json)
            } catch (e: Exception) { null }
        }

        private fun parseManifestJsonStatic(json: String): XapkManifestData? = try {
            val obj = JSONObject(json)
            val packageName = obj.getString("package_name")
            val versionCode = obj.getString("version_code")
            val versionName = obj.getString("version_name")
            val minSdkVersion = if (obj.has("min_sdk_version")) obj.getString("min_sdk_version") else null
            val targetSdkVersion = if (obj.has("target_sdk_version")) obj.getString("target_sdk_version") else null
            val expansions = obj.optJSONArray("expansions")?.let { arr ->
                (0 until arr.length()).map { i ->
                    val exp = arr.getJSONObject(i)
                    XapkExpansion(
                        file = exp.getString("file"),
                        installLocation = if (exp.has("install_location")) exp.getString("install_location") else null,
                        installPath = if (exp.has("install_path")) exp.getString("install_path") else null
                    )
                }
            } ?: emptyList()
            XapkManifestData(packageName, versionCode, versionName, minSdkVersion, targetSdkVersion, expansions)
        } catch (e: Exception) { null }
    }

    private var extractDir: File? = null

    fun extract(context: Context, xapkFile: File): ExtractedXapk = try {
        ZipFile(xapkFile).use { zip ->
            val manifestEntry = zip.getEntry("manifest.json")
                ?: return ExtractedXapk(File(""), emptyList(), false, "No manifest.json in XAPK")

            val manifestJson = zip.getInputStream(manifestEntry).use { it.bufferedReader().readText() }
            val parsedManifest = parseManifestJson(manifestJson)
            if (parsedManifest == null) {
                return ExtractedXapk(File(""), emptyList(), false, "Invalid manifest.json")
            }

            val dir = File(context.cacheDir, "xapk_extract_${System.currentTimeMillis()}")
            dir.mkdirs()
            extractDir = dir
            val obbDir = File(dir, "obb")
            obbDir.mkdirs()

            val entries = zip.entries()
            val apkFiles = mutableListOf<File>()
            var totalBytes = 0L

            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue

                val entryName = entry.name

                if (entryName.contains("..") || entryName.startsWith("/")) {
                    dir.deleteRecursively()
                    return ExtractedXapk(File(""), emptyList(), false, "ZipSlip detected: $entryName")
                }

                if (entry.size > 0 && entry.compressedSize > 0) {
                    val ratio = entry.size.toDouble() / entry.compressedSize.toDouble()
                    if (ratio > MAX_COMPRESSION_RATIO) {
                        dir.deleteRecursively()
                        return ExtractedXapk(File(""), emptyList(), false,
                            "Zip bomb: $entryName (${"%.0f".format(ratio)}:1)")
                    }
                }

                totalBytes += entry.size

                val fileName = File(entryName).name
                val isApk = fileName.endsWith(".apk", ignoreCase = true)
                val isObb = fileName.endsWith(".obb", ignoreCase = true)

                // Skip non-APK/non-OBB entries if over limit, stop entirely if APKs exceed cap too
                if (totalBytes > MAX_EXTRACTION_SIZE) {
                    if (!isApk) continue
                    android.util.Log.w(TAG, "XAPK total size exceeds 2GB limit, stopping extraction")
                    break
                }

                val outFile = when {
                    isApk -> File(dir, fileName)
                    isObb -> File(obbDir, fileName)
                    else -> continue
                }

                try {
                    zip.getInputStream(entry).use { input ->
                        outFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                } catch (e: IOException) {
                    dir.deleteRecursively()
                    return ExtractedXapk(File(""), emptyList(), false, "Failed to extract $fileName: ${e.message}")
                }

                if (isApk) {
                    apkFiles.add(outFile)
                }
            }

            if (apkFiles.isEmpty()) {
                dir.deleteRecursively()
                return ExtractedXapk(File(""), emptyList(), false, "No APK files in XAPK archive")
            }

            val baseApk = apkFiles.firstOrNull { it.name.contains("base", ignoreCase = true) }
                ?: apkFiles.maxByOrNull { it.length() }
                ?: apkFiles.first()

            val splitApks = apkFiles.filter { it != baseApk }

            ExtractedXapk(baseApk, splitApks, true)
        }
    } catch (e: IOException) {
        extractDir?.deleteRecursively()
        ExtractedXapk(File(""), emptyList(), false, "IO error: ${e.message}")
    } catch (e: SecurityException) {
        extractDir?.deleteRecursively()
        ExtractedXapk(File(""), emptyList(), false, "Security error: ${e.message}")
    } catch (e: Exception) {
        extractDir?.deleteRecursively()
        ExtractedXapk(File(""), emptyList(), false, e.message ?: "Extraction failed")
    }

    private fun parseManifestJson(json: String): XapkManifestData? = try {
        val obj = JSONObject(json)
        val packageName = obj.getString("package_name")
        val versionCode = obj.getString("version_code")
        val versionName = obj.getString("version_name")
        val minSdkVersion = if (obj.has("min_sdk_version")) obj.getString("min_sdk_version") else null
        val targetSdkVersion = if (obj.has("target_sdk_version")) obj.getString("target_sdk_version") else null
        val expansions = obj.optJSONArray("expansions")?.let { arr ->
            (0 until arr.length()).map { i ->
                val exp = arr.getJSONObject(i)
                XapkExpansion(
                    file = exp.getString("file"),
                    installLocation = if (exp.has("install_location")) exp.getString("install_location") else null,
                    installPath = if (exp.has("install_path")) exp.getString("install_path") else null
                )
            }
        } ?: emptyList()

        XapkManifestData(packageName, versionCode, versionName, minSdkVersion, targetSdkVersion, expansions)
    } catch (e: Exception) {
        null
    }

    fun isXapk(file: File): Boolean {
        if (!file.exists() || !file.isFile) return false
        if (file.name.endsWith(".xapk", ignoreCase = true)) return true
        return try {
            ZipFile(file).use { zip -> zip.getEntry("manifest.json") != null }
        } catch (e: IOException) {
            false
        } catch (e: SecurityException) {
            false
        }
    }

    fun analyzeFindings(extracted: ExtractedXapk): List<Finding> {
        val findings = mutableListOf<Finding>()

        if (extracted.splitApks.isNotEmpty()) {
            findings.add(
                Finding(
                    category = FindingCategory.PACKER,
                    severity = Severity.LOW,
                    title = "Split APK Bundle Detected",
                    description = "XAPK contains ${extracted.splitApks.size} split APKs"
                )
            )
        }

        for (apk in extracted.splitApks) {
            if (apk.length() > 100 * 1024 * 1024) {
                findings.add(
                    Finding(
                        category = FindingCategory.STRING,
                        severity = Severity.MEDIUM,
                        title = "Large Split APK",
                        description = "${apk.name} is ${"%.1f".format(apk.length().toDouble() / (1024 * 1024))}MB"
                    )
                )
            }
        }

        val allNames = (listOf(extracted.baseApk) + extracted.splitApks).map { it.name.lowercase() }
        val suspicious = allNames.filter { name ->
            name.contains("crack") || name.contains("hack") || name.contains("mod") ||
                name.contains("patched") || name.contains("unlocked") || name.contains("cheat")
        }
        if (suspicious.isNotEmpty()) {
            findings.add(
                Finding(
                    category = FindingCategory.MANIFEST,
                    severity = Severity.MEDIUM,
                    title = "Suspicious APK Names",
                    description = "APKs named: ${suspicious.joinToString(", ")}"
                )
            )
        }

        return findings
    }
}
