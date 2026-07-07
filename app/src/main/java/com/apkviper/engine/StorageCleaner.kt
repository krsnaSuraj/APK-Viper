package com.apkviper.engine

import android.content.Context
import java.io.File

class StorageCleaner(private val context: Context) {

    data class CleanResult(
        val scannedPaths: Int,
        val deletedFiles: Int,
        val deletedDirs: Int,
        val freedBytes: Long,
        val errors: List<String>
    )

    data class Orphan(
        val file: File,
        val reason: String,
        val ageHours: Long,
        val sizeBytes: Long
    )

    // Directories the app creates that can accumulate stale data
    private val appDirs: List<File> by lazy {
        listOf(
            context.cacheDir,
            File(context.cacheDir.parentFile, "code_cache"),
            File(context.cacheDir.parentFile, "no_backup"),
            context.externalCacheDir
        ).filterNotNull()
    }

    fun analyze(): Pair<List<Orphan>, Long> {
        val orphans = mutableListOf<Orphan>()
        var totalSize = 0L
        val now = System.currentTimeMillis()

        for (dir in appDirs) {
            if (!dir.exists()) continue
            try {
                // Detect stale directories (accumulated XAPK extract dirs, etc.)
                dir.walkTopDown().maxDepth(4).filter { it.isDirectory && it != dir }.forEach { d ->
                    val ageHours = (now - d.lastModified()) / 3600_000L
                    val name = d.name
                    if (name.startsWith("xapk_extract_") && ageHours > 0) {
                        val size = d.walkTopDown().filter { it.isFile }.sumOf { it.length() }
                        orphans.add(Orphan(d, "Stale XAPK dir (${ageHours}h)", ageHours, size))
                        totalSize += size
                    }
                }
                // Detect stale individual files
                dir.walkTopDown().maxDepth(8).forEach { file ->
                    if (!file.isFile) return@forEach
                    val ageHours = (now - file.lastModified()) / 3600_000L
                    val size = file.length()

                    val reason = when {
                        file.name.startsWith("scan_") && ageHours > 1 -> "Old scan extract (${ageHours}h)"
                        file.name.startsWith("xapk_") && ageHours > 1 -> "Old XAPK extract (${ageHours}h)"
                        file.name.endsWith(".tmp") -> "Temporary file"
                        file.name.endsWith(".log") -> "Log file"
                        file.extension in listOf("dex", "arsc", "sf", "rsa", "xml") &&
                            file.parentFile?.name?.startsWith("decompiled") == true -> "Old decompiled artifact"
                        ageHours > 24 -> "Stale file (${ageHours}h)"
                        else -> null
                    }

                    if (reason != null) {
                        orphans.add(Orphan(file, reason, ageHours, size))
                        totalSize += size
                    }
                }
            } catch (_: Exception) {}
        }

        return orphans.sortedByDescending { it.ageHours } to totalSize
    }

    fun clean(): CleanResult {
        val (orphans, _) = analyze()

        var deletedFiles = 0
        var deletedDirs = 0
        var freedBytes = 0L
        val errors = mutableListOf<String>()

        // Delete orphaned files and directories
        for (orphan in orphans) {
            try {
                if (orphan.file.isDirectory) {
                    val size = orphan.file.walkTopDown().filter { it.isFile }.sumOf { it.length() }
                    orphan.file.deleteRecursively().also { if (it) { deletedDirs++; freedBytes += size } }
                } else if (orphan.file.delete()) {
                    deletedFiles++
                    freedBytes += orphan.sizeBytes
                }
            } catch (e: Exception) {
                errors.add("${orphan.file.name}: ${e.message}")
            }
        }

        // Purge empty directories
        for (dir in appDirs) {
            if (!dir.exists()) continue
            try {
                dir.walkBottomUp().maxDepth(6).filter { it.isDirectory && it != dir && it.listFiles()?.isEmpty() == true }
                    .forEach { it.delete().also { if (it) deletedDirs++ } }
            } catch (e: Exception) {
                errors.add("Dir cleanup: ${e.message}")
            }
        }

        // Scan for high-entropy log files across app storage
        try {
            context.cacheDir.walkTopDown().maxDepth(4).filter { it.isFile && it.name.endsWith(".log") }.forEach { log ->
                try {
                    if (isHighEntropyLog(log) && log.delete()) {
                        deletedFiles++
                        freedBytes += log.length()
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}

        return CleanResult(
            scannedPaths = appDirs.sumOf { if (it.exists()) it.walkTopDown().count() else 0 },
            deletedFiles = deletedFiles,
            deletedDirs = deletedDirs,
            freedBytes = freedBytes,
            errors = errors
        )
    }

    private fun isHighEntropyLog(file: File): Boolean {
        return try {
            val sample = file.readBytes().take(2048).toByteArray()
            val freq = IntArray(256)
            for (b in sample) freq[b.toInt() and 0xFF]++
            var entropy = 0.0
            val len = sample.size.toDouble()
            for (c in freq) {
                if (c == 0) continue
                val p = c / len
                entropy -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
            }
            entropy > 6.5
        } catch (_: Exception) { false }
    }

    fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))} MB"
        else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))} GB"
    }
}
