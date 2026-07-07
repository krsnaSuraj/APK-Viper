package com.apkviper.engine.advanced

import android.content.Context
import android.util.Log
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class LocalRuleWatcher(private val context: Context) {

    companion object {
        private const val RULES_DIR = "rules"
        private const val POLL_INTERVAL_SECONDS = 30L
    }

    @Volatile var loadedRules: List<String> = emptyList()
        private set
    @Volatile var loadedRuleCount: Int = 0
        private set

    private val executor = Executors.newSingleThreadScheduledExecutor()
    private var lastModified: Long = 0
    private val rulesDir: File by lazy {
        File(context.filesDir, RULES_DIR).also { it.mkdirs() }
    }

    fun start() {
        executor.scheduleWithFixedDelay(
            { pollRulesDirectory() },
            0, POLL_INTERVAL_SECONDS, TimeUnit.SECONDS
        )
    }

    fun stop() {
        executor.shutdown()
    }

    private fun pollRulesDirectory() {
        try {
            val ruleFiles = rulesDir.listFiles { f -> f.isFile && f.name.endsWith(".txt") } ?: return
            var newestMod: Long = 0
            var reloadNeeded = false

            for (file in ruleFiles) {
                if (file.lastModified() > lastModified) {
                    newestMod = maxOf(newestMod, file.lastModified())
                    try {
                        val rules = loadVerifiedRuleFile(file)
                        if (rules.isNotEmpty()) {
                            loadedRules = rules
                            loadedRuleCount = rules.size
                            reloadNeeded = true
                        }
                    } catch (e: Exception) {
                        Log.w("LocalRuleWatcher", "Failed to load rule file ${file.name}: ${e.message}")
                    }
                }
            }

            if (reloadNeeded && newestMod > lastModified) {
                lastModified = newestMod
            }
        } catch (e: Exception) {
            Log.w("LocalRuleWatcher", "Error polling rules directory: ${e.message}")
        }
    }

    private fun loadVerifiedRuleFile(file: File): List<String> {
        val content = file.readBytes()
        val hashFile = File(file.absolutePath + ".sha256")
        if (hashFile.exists()) {
            val storedHash = hashFile.readBytes().decodeToString().trim()
            val computedHash = MessageDigest.getInstance("SHA-256")
                .digest(content)
                .joinToString("") { "%02x".format(it) }
            if (storedHash != computedHash) {
                Log.w("LocalRuleWatcher", "Integrity check failed for ${file.name}")
                return emptyList()
            }
        }
        return String(content, Charsets.UTF_8)
            .lines()
            .filter { it.isNotBlank() && !it.startsWith("#") }
    }

}
