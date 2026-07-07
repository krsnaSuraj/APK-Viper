package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import java.io.File
import java.util.zip.ZipFile

/**
 * Anti-Evasion Stub Defeater — detects malware that detects analysis
 * environments and remains dormant. Scans for anti-debug, anti-emulator,
 * anti-root, anti-hook, and timing-based evasion techniques.
 */
class AntiEvasionDetector {

    data class EvasionCategory(val name: String, val patterns: List<String>, val severity: Severity, val minMatches: Int)

    private val evasionCategories = listOf(
        // Debugger detection
        EvasionCategory("Debugger Detection", listOf(
            "isDebuggerConnected", "android.os.Debug", "Debug.isDebuggerConnected",
            "Debug.waitingForDebugger", "waitForDebugger", "Debug.threadCpuTimeNanos"
        ), Severity.HIGH, 1),

        // Emulator detection
        EvasionCategory("Emulator Detection", listOf(
            "Build.FINGERPRINT", "Build.MODEL", "qemu", "goldfish", "ranchu",
            "generic", "vbox", "vmware", "genymotion", "androVM",
            "/system/lib/libc_malloc_debug_qemu", "ro.kernel.qemu",
            "ro.hardware", "qemu.hw.mainkeys", "init.svc.qemud"
        ), Severity.HIGH, 2),

        // Root detection
        EvasionCategory("Root Detection & Evasion", listOf(
            "test-keys", "Superuser.apk", "su", "which su", "magisk",
            "ro.build.tags", "ro.debuggable", "ro.secure",
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su"
        ), Severity.MEDIUM, 2),

        // Frida/Xposed/Substrate hook detection
        EvasionCategory("Hook Framework Detection", listOf(
            "frida", "frida-server", "frida-agent", "re.frida.server",
            "xposed", "XposedBridge", "XposedHelpers", "de.robv.android.xposed",
            "substrate", "cydia", "CydiaSubstrate", "MSHookFunction",
            "DobbyHook", "SubstrateHook"
        ), Severity.HIGH, 1),

        // Timing-based evasion (delays execution to bypass sandbox timeout)
        EvasionCategory("Timing-Based Evasion", listOf(
            "Thread.sleep", "SystemClock.sleep", "Handler.postDelayed",
            "ScheduledExecutorService", "Timer.schedule", "AlarmManager.set"
        ), Severity.MEDIUM, 3),

        // Sandbox detection (checks for common sandbox indicators)
        EvasionCategory("Sandbox Detection", listOf(
            "com.google.android.gms", "com.android.vending", "android_id",
            "getSystemService", "TelephonyManager.getDeviceId",
            "WifiManager.getConnectionInfo", "NetworkInfo.isConnectedOrConnecting"
        ), Severity.MEDIUM, 3),

        // Anti-disassembly (junk code, self-modifying)
        EvasionCategory("Anti-Disassembly Techniques", listOf(
            "obfuscate", "obfuscated", "junk", "garbage", "decryptPayload",
            "decryptAndLoad", "xor", "deobfuscate", "xorDecrypt"
        ), Severity.MEDIUM, 2),

        // IPC/Intent hijacking evasion
        EvasionCategory("IPC Evasion", listOf(
            "Intent.FLAG_ACTIVITY_NEW_TASK", "Intent.FLAG_INCLUDE_STOPPED_PACKAGES",
            "Intent.setComponent", "PackageManager.setComponentEnabledSetting"
        ), Severity.LOW, 2),

        // /proc-based evasion (process file system checks to detect analysis)
        EvasionCategory("/proc-Based Evasion", listOf(
            "/proc/self/status", "TracerPid", "/proc/self/maps",
            "/proc/self/cmdline", "/proc/%d/status", "/proc/self/exe",
            "/proc/self/fd", "/proc/self/task", "readlink(/proc",
            "BufferedReader.*proc/self"
        ), Severity.HIGH, 2),
    )

    data class EvasionScore(val category: String, val matches: Int, val total: Int, val files: List<String>)

    fun analyze(decompiled: DecompileResult, apkFile: File): List<Finding> {
        val findings = mutableListOf<Finding>()
        val allCode = decompiled.allSourceText ?: run {
            val combined = (decompiled.javaSource.values + decompiled.smaliSource.values)
            val estimatedSize = combined.sumOf { it.length }
            if (estimatedSize > 50_000_000) {
                android.util.Log.w("AntiEvasionDetector", "Source too large ($estimatedSize bytes), skipping")
                return emptyList()
            }
            combined.joinToString("\n")
        }
        val scores = mutableListOf<EvasionScore>()
        val allAffectedFiles = mutableSetOf<String>()
        val combinedSource = decompiled.javaSource + decompiled.smaliSource

        for (cat in evasionCategories) {
            var totalMatches = 0
            val matchedFiles = mutableListOf<String>()

            for ((filename, code) in combinedSource) {
                val fileMatches = cat.patterns.count { code.contains(it, ignoreCase = true) }
                if (fileMatches > 0) {
                    matchedFiles.add(filename)
                }
                totalMatches += fileMatches
            }

            if (totalMatches >= cat.minMatches) {
                scores.add(EvasionScore(cat.name, totalMatches, cat.patterns.size, matchedFiles))
                allAffectedFiles.addAll(matchedFiles)

                findings.add(Finding(
                    category = FindingCategory.CODE,
                    severity = cat.severity,
                    title = "Evasion: ${cat.name}",
                    description = "$totalMatches evasion indicators matched across ${matchedFiles.size} files",
                    details = "Patterns: ${cat.patterns.filter { allCode.contains(it, ignoreCase = true) }.take(5).joinToString(", ")}",
                    file = matchedFiles.firstOrNull()
                ))
            }
        }

        // Check native libraries for evasion strings
        val cachedLibBytes = decompiled.nativeLibBytes
        ZipFile(apkFile).use { zip ->
            for (libPath in decompiled.nativeLibs) {
                try {
                    val entry = zip.getEntry(libPath) ?: continue
                    val bytes = cachedLibBytes[libPath] ?: zip.getInputStream(entry).readBytes()
                    val strings = extractStrings(bytes)

                    val libEvasionMatches = evasionCategories.flatMap { cat ->
                        cat.patterns.filter { strings.contains(it, ignoreCase = true) }
                    }

                    if (libEvasionMatches.size >= 2) {
                        findings.add(Finding(
                            category = FindingCategory.NATIVE,
                            severity = Severity.HIGH,
                            title = "Native Evasion: ${libPath.substringAfterLast('/')}",
                            description = "${libEvasionMatches.size} evasion indicators in native code",
                            details = libEvasionMatches.take(5).joinToString(", "),
                            file = libPath
                        ))
                    }
                } catch (_: Exception) {
                    continue
                }
            }
        }

        // Overall evasion scoring
        if (scores.size >= 3) {
            val totalMatches = scores.sumOf { it.matches }
            val categories = scores.map { it.category }.joinToString(", ")
            val severity = if (scores.size >= 5) Severity.CRITICAL else Severity.HIGH

            findings.add(Finding(
                category = FindingCategory.CODE,
                severity = severity,
                title = "Heavy Evasion Suite Detected",
                description = "$totalMatches evasion indicators across ${scores.size} categories: $categories",
                details = "App actively tries to avoid analysis. ${allAffectedFiles.size} affected files. This is a strong malware indicator — legitimate apps rarely attempt to hide from analysis tools."
            ))
        }

        return findings
    }

    private fun extractStrings(data: ByteArray, minLen: Int = 3): String {
        val sb = StringBuilder()
        var current = StringBuilder()
        data.forEach { byte ->
            if (byte in 0x20..0x7E.toByte()) {
                current.append(byte.toInt().toChar())
            } else {
                if (current.length >= minLen) { sb.append(current.toString()).append('\n') }
                current = StringBuilder()
            }
        }
        if (current.length >= minLen) sb.append(current.toString())
        return sb.toString()
    }
}
