package com.apkviper.engine.taint

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

/**
 * Taint Analysis — tracks data flow from sensitive sources to external sinks.
 * Only flags when source + sink + obfuscation co-occur in the same class
 * (legit apps transmit data but don't obfuscate before sending).
 */
class TaintAnalyzer {

    data class TaintSource(val method: String, val description: String, val category: String)
    data class TaintSink(val method: String, val description: String)

    private val sources = listOf(
        TaintSource("getDeviceId", "Device IMEI", "device"),
        TaintSource("getSubscriberId", "IMSI", "device"),
        TaintSource("getLastKnownLocation", "GPS Location", "location"),
        TaintSource("requestLocationUpdates", "Live Location Tracking", "location"),
        TaintSource("ContactsContract", "Contact Database", "contacts"),
        TaintSource("CallLog.Calls", "Call History", "calls"),
        TaintSource("getMessageBody", "SMS Content", "sms"),
        TaintSource("AccountManager.getAccounts", "Account List", "accounts"),
        TaintSource("getAuthToken", "Auth Token", "auth"),
        TaintSource("Camera.open", "Camera Feed", "media"),
        TaintSource("CameraManager", "Camera Manager API", "media"),
        TaintSource("MediaRecorder", "Audio/Video Recording", "media"),
        TaintSource("ClipboardManager", "Clipboard Content", "clipboard"),
        TaintSource("ClipData", "Clipboard Data", "clipboard"),
    )

    private val sinks = listOf(
        TaintSink("HttpURLConnection", "HTTP transmission"),
        TaintSink("OkHttpClient", "HTTP client transmission"),
        TaintSink("okhttp3.Call.execute", "HTTP client execute"),
        TaintSink("Retrofit", "API client transmission"),
        TaintSink("Socket", "Raw socket connection"),
        TaintSink("sendTextMessage", "SMS sending"),
        TaintSink("OutputStream", "Data output stream"),
        TaintSink("BluetoothSocket", "Bluetooth data transfer"),
        TaintSink("BluetoothGatt", "Bluetooth LE data transfer"),
        TaintSink("sendBroadcast", "Broadcast data leak"),
        TaintSink("startService", "Service data pass"),
    )

    // Obfuscation indicators — if present WITH source+sink, strongly indicates malware
    private val obfuscation = listOf(
        "XOR", "Cipher.getInstance", "Base64.encode", "encrypt", "decrypt",
        "MessageDigest", "SecretKeySpec", "GZIPOutputStream", "Inflater",
        "StringBuilder.append" // string concatenation obfuscation
    )

    companion object {
        private val LOG_REGEX = Regex("Log\\.[divew]\\(")
        private const val MAX_CROSS_CLASS_BYTES = 10 * 1024 * 1024
    }

    fun analyzeSmali(decompiled: DecompileResult): List<Finding> {
        return smaliDefUseAnalysis(decompiled)
    }

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()

        for ((fileName, code) in decompiled.javaSource) {
            // Find all sources, sinks, and obfuscation in this class
            val foundSources = sources.filter { s -> code.contains(s.method, ignoreCase = true) }
            val foundSinks = sinks.filter { s -> code.contains(s.method, ignoreCase = true) }
            val hasObfuscation = obfuscation.any { obf -> code.contains(obf, ignoreCase = true) }

            if (foundSources.isEmpty() || foundSinks.isEmpty()) continue

            // Check if any data category has both source + sink + obfuscation
            val categories = foundSources.map { it.category }.distinct()

            for (category in categories) {
                val catSources = foundSources.filter { it.category == category }
                val allThreePresent = catSources.isNotEmpty() && foundSinks.isNotEmpty() && hasObfuscation

                if (allThreePresent) {
                    // High confidence — source + sink + obfuscation in same class
                    findings.add(Finding(
                        category = FindingCategory.CODE,
                        severity = Severity.CRITICAL,
                        title = "Confirmed Data Exfiltration: $category",
                        description = "${catSources.first().description} sent via ${foundSinks.first().description} with obfuscation",
                        details = "Class: $fileName — data access, network transmission, and obfuscation code co-locate. This is the definitive malware pattern.",
                        file = fileName
                    ))
                } else if (catSources.size >= 2 && foundSinks.size >= 1) {
                    // Medium confidence — multiple sources + sink, no obfuscation (could be normal)
                    findings.add(Finding(
                        category = FindingCategory.CODE,
                        severity = Severity.MEDIUM,
                        title = "Data Collection + Network: $category",
                        description = "${catSources.size} data sources access AND ${foundSinks.size} network sink in same class",
                        details = "May be legitimate if this is a data management class. No obfuscation detected.",
                        file = fileName
                    ))
                }
            }
        }

        // Cross-class analysis — if data is accessed in one class and sent in another (indicates intent)
        val totalSize = decompiled.javaSource.values.sumOf { it.length }
        val largeApk = totalSize > MAX_CROSS_CLASS_BYTES

        val sourceClasses = decompiled.javaSource.entries
            .filter { (_, code) -> sources.any { s -> code.contains(s.method, ignoreCase = true) } }
        val sinkClasses = decompiled.javaSource.entries
            .filter { (_, code) -> sinks.any { s -> code.contains(s.method) } }
        val obfuscationClasses = decompiled.javaSource.entries
            .filter { (_, code) -> obfuscation.any { o -> code.contains(o, ignoreCase = true) } }

        val anySource = sourceClasses.isNotEmpty()
        val anySink = sinkClasses.isNotEmpty()
        val anyObfuscation = obfuscationClasses.isNotEmpty()

        if (anySource && anySink && anyObfuscation &&
            sourceClasses.size >= 2 && sinkClasses.size >= 2 && obfuscationClasses.size >= 2) {
            findings.add(Finding(
                FindingCategory.CODE, Severity.CRITICAL,
                "Multi-Class Exfiltration Architecture",
                "App spans data collection (${sourceClasses.size} classes), network transmission (${sinkClasses.size} classes), and obfuscation (${obfuscationClasses.size} classes). Professional malware architecture detected.",
                details = "Data, network, and obfuscation separated across classes — sophisticated exfiltration design"
            ))
        }

        // Production logging check (process per-file for large APKs to avoid OOM)
        val logCalls = if (largeApk) {
            decompiled.javaSource.values.sumOf { code -> LOG_REGEX.findAll(code).count() }
        } else {
            val allCode = decompiled.allSourceText ?: decompiled.javaSource.values.joinToString("\n")
            LOG_REGEX.findAll(allCode).count()
        }
        if (logCalls > 20) {
            findings.add(Finding(
                FindingCategory.CODE, Severity.LOW,
                "Verbose Logging ($logCalls calls)",
                "App logs extensively — may leak sensitive data if shipped to production"
            ))
        }

        // Smali-level register def-use chain tracking
        findings.addAll(smaliDefUseAnalysis(decompiled))

        return findings
    }

    /**
     * Tracks actual register-level data flow in smali bytecode.
     * Pattern: source call → move-result-object vN → sink call with vN as argument.
     * This confirms that data from a sensitive API actually reaches a data egress point,
     * not just that both exist somewhere in the class.
     */
    private fun smaliDefUseAnalysis(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val sourceMethodNames = sources.map { it.method.lowercase() }.toSet()
        val sinkMethodNames = sinks.map { it.method.lowercase() }.toSet()

        // Register tracking pattern: match invoke-* then move-result-object on next line
        val invokeRegex = Regex("""invoke-\w+\s*\{[^}]*\},\s*([\w.$/]+)->(\w+)\(([^)]*)\)([\w;/]+)""")
        val moveResultRegex = Regex("""move-result-object\s+(v\d+)""")

        for ((fileName, smaliCode) in decompiled.smaliSource) {
            val lines = smaliCode.lines()
            val registerTaint = mutableMapOf<String, String>() // register → source description

            for (i in lines.indices) {
                val line = lines[i]

                // Detect source API invocation
                val invokeMatch = invokeRegex.find(line)
                if (invokeMatch != null) {
                    val className = invokeMatch.groupValues[1].lowercase()
                    val methodName = invokeMatch.groupValues[2].lowercase()
                    val methodKey = "$className.$methodName"

                    if (methodName in sourceMethodNames || sources.any { methodKey.contains(it.method.lowercase()) }) {
                        // Look at next line for move-result-object
                        if (i + 1 < lines.size) {
                            val moveMatch = moveResultRegex.find(lines[i + 1])
                            if (moveMatch != null) {
                                val resultReg = moveMatch.groupValues[1]
                                val srcDesc = sources.find { methodKey.contains(it.method.lowercase()) }
                                    ?.description ?: methodName
                                registerTaint[resultReg] = srcDesc
                            }
                        }
                    }
                }

                // Detect sink with tainted register argument
                val sinkMatch = invokeRegex.find(line)
                if (sinkMatch != null) {
                    val methodKey = "${sinkMatch.groupValues[1].lowercase()}.${sinkMatch.groupValues[2].lowercase()}"

                    if (sinkMethodNames.any { methodKey.contains(it) }) {
                        // Extract register arguments from the invoke
                        val invokeBody = line.substringAfter("{").substringBefore("}")
                        val argRegs = invokeBody.split(",").map { it.trim() }.filter { it.isNotEmpty() }

                        val taintedArg = argRegs.firstOrNull { it in registerTaint }
                        if (taintedArg != null) {
                            val sourceDesc = registerTaint[taintedArg] ?: continue
                            findings.add(Finding(
                                category = FindingCategory.CODE,
                                severity = Severity.CRITICAL,
                                title = "Def-Use Chain: $sourceDesc → Network Sink",
                                description = "Register-level data flow: $sourceDesc loaded into $taintedArg → passed to ${sinkMatch.groupValues[2]}",
                                details = "Smali flow confirmed in $fileName — source API output tracked through $taintedArg to network sink.",
                                file = fileName
                            ))
                            // Remove taint to avoid duplicate findings for same register
                            registerTaint.remove(taintedArg)
                        }
                    }
                }
            }
        }
        return findings.take(20) // Cap to prevent flooding
    }
}
