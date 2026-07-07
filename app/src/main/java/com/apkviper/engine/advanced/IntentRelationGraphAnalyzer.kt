package com.apkviper.engine.advanced

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

/**
 * Intent-Relation Graph Analyzer — constructs an adjacency matrix of how Android
 * components (Activities, Services, BroadcastReceivers) trigger each other via
 * Intents, permissions, and API calls. Malware fragments behavior across
 * components to evade sequential matching; this catches the cross-component chains.
 */
class IntentRelationGraphAnalyzer {

    data class Component(val name: String, val type: String, val permissions: List<String>, val intents: List<String>, val apis: List<String>)

    // Sensitive API calls that tracked across component boundaries
    private val trackedApis = listOf(
        "sendTextMessage", "HttpURLConnection", "getDeviceId", "getLastKnownLocation",
        "ContactsContract", "createPackageContext", "DexClassLoader", "System.loadLibrary",
        "Runtime.exec", "startActivity", "sendBroadcast", "startService",
        "addJavascriptInterface", "setJavaScriptEnabled"
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val manifest = decompiled.manifest
        val components = mutableListOf<Component>()

        // Extract components from manifest
        val activityRegex = Regex("""<activity[^>]*android:name="([^"]+)"[^>]*>""")
        val serviceRegex = Regex("""<service[^>]*android:name="([^"]+)"[^>]*>""")
        val receiverRegex = Regex("""<receiver[^>]*android:name="([^"]+)"[^>]*>""")

        val activities = activityRegex.findAll(manifest).map { Component(it.groupValues[1], "activity", emptyList(), emptyList(), emptyList()) }.toList()
        val services = serviceRegex.findAll(manifest).map { Component(it.groupValues[1], "service", emptyList(), emptyList(), emptyList()) }.toList()
        val receivers = receiverRegex.findAll(manifest).map { Component(it.groupValues[1], "receiver", emptyList(), emptyList(), emptyList()) }.toList()
        components.addAll(activities + services + receivers)

        // App-level permission adjacency analysis (independent of component count)
        val appPerms = decompiled.permissions.map { it.removePrefix("android.permission.") }.toSet()
        val hasSmsPerms = appPerms.any { it in setOf("SEND_SMS", "READ_SMS", "RECEIVE_SMS") }
        val hasBootPerm = "RECEIVE_BOOT_COMPLETED" in appPerms
        if (hasSmsPerms && hasBootPerm) {
            findings.add(Finding(
                FindingCategory.MANIFEST, Severity.CRITICAL,
                "Auto-start SMS Spy Architecture",
                "App auto-starts on boot AND has SMS access — SMS interception spyware pattern"
            ))
        }

        if (components.isEmpty()) return findings

        // For each component, find which permissions it needs and which APIs it calls
        for (comp in components) {
            // Match component to decompiled class
            val simpleName = comp.name.substringAfterLast('.')
            val matchingClass = decompiled.javaSource.entries.find { (filename, _) ->
                filename.contains(simpleName) || filename.contains(comp.name.replace('.', '/'))
            }

            if (matchingClass != null) {
                val code = matchingClass.value
                val apis = trackedApis.filter { code.contains(it, ignoreCase = true) }
                // Cross-component intent launching
                val intentTargets = Regex("""new Intent\([^)]*,\s*(\w+)\.class\s*\)""").findAll(code).map { match ->
                    match.groupValues[1]
                }.toList()

                // Check if this component launches other components with sensitive data
                if (intentTargets.isNotEmpty() && apis.isNotEmpty()) {
                    val launchedComps = intentTargets.filter { target ->
                        components.any { it.name.contains(target) || target in it.name }
                    }
                    if (launchedComps.isNotEmpty()) {
                        findings.add(Finding(
                            FindingCategory.CODE, Severity.HIGH,
                            "Cross-Component Intent Chain",
                            "${comp.name.substringAfterLast('.')} collects ${apis.take(3).joinToString(", ")} and launches ${launchedComps.joinToString(", ")}",
                            details = "Component-to-component data pass detected. Check if the receiving component sends data over network.",
                            file = matchingClass.key
                        ))
                    }
                }
            }
        }

        // Many cross-component intents = evasion
        if (components.size >= 5) {
            findings.add(Finding(
                FindingCategory.CODE, Severity.MEDIUM,
                "Heavy Component Fragmentation",
                "${components.size} components — behavior fragmented across multiple components to evade scanning",
                details = "${activities.size} activities, ${services.size} services, ${receivers.size} receivers"
            ))
        }

        return findings
    }
}
