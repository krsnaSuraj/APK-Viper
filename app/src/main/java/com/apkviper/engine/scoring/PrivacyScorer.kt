package com.apkviper.engine.scoring

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class PrivacyScorer {

    data class PrivacyResult(
        val privacyScore: Int,
        val trackersFound: List<String>,
        val dataCategories: List<String>,
        val findings: List<Finding>
    )

    private val trackerSdks = listOf(
        "com.google.firebase.analytics" to "Firebase Analytics",
        "com.google.android.gms.analytics" to "Google Analytics",
        "com.adjust.sdk" to "Adjust",
        "com.appsflyer" to "AppsFlyer",
        "com.facebook.analytics" to "Facebook Analytics",
        "com.flurry.android" to "Flurry",
        "com.mixpanel.android" to "Mixpanel",
        "com.amplitude.api" to "Amplitude",
        "com.branch.sdk" to "Branch",
        "com.onesignal" to "OneSignal",
        "com.localytics.android" to "Localytics",
        "com.optimizely" to "Optimizely",
        "com.segment.analytics" to "Segment",
        "com.kochava.base" to "Kochava",
        "com.tenjin." to "Tenjin",
        "com.ironsource" to "ironSource",
        "com.unity3d.ads" to "Unity Ads",
        "com.vungle" to "Vungle",
        "com.chartboost" to "Chartboost",
        "com.applovin" to "AppLovin",
    )

    private val dataCollectionPerms = mapOf(
        "READ_CONTACTS" to "Contacts",
        "ACCESS_FINE_LOCATION" to "Precise Location",
        "ACCESS_COARSE_LOCATION" to "Approximate Location",
        "READ_CALENDAR" to "Calendar",
        "CAMERA" to "Camera",
        "RECORD_AUDIO" to "Microphone",
        "READ_SMS" to "SMS Messages",
        "READ_PHONE_STATE" to "Device Info (IMEI/IMSI)",
        "READ_EXTERNAL_STORAGE" to "File Storage",
        "GET_ACCOUNTS" to "User Accounts",
        "READ_CALL_LOG" to "Call Log",
        "BODY_SENSORS" to "Health Sensors",
        "ACTIVITY_RECOGNITION" to "Physical Activity",
    )

    fun assess(decompiled: DecompileResult): PrivacyResult {
        val findings = mutableListOf<Finding>()
        val trackers = mutableListOf<String>()
        val dataCategories = mutableListOf<String>()
        val allCode = decompiled.allSourceText ?: run {
            val estimatedSize = decompiled.javaSource.values.sumOf { it.length }
            if (estimatedSize > 50_000_000) "" else decompiled.javaSource.values.joinToString("\n")
        }
        val manifest = decompiled.manifest

        for ((sdk, name) in trackerSdks) {
            if (allCode.contains(sdk, ignoreCase = true)) {
                trackers.add(name)
            }
        }

        val permRegex = Regex("""android\.permission\.([A-Z_]+)""")
        for (match in permRegex.findAll(manifest)) {
            val perm = match.groupValues[1]
            dataCollectionPerms[perm]?.let { category ->
                if (category !in dataCategories) dataCategories.add(category)
            }
        }

        if (trackers.isNotEmpty()) {
            val trackerSeverity = when {
                trackers.size >= 10 -> Severity.CRITICAL
                trackers.size >= 5 -> Severity.HIGH
                else -> Severity.MEDIUM
            }
            findings.add(Finding(
                category = FindingCategory.CLOUD,
                severity = trackerSeverity,
                title = "${trackers.size} Trackers Detected",
                description = "App embeds ${trackers.size} tracking SDKs: ${trackers.joinToString(", ")}",
                details = "Tracking SDKs collect user data for advertising and analytics purposes"
            ))
        }

        if (dataCategories.isNotEmpty()) {
            val privSeverity = when {
                dataCategories.size >= 5 -> Severity.HIGH
                dataCategories.size >= 3 -> Severity.MEDIUM
                else -> Severity.LOW
            }
            findings.add(Finding(
                category = FindingCategory.PERMISSION,
                severity = privSeverity,
                title = "${dataCategories.size} Data Categories Accessible",
                description = "App can access: ${dataCategories.joinToString(", ")}",
                details = "Review whether the app legitimately needs access to this data"
            ))
        }

        val privacyScore = calculateScore(trackers.size, dataCategories.size)
        return PrivacyResult(privacyScore, trackers, dataCategories, findings)
    }

    private fun calculateScore(trackerCount: Int, dataCategoryCount: Int): Int {
        var score = 0
        score += minOf(trackerCount * 10, 50)
        score += minOf(dataCategoryCount * 8, 40)
        return score.coerceIn(0, 100)
    }
}
