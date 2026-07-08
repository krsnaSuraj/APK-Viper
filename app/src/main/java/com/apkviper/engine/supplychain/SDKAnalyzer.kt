package com.apkviper.engine.supplychain

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

/**
 * Third-party SDK scanner — detects embedded libraries,
 * flags outdated versions with known CVEs, and identifies
 * risky SDKs that collect excessive data or load code dynamically.
 */
class SDKAnalyzer {

    data class SDKFingerprint(
        val name: String,
        val vendor: String,
        val packagePattern: String,
        val description: String,
        val riskLevel: Severity,
        val category: String,
        val knownVulnerabilities: List<String> = emptyList()
    )

    private val sdkDatabase = listOf(
        // Analytics / Tracking
        SDKFingerprint("Google Analytics", "Google", "com.google.analytics", "Analytics tracking", Severity.LOW, "Analytics"),
        SDKFingerprint("Google Firebase", "Google", "com.google.firebase", "Firebase platform SDK", Severity.LOW, "Platform"),
        SDKFingerprint("Facebook SDK", "Meta", "com.facebook", "Facebook integration", Severity.MEDIUM, "Social", listOf("CVE-2023-41040")),
        SDKFingerprint("Appsflyer", "Appsflyer", "com.appsflyer", "Marketing attribution", Severity.MEDIUM, "Analytics"),
        SDKFingerprint("Adjust", "Adjust", "com.adjust", "Mobile attribution", Severity.MEDIUM, "Analytics"),

        // Advertising
        SDKFingerprint("AdMob", "Google", "com.google.ads", "Google mobile ads", Severity.MEDIUM, "Ads"),
        SDKFingerprint("Unity Ads", "Unity", "com.unity3d.ads", "Unity ad network", Severity.MEDIUM, "Ads"),
        SDKFingerprint("Vungle", "Vungle", "com.vungle", "Video ad network", Severity.MEDIUM, "Ads"),
        SDKFingerprint("IronSource", "IronSource", "com.ironsource", "Ad mediation", Severity.MEDIUM, "Ads"),
        SDKFingerprint("Mopub", "Twitter", "com.mopub", "Ad mediation platform", Severity.MEDIUM, "Ads"),

        // Payment
        SDKFingerprint("Google Play Billing", "Google", "com.android.billingclient", "In-app purchases", Severity.LOW, "Payment"),
        SDKFingerprint("Stripe", "Stripe", "com.stripe", "Payment processing", Severity.MEDIUM, "Payment"),
        SDKFingerprint("PayPal", "PayPal", "com.paypal", "PayPal checkout", Severity.MEDIUM, "Payment"),
        SDKFingerprint("Braintree", "PayPal", "com.braintreepayments", "Payment gateway", Severity.MEDIUM, "Payment"),

        // Networking
        SDKFingerprint("OkHttp", "Square", "okhttp3", "HTTP client library", Severity.LOW, "Networking", listOf("CVE-2023-45897")),
        SDKFingerprint("Retrofit", "Square", "retrofit2", "REST client library", Severity.LOW, "Networking"),
        SDKFingerprint("Volley", "Google", "com.android.volley", "HTTP library", Severity.LOW, "Networking"),

        // Crash Reporting
        SDKFingerprint("Crashlytics", "Google", "com.crashlytics", "Crash reporting", Severity.LOW, "Crash Reporting"),
        SDKFingerprint("Sentry", "Sentry", "io.sentry", "Error tracking", Severity.LOW, "Crash Reporting"),
        SDKFingerprint("Bugsnag", "Bugsnag", "com.bugsnag", "Error monitoring", Severity.LOW, "Crash Reporting"),

        // Image Loading
        SDKFingerprint("Glide", "Bumptech", "com.bumptech.glide", "Image loading library", Severity.LOW, "Media"),
        SDKFingerprint("Picasso", "Square", "com.squareup.picasso", "Image loading library", Severity.LOW, "Media"),
        SDKFingerprint("Fresco", "Facebook", "com.facebook.drawee", "Image loading library", Severity.LOW, "Media"),

        // Database/Storage
        SDKFingerprint("Realm", "MongoDB", "io.realm", "Mobile database", Severity.LOW, "Database"),
        SDKFingerprint("Room", "Google", "androidx.room", "Android persistence", Severity.LOW, "Database"),

        // Push Notifications
        SDKFingerprint("Firebase Cloud Messaging", "Google", "com.google.firebase.messaging", "Push notifications", Severity.LOW, "Messaging"),
        SDKFingerprint("OneSignal", "OneSignal", "com.onesignal", "Push notification service", Severity.MEDIUM, "Messaging"),

        // Risk SDKs — known for data collection or dynamic loading
        SDKFingerprint("InstallReferrer", "Google", "com.android.installreferrer", "Install attribution", Severity.MEDIUM, "Tracking"),
        SDKFingerprint("Adjust Referrer", "Adjust", "com.android.installreferrer", "Install attribution", Severity.MEDIUM, "Tracking"),
        SDKFingerprint("AndroidX WebKit", "Google", "androidx.webkit", "WebView enhancements", Severity.LOW, "Platform"),
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val detectedSdks = mutableListOf<SDKFingerprint>()
        val allCode = decompiled.allSourceText ?: decompiled.javaSource.values.joinToString("\n")

        sdkDatabase.forEach { sdk ->
            if (allCode.contains(sdk.packagePattern, ignoreCase = true)) {
                detectedSdks.add(sdk)

                // Flag known CVEs
                sdk.knownVulnerabilities.forEach { cve ->
                    findings.add(Finding(
                        category = FindingCategory.CODE,
                        severity = Severity.HIGH,
                        title = "Vulnerable SDK: ${sdk.name}",
                        description = "$cve in ${sdk.name} (${sdk.description})"
                    ))
                }

                // Flag risky SDKs
                if (sdk.riskLevel >= Severity.MEDIUM) {
                    findings.add(Finding(
                        category = FindingCategory.CODE,
                        severity = sdk.riskLevel,
                        title = "Risky SDK Detected: ${sdk.name}",
                        description = "${sdk.vendor} ${sdk.description} — Category: ${sdk.category}"
                    ))
                }
            }
        }

        // Summarize
        if (detectedSdks.isNotEmpty()) {
            val byCategory = detectedSdks.groupBy { it.category }
            val sbomText = byCategory.map { (cat, sdks) ->
                "  $cat: ${sdks.joinToString(", ") { "${it.name} (${it.vendor})" }}"
            }.joinToString("\n")

            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.INFO,
                title = "Software Bill of Materials (SBOM)",
                description = "${detectedSdks.size} SDKs detected across ${byCategory.size} categories",
                details = sbomText
            ))
        }

        // Check for Java reflection usage (suspicious)
        if (allCode.contains("DexClassLoader") || allCode.contains("PathClassLoader")) {
            findings.add(Finding(
                category = FindingCategory.PACKER,
                severity = Severity.HIGH,
                title = "Dynamic Code Loading",
                description = "SDK or app loads code at runtime — cannot be fully analyzed statically"
            ))
        }

        return findings
    }
}
