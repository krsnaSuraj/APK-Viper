package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

/**
 * Context-aware permission analyzer.
 * Determines what the app IS (camera, SMS, map, etc.) and whether
 * its permissions are justified for its purpose.
 */
class PermissionAnalyzer {

    // App purpose classification patterns — what does this app do?
    private data class AppPurpose(val name: String, val justifiedPerms: Set<String>, val codeIndicators: List<String>, val manifestIndicators: List<String>)

    private val appPurposes = listOf(
        AppPurpose("Camera/Photography", setOf(
            "android.permission.CAMERA",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.ACCESS_FINE_LOCATION" // geotagging
        ), listOf("Camera.open", "Camera.CameraInfo", "takePicture", "MediaStore.Images", "camera2", "CaptureRequest", "ImageReader", "Photo"), listOf("camera", "photo", "capture", "gallery")),

        AppPurpose("Video/Voice Calling", setOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.MODIFY_AUDIO_SETTINGS"
        ), listOf("MediaRecorder", "AudioRecord", "RTC", "VideoCall", "webrtc", "VoIP", "AudioManager", "Speakerphone"), listOf("call", "video", "voice", "meet", "conference")),

        AppPurpose("Maps/Navigation", setOf(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.INTERNET"
        ), listOf("LocationManager", "FusedLocationProvider", "GoogleMap", "Navigation", "Route", "GeoPoint", "LatLng"), listOf("map", "navigation", "location", "gps", "route")),

        AppPurpose("SMS/Messaging", setOf(
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS"
        ), listOf("SmsManager", "sendTextMessage", "SmsMessage", "getMessageBody", "Telephony.Sms"), listOf("sms", "message", "messaging", "text")),

        AppPurpose("Social Media", setOf(
            "android.permission.CAMERA",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET"
        ), listOf("Social", "Feed", "Share", "Post", "Story", "Timeline", "Profile"), listOf("social", "share", "feed", "post")),

        AppPurpose("Health/Fitness", setOf(
            "android.permission.BODY_SENSORS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACTIVITY_RECOGNITION"
        ), listOf("Sensor", "Step", "Heart", "Fitness", "Workout", "Pedometer"), listOf("health", "fitness", "step", "heart", "workout")),

        AppPurpose("Anti-Theft/Device Admin", setOf(
            "android.permission.READ_PHONE_STATE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        ), listOf("DevicePolicyManager", "DeviceAdminReceiver", "wipeData", "lockNow", "FindMyDevice"), listOf("security", "antitheft", "find", "track", "admin")),
    )

    // Permissions that are ALWAYS suspicious regardless of app purpose
    private val alwaysSuspicious = setOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.WRITE_SECURE_SETTINGS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.REQUEST_INSTALL_PACKAGES"
    )

    // Known legitimate package prefixes (system apps, well-known vendors)
    private val knownLegitPrefixes = listOf(
        "com.google.android", "com.android.", "com.samsung.", "com.oneplus.",
        "com.xiaomi.", "com.miui.", "com.oppo.", "com.vivo.", "com.huawei.",
        "com.motorola.", "com.nothing.", "com.microsoft.", "com.adobe.",
        "com.spotify.", "com.netflix.", "com.whatsapp", "com.instagram",
        "com.facebook.", "com.twitter.", "com.snapchat.", "com.tiktok.",
        "com.zoom.", "com.skype.", "com.telegram.", "com.signal.",
        "com.dropbox.", "com.google.", "org.mozilla."
    )

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val permissions = extractPermissions(decompiled.manifest)
        val permSet = permissions.toSet()
        val packageName = extractPackageName(decompiled.manifest)

        // Skip known legitimate apps entirely
        if (knownLegitPrefixes.any { packageName.startsWith(it) }) {
            // Only check for truly suspicious things even in known apps
            checkAlwaysSuspicious(permSet, findings)
            return findings
        }

        // Determine what kind of app this is
        val allCode = decompiled.allSourceText?.lowercase() ?: run {
            val estimatedSize = decompiled.javaSource.values.sumOf { it.length }
            if (estimatedSize > 50_000_000) {
                android.util.Log.w("PermissionAnalyzer", "Source too large ($estimatedSize bytes), skipping")
                return emptyList()
            }
            decompiled.javaSource.values.joinToString("\n").lowercase()
        }
        val allManifest = decompiled.manifest.lowercase()
        val detectedPurpose = detectAppPurpose(allCode, allManifest)

        // Get permissions NOT justified by the app's purpose
        val unjustifiedPerms = permissions.filter { perm ->
            perm !in detectedPurpose.justifiedPerms && perm !in alwaysSuspicious
        }

        // Only flag if multiple unjustified permissions exist
        if (unjustifiedPerms.size >= 2) {
            findings.add(Finding(
                category = FindingCategory.PERMISSION,
                severity = Severity.MEDIUM,
                title = "Unusual Permissions for App Purpose",
                description = "This appears to be a ${detectedPurpose.name} app but requests permissions unusual for its type",
                details = "Unusual permissions: ${unjustifiedPerms.joinToString(", ")}\nApp purpose: ${detectedPurpose.name}"
            ))
        }

        // SMS capability without being a messaging app
        if ("android.permission.READ_SMS" in permSet && "android.permission.SEND_SMS" in permSet) {
            if (detectedPurpose.name != "SMS/Messaging") {
                val is2faApp = allCode.contains("2fa") || allCode.contains("otp") || allCode.contains("verification")
                if (!is2faApp) {
                    findings.add(Finding(
                        category = FindingCategory.PERMISSION,
                        severity = Severity.CRITICAL,
                        title = "SMS Spy — Unjustified SMS Access",
                        description = "App has full SMS access but is not a messaging or 2FA app"
                    ))
                }
            }
        }

        // CAMERA + RECORD_AUDIO without being a communication/camera app
        if ("android.permission.CAMERA" in permSet && "android.permission.RECORD_AUDIO" in permSet) {
            val isMediaApp = detectedPurpose.name in listOf("Camera/Photography", "Video/Voice Calling", "Social Media")
            if (!isMediaApp) {
                findings.add(Finding(
                    category = FindingCategory.PERMISSION,
                    severity = Severity.HIGH,
                    title = "Suspicious Media Access",
                    description = "App accesses camera AND microphone but is not a camera, calling, or social app"
                ))
            }
        }

        // Always-suspicious checks
        checkAlwaysSuspicious(permSet, findings)

        return findings
    }

    private fun checkAlwaysSuspicious(permSet: Set<String>, findings: MutableList<Finding>) {
        if ("android.permission.BIND_ACCESSIBILITY_SERVICE" in permSet) {
            findings.add(Finding(
                category = FindingCategory.PERMISSION,
                severity = Severity.CRITICAL,
                title = "Accessibility Service Bound",
                description = "App uses accessibility — can read screen content and simulate touch. Very high risk."
            ))
        }
        if ("android.permission.INSTALL_PACKAGES" in permSet) {
            findings.add(Finding(
                category = FindingCategory.PERMISSION,
                severity = Severity.CRITICAL,
                title = "Silent Package Installer",
                description = "App can install other apps silently — classic dropper capability"
            ))
        }
        if ("android.permission.WRITE_SECURE_SETTINGS" in permSet) {
            findings.add(Finding(
                category = FindingCategory.PERMISSION,
                severity = Severity.CRITICAL,
                title = "System Settings Modification",
                description = "App can modify secure system settings — requires root-like privileges"
            ))
        }
        if ("android.permission.PROCESS_OUTGOING_CALLS" in permSet) {
            findings.add(Finding(
                category = FindingCategory.PERMISSION,
                severity = Severity.CRITICAL,
                title = "Outgoing Call Interception",
                description = "App can intercept outgoing calls — can redirect calls silently"
            ))
        }
        if ("android.permission.REQUEST_INSTALL_PACKAGES" in permSet) {
            findings.add(Finding(
                category = FindingCategory.PERMISSION,
                severity = Severity.HIGH,
                title = "App Installation Capability",
                description = "App can trigger APK installation — check if this is expected"
            ))
        }
    }

    private fun detectAppPurpose(code: String, manifest: String): AppPurpose {
        // Score each purpose by how many code and manifest indicators match
        val scores = appPurposes.associateWith { purpose ->
            val codeMatches = purpose.codeIndicators.count { code.contains(it.lowercase()) }
            val manifestMatches = purpose.manifestIndicators.count { manifest.contains(it.lowercase()) }
            codeMatches * 2 + manifestMatches
        }
        // Return best match or "General Purpose" with reasonable default justified perms
        return scores.maxByOrNull { it.value }?.takeIf { it.value >= 2 }?.key
            ?: AppPurpose("General Purpose", setOf(
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.ACCESS_WIFI_STATE",
                "android.permission.VIBRATE",
                "android.permission.WAKE_LOCK",
                "android.permission.FOREGROUND_SERVICE",
                "android.permission.POST_NOTIFICATIONS",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE"
            ), emptyList(), emptyList())
    }

    private fun extractPermissions(manifest: String): List<String> {
        val regex = Regex("""android\.permission\.[A-Z_]+""")
        return regex.findAll(manifest).map { it.value }.distinct().toList()
    }

    private fun extractPackageName(manifest: String): String {
        val regex = Regex("""package="([^"]+)"""")
        return regex.find(manifest)?.groupValues?.getOrNull(1) ?: "unknown"
    }
}
