package com.apkviper.engine.static

import com.apkviper.model.DecompileResult
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity

class ManifestAnalyzer {

    fun analyze(decompiled: DecompileResult): List<Finding> {
        val findings = mutableListOf<Finding>()
        val manifest = decompiled.manifest

        // Check for exported components
        if (Regex("""exported=(['"])true\1""").containsMatchIn(manifest)) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = "Exported Component",
                description = "App has exported components that can be accessed by other apps"
            ))
        }

        // Check for debuggable flag
        if (Regex("""android:debuggable=(['"])true\1""").containsMatchIn(manifest)) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.HIGH,
                title = "Debuggable Application",
                description = "App is debuggable - allows debugging and inspection"
            ))
        }

        // Check for backup enabled
        if (Regex("""android:allowBackup=(['"])true\1""").containsMatchIn(manifest)) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = "Backup Enabled",
                description = "App data can be backed up and restored"
            ))
        }

        // Check for cleartext traffic
        if (Regex("""usesCleartextTraffic=(['"])true\1""").containsMatchIn(manifest)) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.HIGH,
                title = "Cleartext Traffic Allowed",
                description = "App allows unencrypted HTTP traffic"
            ))
        }

        // Check for testOnly flag
        if (Regex("""testOnly=(['"])true\1""").containsMatchIn(manifest)) {
            findings.add(Finding(
                category = FindingCategory.MANIFEST,
                severity = Severity.LOW,
                title = "Test Build",
                description = "This appears to be a test/debug build"
            ))
        }

        return findings
    }
}
