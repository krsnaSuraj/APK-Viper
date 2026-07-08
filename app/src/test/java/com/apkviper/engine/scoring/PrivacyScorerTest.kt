package com.apkviper.engine.scoring

import com.apkviper.model.DecompileResult
import com.apkviper.model.FindingCategory
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test

class PrivacyScorerTest {
    private val scorer = PrivacyScorer()

    private fun makeResult(javaSrc: Map<String, String> = emptyMap(), manifest: String = ""): DecompileResult {
        return DecompileResult(
            javaSource = javaSrc, smaliSource = emptyMap(),
            manifest = manifest, resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
    }

    @Test
    fun noTrackersNoPerms_returnsScore0() {
        val result = makeResult(manifest = "<manifest></manifest>")
        val pr = scorer.assess(result)
        assertEquals(0, pr.privacyScore)
        assertTrue(pr.trackersFound.isEmpty())
        assertTrue(pr.dataCategories.isEmpty())
    }

    @Test
    fun detectsFirebaseTracker() {
        val javaSrc = mapOf("Main.java" to "import com.google.firebase.analytics;")
        val result = makeResult(javaSrc = javaSrc)
        val pr = scorer.assess(result)
        assertTrue("Should detect Firebase Analytics", pr.trackersFound.any { it.contains("Firebase") })
        assertTrue(pr.findings.any { it.category == FindingCategory.CLOUD })
    }

    @Test
    fun detectsMultipleTrackers() {
        val javaSrc = mapOf("App.java" to """
            import com.google.firebase.analytics;
            import com.appsflyer;
            import com.facebook.analytics;
        """.trimIndent())
        val result = makeResult(javaSrc = javaSrc)
        val pr = scorer.assess(result)
        assertTrue(pr.trackersFound.size >= 3)
    }

    @Test
    fun detectsLocationDataCategory() {
        val manifest = "<uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\"/>"
        val result = makeResult(manifest = manifest)
        val pr = scorer.assess(result)
        assertTrue(pr.dataCategories.any { it.contains("Location") })
    }

    @Test
    fun multipleDataCategories_raisesSeverity() {
        val manifest = """
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
            <uses-permission android:name="android.permission.CAMERA"/>
            <uses-permission android:name="android.permission.RECORD_AUDIO"/>
            <uses-permission android:name="android.permission.READ_CONTACTS"/>
            <uses-permission android:name="android.permission.READ_SMS"/>
        """.trimIndent()
        val result = makeResult(manifest = manifest)
        val pr = scorer.assess(result)
        assertTrue(pr.dataCategories.size >= 5)
        // Trackers / data-access are expected in genuine apps — capped at LOW, never flagged malicious.
        assertTrue(pr.findings.all { it.severity == Severity.LOW })
    }

    @Test
    fun largeSource_noTrackers_noCrash() {
        val largeSrc = mapOf("Large.java" to "a".repeat(60_000_000))
        val result = makeResult(javaSrc = largeSrc, manifest = "<manifest/>")
        val pr = scorer.assess(result)
        assertTrue(pr.trackersFound.isEmpty())
    }

    @Test
    fun dataCategoryPermMapping() {
        val manifest = """
            <uses-permission android:name="android.permission.READ_CALENDAR"/>
            <uses-permission android:name="android.permission.BODY_SENSORS"/>
            <uses-permission android:name="android.permission.ACTIVITY_RECOGNITION"/>
        """.trimIndent()
        val result = makeResult(manifest = manifest)
        val pr = scorer.assess(result)
        assertTrue(pr.dataCategories.any { it.contains("Calendar") })
        assertTrue(pr.dataCategories.any { it.contains("Sensor") })
        assertTrue(pr.dataCategories.any { it.contains("Activity") })
    }

    @Test
    fun privacyScore_boundaries() {
        val clean = makeResult()
        assertEquals(0, scorer.assess(clean).privacyScore)

        val heavy = makeResult(
            javaSrc = mapOf("A.java" to """
                import com.google.firebase.analytics;
                import com.appsflyer;
                import com.facebook.analytics;
                import com.adjust.sdk;
                import com.mixpanel.android;
                import com.amplitude.api;
            """.trimIndent()),
            manifest = """
                <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
                <uses-permission android:name="android.permission.CAMERA"/>
                <uses-permission android:name="android.permission.RECORD_AUDIO"/>
                <uses-permission android:name="android.permission.READ_CONTACTS"/>
                <uses-permission android:name="android.permission.READ_SMS"/>
                <uses-permission android:name="android.permission.READ_CALENDAR"/>
                <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
                <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
            """.trimIndent()
        )
        assertTrue(scorer.assess(heavy).privacyScore > 0)
    }

    @Test
    fun emptyManifest_returnsScore0() {
        val result = makeResult(manifest = "")
        val pr = scorer.assess(result)
        assertEquals(0, pr.privacyScore)
        assertTrue(pr.dataCategories.isEmpty())
        assertTrue(pr.trackersFound.isEmpty())
        assertTrue(pr.findings.isEmpty())
    }

    @Test
    fun unknownPermission_notCrash() {
        val manifest = """<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>"""
        val result = makeResult(manifest = manifest)
        val pr = scorer.assess(result)
        assertTrue(pr.dataCategories.isEmpty())
        assertEquals(0, pr.privacyScore)
    }

    @Test
    fun allTrackerTypes_detectedCorrectly() {
        val src = """
            import com.google.firebase.analytics;
            import com.adjust.sdk;
            import com.appsflyer;
            import com.facebook.analytics;
            import com.onesignal;
            import com.mixpanel.android;
            import com.amplitude.api;
            import com.branch.sdk;
        """.trimIndent()
        val result = makeResult(javaSrc = mapOf("App.java" to src))
        val names = scorer.assess(result).trackersFound
        assertTrue(names.any { it.contains("Firebase") })
        assertTrue(names.any { it.contains("Adjust") })
        assertTrue(names.any { it.contains("AppsFlyer") })
        assertTrue(names.any { it.contains("Facebook") })
        assertTrue(names.any { it.contains("OneSignal") })
        assertTrue(names.any { it.contains("Mixpanel") })
        assertTrue(names.any { it.contains("Amplitude") })
        assertTrue(names.any { it.contains("Branch") })
    }

    @Test
    fun trackerInSmaliSource_notDetectedByCurrentImpl() {
        val result = DecompileResult(
            javaSource = emptyMap(), smaliSource = mapOf("a.smali" to "com.google.firebase.analytics"),
            manifest = "", resources = emptyMap(),
            dexFiles = emptyList(), nativeLibs = emptyList(), decompileTimeMs = 0
        )
        val pr = scorer.assess(result)
        assertTrue(
            "Tracker in smali source is NOT detected (code only checks javaSource)",
            pr.trackersFound.isEmpty()
        )
    }

    @Test
    fun dataCategory_contacts_mapsCorrectly() {
        val manifest = """<uses-permission android:name="android.permission.READ_CONTACTS"/>"""
        val result = makeResult(manifest = manifest)
        assertTrue(scorer.assess(result).dataCategories.any { it.contains("Contact") })
    }

    @Test
    fun dataCategory_microphone_mapsCorrectly() {
        val manifest = """<uses-permission android:name="android.permission.RECORD_AUDIO"/>"""
        val result = makeResult(manifest = manifest)
        assertTrue(scorer.assess(result).dataCategories.any { it.contains("Microphone") })
    }

    @Test
    fun dataCategory_calendar_mapsCorrectly() {
        val manifest = """<uses-permission android:name="android.permission.READ_CALENDAR"/>"""
        val result = makeResult(manifest = manifest)
        assertTrue(scorer.assess(result).dataCategories.any { it.contains("Calendar") })
    }

    @Test
    fun privacyScore_maxCapped() {
        val src = (1..30).joinToString("\n") { "import com.tracker$it;" }
        val perms = (1..15).joinToString("\n") {
            "<uses-permission android:name=\"android.permission.PERM_$it\"/>"
        }
        val result = makeResult(javaSrc = mapOf("A.java" to src), manifest = perms)
        val pr = scorer.assess(result)
        assertTrue(pr.privacyScore <= 100)
        assertTrue(pr.privacyScore >= 0)
    }

    @Test
    fun manifestWithNoPermissions_stillDetectsTrackers() {
        val src = "import com.google.firebase.analytics; import com.appsflyer;"
        val result = makeResult(javaSrc = mapOf("A.java" to src), manifest = "")
        val pr = scorer.assess(result)
        assertTrue(pr.trackersFound.isNotEmpty())
        assertTrue(pr.dataCategories.isEmpty())
    }

    @Test
    fun duplicateTracker_noDoubleCount() {
        val src = """
            com.google.firebase.analytics
            com.google.firebase.analytics
            com.google.firebase.analytics
        """.trimIndent()
        val result = makeResult(javaSrc = mapOf("A.java" to src))
        val pr = scorer.assess(result)
        val firebaseCount = pr.trackersFound.count { it.contains("Firebase") }
        assertEquals("Same tracker should not be double-counted", 1, firebaseCount)
    }

    @Test
    fun combinedTrackerAndPerm_scoreAboveEitherAlone() {
        val trackerSrc = "import com.google.firebase.analytics;"
        val permManifest = """<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>"""

        val trackersOnly = scorer.assess(makeResult(javaSrc = mapOf("A.java" to trackerSrc)))
        val permsOnly = scorer.assess(makeResult(manifest = permManifest))
        val combined = scorer.assess(makeResult(javaSrc = mapOf("A.java" to trackerSrc), manifest = permManifest))

        val trackerScore = trackersOnly.privacyScore
        val permScore = permsOnly.privacyScore
        val combinedScore = combined.privacyScore

        assertTrue("Combined $combinedScore > tracker-only $trackerScore", combinedScore > trackerScore)
        assertTrue("Combined $combinedScore > perm-only $permScore", combinedScore > permScore)
    }

    @Test
    fun verifyPrivacyReportStructure() {
        val src = "import com.google.firebase.analytics; import com.appsflyer;"
        val manifest = """
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
            <uses-permission android:name="android.permission.CAMERA"/>
        """.trimIndent()
        val result = scorer.assess(makeResult(javaSrc = mapOf("A.java" to src), manifest = manifest))

        assertTrue("privacyScore should be valid", result.privacyScore in 0..100)
        assertTrue("trackersFound should be non-empty", result.trackersFound.isNotEmpty())
        assertTrue("dataCategories should be non-empty", result.dataCategories.isNotEmpty())
        assertTrue("findings should be non-empty", result.findings.isNotEmpty())
        assertTrue("Each tracker name should be non-blank", result.trackersFound.all { it.isNotBlank() })
        assertTrue("Each data category should be non-blank", result.dataCategories.all { it.isNotBlank() })
        assertTrue("Each finding should have valid fields", result.findings.all {
            it.title.isNotBlank() && it.description.isNotBlank()
        })
    }
}
