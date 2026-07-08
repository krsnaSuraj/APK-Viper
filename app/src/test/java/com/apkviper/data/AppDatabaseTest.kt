package com.apkviper.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.Severity
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AppDatabaseTest {

    private val findingConverter = FindingListConverter()
    private val remediationConverter = RemediationListConverter()

    // --- FindingListConverter tests ---

    @Test
    fun findingConverter_emptyList_roundTrips() {
        val original = emptyList<Finding>()
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertTrue(result.isEmpty())
    }

    @Test
    fun findingConverter_singleFinding_roundTrips() {
        val original = listOf(
            Finding(FindingCategory.MANIFEST, Severity.INFO, "Test Title", "Test description")
        )
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals(FindingCategory.MANIFEST, result[0].category)
        assertEquals(Severity.INFO, result[0].severity)
        assertEquals("Test Title", result[0].title)
        assertEquals("Test description", result[0].description)
    }

    @Test
    fun findingConverter_multipleFindings_roundTrips() {
        val original = listOf(
            Finding(FindingCategory.PERMISSION, Severity.CRITICAL, "Overly broad", "Uses all permissions", details = "INTERNET, READ_SMS", file = "AndroidManifest.xml", line = 15),
            Finding(FindingCategory.CODE, Severity.MEDIUM, "Reflection", "Uses reflection API", details = "Class.forName", file = "MainActivity.java"),
            Finding(FindingCategory.NETWORK, Severity.HIGH, "HTTP traffic", "Uses cleartext HTTP", details = "http://example.com")
        )
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(3, result.size)
        assertEquals(FindingCategory.PERMISSION, result[0].category)
        assertEquals(Severity.CRITICAL, result[0].severity)
        assertEquals(15, result[0].line)
        assertEquals("MainActivity.java", result[1].file)
        assertNull(result[2].line)
        assertNull(result[2].file)
    }

    @Test
    fun findingConverter_allFieldsPopulated_roundTrips() {
        val original = listOf(
            Finding(
                category = FindingCategory.MALWARE,
                severity = Severity.CRITICAL,
                title = "Known malware signature detected",
                description = "APK matches known malware family",
                details = "Matches Trojan.Dropper.ABC123",
                file = "/path/to/classes.dex",
                line = 42
            )
        )
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals(FindingCategory.MALWARE, result[0].category)
        assertEquals(Severity.CRITICAL, result[0].severity)
        assertEquals("Known malware signature detected", result[0].title)
        assertEquals("APK matches known malware family", result[0].description)
        assertEquals("Matches Trojan.Dropper.ABC123", result[0].details)
        assertEquals("/path/to/classes.dex", result[0].file)
        assertEquals(42, result[0].line)
    }

    // ── Confidence / ruleSource (verdict-gate persistence) ──────────
    //
    // The verdict-gate fix relies on per-finding `confidence` + `ruleSource`.
    // If the converter dropped them (the previous Gson-based bug, and an early
    // version of this org.json converter), every finding would reload as
    // confidence=HIGH and re-trigger false MALICIOUS verdicts from history.
    // These tests lock the round-trip behavior.

    @Test
    fun findingConverter_lowConfidence_heuristic_roundTrips() {
        val original = listOf(
            Finding(
                category = FindingCategory.BEHAVIORAL,
                severity = Severity.HIGH,
                title = "Possible data exfiltration",
                description = "Heuristic chain",
                confidence = FindingConfidence.LOW,
                ruleSource = "heuristic_behavioral"
            )
        )
        val result = findingConverter.fromString(findingConverter.fromList(original))
        assertEquals(1, result.size)
        assertEquals(FindingConfidence.LOW, result[0].confidence)
        assertEquals("heuristic_behavioral", result[0].ruleSource)
    }

    @Test
    fun findingConverter_allConfidenceLevels_roundTrip() {
        val original = FindingConfidence.values().mapIndexed { i, c ->
            Finding(FindingCategory.CODE, Severity.INFO, "c$i", "d", confidence = c, ruleSource = "src_$c")
        }
        val result = findingConverter.fromString(findingConverter.fromList(original))
        assertEquals(original.size, result.size)
        FindingConfidence.values().forEachIndexed { i, c ->
            assertEquals(c, result[i].confidence)
            assertEquals("src_$c", result[i].ruleSource)
        }
    }

    @Test
    fun findingConverter_missingConfidenceKey_defaultsToHigh_backwardCompatible() {
        // Old rows serialized before confidence was persisted have no "confidence" key.
        val json = """[{"category":"CODE","severity":"INFO","title":"t","description":"d"}]"""
        val result = findingConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals(FindingConfidence.HIGH, result[0].confidence)
        assertNull(result[0].ruleSource)
    }

    @Test
    fun findingConverter_nullRuleSource_roundTripsToNull() {
        val original = listOf(
            Finding(FindingCategory.CODE, Severity.MEDIUM, "t", "d", confidence = FindingConfidence.MEDIUM, ruleSource = null)
        )
        val result = findingConverter.fromString(findingConverter.fromList(original))
        assertEquals(FindingConfidence.MEDIUM, result[0].confidence)
        assertNull(result[0].ruleSource)
    }

    @Test
    fun findingConverter_nullFields_roundTrips() {
        val original = listOf(
            Finding(FindingCategory.STRING, Severity.LOW, "URL found", "Contains URL", details = null, file = null, line = null)
        )
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(1, result.size)
        assertNull(result[0].details)
        assertNull(result[0].file)
        assertNull(result[0].line)
    }

    @Test
    fun findingConverter_invalidJson_returnsEmptyList() {
        val result = findingConverter.fromString("this is not valid json")
        assertTrue(result.isEmpty())
    }

    @Test
    fun findingConverter_malformedArray_returnsEmptyList() {
        val result = findingConverter.fromString("[{bad json}")
        assertTrue(result.isEmpty())
    }

    @Test
    fun findingConverter_emptyJsonArray_returnsEmptyList() {
        val result = findingConverter.fromString("[]")
        assertTrue(result.isEmpty())
    }

    @Test
    fun findingConverter_allSeverities_roundTrip() {
        val original = Severity.values().map { sev ->
            Finding(FindingCategory.CODE, sev, "Severity test $sev", "Testing $sev")
        }
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(original.size, result.size)
        Severity.values().forEachIndexed { index, sev ->
            assertEquals(sev, result[index].severity)
        }
    }

    @Test
    fun findingConverter_allCategories_roundTrip() {
        val original = FindingCategory.values().map { cat ->
            Finding(cat, Severity.INFO, "Category test $cat", "Testing $cat")
        }
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(original.size, result.size)
        FindingCategory.values().forEachIndexed { index, cat ->
            assertEquals(cat, result[index].category)
        }
    }

    @Test
    fun findingConverter_veryLongStrings_roundTrips() {
        val longTitle = "A".repeat(10000)
        val longDesc = "B".repeat(50000)
        val original = listOf(
            Finding(FindingCategory.CODE, Severity.INFO, longTitle, longDesc)
        )
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals(longTitle, result[0].title)
        assertEquals(longDesc, result[0].description)
    }

    @Test
    fun findingConverter_specialCharacters_roundTrips() {
        val original = listOf(
            Finding(FindingCategory.STRING, Severity.MEDIUM, "Special: \"quotes\" & <html>", "Unicode: \u00e9\u00e0\u00fc\u00f1\u00df \u4e2d\u6587 \u0420\u0443\u0441\u0441\u043a\u0438\u0439", details = "Tab\there\nNewline here")
        )
        val json = findingConverter.fromList(original)
        val result = findingConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals("Special: \"quotes\" & <html>", result[0].title)
        assertEquals("Unicode: \u00e9\u00e0\u00fc\u00f1\u00df \u4e2d\u6587 \u0420\u0443\u0441\u0441\u043a\u0438\u0439", result[0].description)
        assertEquals("Tab\there\nNewline here", result[0].details)
    }

    @Test
    fun findingConverter_serializationDeterministic() {
        val findings = listOf(
            Finding(FindingCategory.MALWARE, Severity.CRITICAL, "Malware", "desc", details = "x", file = "f", line = 1)
        )
        val json1 = findingConverter.fromList(findings)
        val json2 = findingConverter.fromList(findings)
        assertEquals(json1, json2)
    }

    // --- RemediationListConverter tests ---

    @Test
    fun remediationConverter_emptyList_roundTrips() {
        val original = emptyList<String>()
        val json = remediationConverter.fromList(original)
        val result = remediationConverter.fromString(json)
        assertTrue(result.isEmpty())
    }

    @Test
    fun remediationConverter_singleItem_roundTrips() {
        val original = listOf("Review AndroidManifest.xml permissions")
        val json = remediationConverter.fromList(original)
        val result = remediationConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals("Review AndroidManifest.xml permissions", result[0])
    }

    @Test
    fun remediationConverter_multipleItems_roundTrips() {
        val original = listOf(
            "Remove unnecessary permissions",
            "Use HTTPS instead of HTTP",
            "Update the certificate",
            "Obfuscate the code with ProGuard"
        )
        val json = remediationConverter.fromList(original)
        val result = remediationConverter.fromString(json)
        assertEquals(4, result.size)
        assertEquals("Remove unnecessary permissions", result[0])
        assertEquals("Use HTTPS instead of HTTP", result[1])
        assertEquals("Update the certificate", result[2])
        assertEquals("Obfuscate the code with ProGuard", result[3])
    }

    @Test
    fun remediationConverter_invalidJson_returnsEmptyList() {
        val result = remediationConverter.fromString("not valid json")
        assertTrue(result.isEmpty())
    }

    @Test
    fun remediationConverter_malformedArray_returnsEmptyList() {
        val result = remediationConverter.fromString("[\"broken")
        assertTrue(result.isEmpty())
    }

    @Test
    fun remediationConverter_emptyJsonArray_returnsEmptyList() {
        val result = remediationConverter.fromString("[]")
        assertTrue(result.isEmpty())
    }

    @Test
    fun remediationConverter_veryLongStrings_roundTrips() {
        val longStr = "C".repeat(20000)
        val original = listOf(longStr)
        val json = remediationConverter.fromList(original)
        val result = remediationConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals(longStr, result[0])
    }

    @Test
    fun remediationConverter_specialCharacters_roundTrips() {
        val original = listOf(
            "Fix: \"quotes\" & 'apos' <tags>",
            "Unicode: \u00e9\u00e0\u00fc\u00f1\u00df \u4e2d\u6587",
            "Newlines\nand\ttabs"
        )
        val json = remediationConverter.fromList(original)
        val result = remediationConverter.fromString(json)
        assertEquals(3, result.size)
        assertEquals("Fix: \"quotes\" & 'apos' <tags>", result[0])
        assertEquals("Newlines\nand\ttabs", result[2])
    }

    @Test
    fun remediationConverter_serializationDeterministic() {
        val items = listOf("a", "b", "c")
        val json1 = remediationConverter.fromList(items)
        val json2 = remediationConverter.fromList(items)
        assertEquals(json1, json2)
    }

    @Test
    fun remediationConverter_emptyStringItem_roundTrips() {
        val original = listOf("")
        val json = remediationConverter.fromList(original)
        val result = remediationConverter.fromString(json)
        assertEquals(1, result.size)
        assertEquals("", result[0])
    }

    // --- Database singleton tests ---

    @Test
    fun databaseGetInstance_returnsSameInstance() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val db1 = AppDatabase.getInstance(ctx)
        val db2 = AppDatabase.getInstance(ctx)
        assertSame(db1, db2)
        db1.close()
    }

    @Test
    fun databaseGetInstance_isNotNull() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val db = AppDatabase.getInstance(ctx)
        assertNotNull(db)
        assertNotNull(db.scanDao())
        db.close()
    }

    @Test
    fun databaseGetInstance_multipleContexts_returnsSameInstance() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val db1 = AppDatabase.getInstance(ctx)
        val db2 = AppDatabase.getInstance(ctx.applicationContext)
        assertSame(db1, db2)
        db1.close()
    }
}
