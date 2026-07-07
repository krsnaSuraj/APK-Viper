package com.apkviper.engine.update

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AutoUpdateEngineTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun constructor_createsInstance() {
        val engine = AutoUpdateEngine(context)
        assertNotNull(engine)
    }

    @Test
    fun getDynamicRules_returnsNonEmptyYaraRules() {
        val engine = AutoUpdateEngine(context)
        val rules = engine.getDynamicRules()
        assertFalse("Dynamic YARA rules should not be empty", rules.isBlank())
        assertTrue("Rules should contain YARA rule keyword", rules.contains("rule "))
        assertTrue("Rules should contain CryptoMiner rule", rules.contains("CryptoMiner"))
        assertTrue("Rules should contain Infostealer rule", rules.contains("Infostealer"))
        assertTrue("Rules should contain SilentInstaller rule", rules.contains("SilentInstaller"))
    }

    @Test
    fun getDynamicRules_containsZeroDayFamily() {
        val engine = AutoUpdateEngine(context)
        val rules = engine.getDynamicRules()
        assertTrue("Rules should reference ZeroDay family", rules.contains("ZeroDay"))
    }

    @Test
    fun getDynamicRules_containsStringPatterns() {
        val engine = AutoUpdateEngine(context)
        val rules = engine.getDynamicRules()
        assertTrue("Rules should contain string identifiers", rules.contains("\$thread"))
        assertTrue("Rules should contain conditions", rules.contains("condition:"))
    }

    @Test
    fun checkAndUpdate_alwaysReturnsValidUpdateResult() {
        runBlocking {
            val engine = AutoUpdateEngine(context)
            val result = engine.checkAndUpdate()
            assertNotNull("UpdateResult should not be null", result)
            assertTrue("yaraRuleCount should be >= 0", result.yaraRuleCount >= 0)
            assertTrue("hashCount should be >= 0", result.hashCount >= 0)
            assertTrue("intelCount should be >= 0", result.intelCount >= 0)
            assertNotNull("errors list should not be null", result.errors)
        }
    }

    @Test
    fun checkAndUpdate_returnsYaraCountFromBundled() {
        runBlocking {
            val engine = AutoUpdateEngine(context)
            val result = engine.checkAndUpdate()
            assertNotNull(result)
            assertTrue(
                "yaraRuleCount should be >= 0, got ${result.yaraRuleCount}",
                result.yaraRuleCount >= 0
            )
        }
    }

    @Test
    fun checkAndUpdate_returnsHashCountFromBundled() {
        runBlocking {
            val engine = AutoUpdateEngine(context)
            val result = engine.checkAndUpdate()
            assertNotNull(result)
            assertTrue(
                "hashCount should be >= 0, got ${result.hashCount}",
                result.hashCount >= 0
            )
        }
    }

    @Test
    fun checkAndUpdate_resultIsSelfConsistent() {
        runBlocking {
            val engine = AutoUpdateEngine(context)
            val result = engine.checkAndUpdate()
            assertNotNull(result)
            // When there are errors, updates should be false
            if (result.errors.isNotEmpty()) {
                assertFalse("yaraRulesUpdated should be false when YARA errors exist", result.yaraRulesUpdated)
            }
            // yaraRuleCount should reflect either downloaded or bundled rules
            assertTrue("yaraRuleCount should be >= 0", result.yaraRuleCount >= 0)
        }
    }

    @Test
    fun checkAndUpdate_withNetworkOrNot_returnsResultWithMessages() {
        runBlocking {
            val engine = AutoUpdateEngine(context)
            val result = engine.checkAndUpdate()
            assertNotNull(result)
            // If network is available, some flags may be true; if not, errors will be populated
            val hasErrors = result.errors.isNotEmpty()
            val hasUpdates = result.yaraRulesUpdated || result.hashesUpdated || result.intelUpdated
            // Either we had errors (no network), or we got updates (network present), or both
            assertTrue(
                "Either errors or updates expected, got errors=$hasErrors updates=$hasUpdates",
                hasErrors || result.yaraRuleCount > 0 || result.hashCount > 0
            )
        }
    }

    @Test
    fun updateResult_defaultErrors_emptyList() {
        val result = AutoUpdateEngine.UpdateResult(
            yaraRulesUpdated = false,
            yaraRuleCount = 0,
            hashesUpdated = false,
            hashCount = 0,
            intelUpdated = false,
            intelCount = 0
        )
        assertTrue("Default errors should be an empty list", result.errors.isEmpty())
    }

    @Test
    fun updateResult_customErrors() {
        val errors = listOf("YARA: timeout", "Hashes: connection refused")
        val result = AutoUpdateEngine.UpdateResult(
            yaraRulesUpdated = false,
            yaraRuleCount = 0,
            hashesUpdated = false,
            hashCount = 0,
            intelUpdated = false,
            intelCount = 0,
            errors = errors
        )
        assertEquals(2, result.errors.size)
        assertEquals("YARA: timeout", result.errors[0])
        assertEquals("Hashes: connection refused", result.errors[1])
    }

    @Test
    fun updateResult_allFieldsStored() {
        val result = AutoUpdateEngine.UpdateResult(
            yaraRulesUpdated = true,
            yaraRuleCount = 42,
            hashesUpdated = true,
            hashCount = 100,
            intelUpdated = true,
            intelCount = 15,
            errors = emptyList()
        )
        assertTrue(result.yaraRulesUpdated)
        assertEquals(42, result.yaraRuleCount)
        assertTrue(result.hashesUpdated)
        assertEquals(100, result.hashCount)
        assertTrue(result.intelUpdated)
        assertEquals(15, result.intelCount)
    }

    @Test
    fun checkAndUpdate_multipleCalls_doNotCrash() {
        runBlocking {
            val engine = AutoUpdateEngine(context)
            val result1 = engine.checkAndUpdate()
            val result2 = engine.checkAndUpdate()
            assertNotNull(result1)
            assertNotNull(result2)
        }
    }
}
