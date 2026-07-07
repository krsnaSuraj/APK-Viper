package com.apkviper.engine.native

import com.apkviper.engine.native.FrameworkWhitelist.FrameworkSignature
import com.apkviper.engine.native.FrameworkWhitelist.SymbolOverride
import org.junit.Assert.*
import org.junit.Test

class FrameworkWhitelistTest {

    @Test
    fun matchUnityLibrary() {
        val match = FrameworkWhitelist.match("libunity.so")
        assertNotNull(match)
        assertEquals("Unity Engine", match?.name)
    }

    @Test
    fun matchFlutterLibrary() {
        val match = FrameworkWhitelist.match("libflutter.so")
        assertNotNull(match)
        assertEquals("Flutter", match?.name)
    }

    @Test
    fun matchWithFullPath() {
        val match = FrameworkWhitelist.match("/data/app/lib/arm64/libunity.so")
        assertNotNull(match)
        assertEquals("Unity Engine", match?.name)
    }

    @Test
    fun unknownLibrary_returnsNull() {
        val match = FrameworkWhitelist.match("libunknown_random.so")
        assertNull(match)
    }

    @Test
    fun emptyString_returnsNull() {
        assertNull(FrameworkWhitelist.match(""))
    }

    @Test
    fun partialMatchWorks() {
        val match = FrameworkWhitelist.match("libunity-native-trace.so")
        assertNotNull(match)
        assertEquals("Unity Engine", match?.name)
    }

    @Test
    fun matchCaseInsensitive() {
        val match = FrameworkWhitelist.match("LIBUNITY.SO")
        assertNotNull(match)
        assertEquals("Unity Engine", match?.name)
    }

    @Test
    fun downgradedInGameEngine() {
        val result = FrameworkWhitelist.getSymbolSeverityOverride("ptrace", "libunity.so")
        assertEquals(SymbolOverride.DOWNGRADE_TO_INFO, result)
    }

    @Test
    fun downgradedInCrashReporter() {
        val result = FrameworkWhitelist.getSymbolSeverityOverride("fork", "libbugsnag.so")
        assertEquals(SymbolOverride.DOWNGRADE_TO_INFO, result)
    }

    @Test
    fun networkInAdSdk_downgradedToLow() {
        val result = FrameworkWhitelist.getSymbolSeverityOverride("socket", "libapplovin.so")
        assertEquals(SymbolOverride.DOWNGRADE_TO_LOW, result)
    }

    @Test
    fun unknownSymbol_useOriginal() {
        val result = FrameworkWhitelist.getSymbolSeverityOverride("unknown_symbol_xyz", "libunity.so")
        assertEquals(SymbolOverride.USE_ORIGINAL, result)
    }

    @Test
    fun unknownLibrary_useOriginal() {
        val result = FrameworkWhitelist.getSymbolSeverityOverride("ptrace", "libunknown_xyz.so")
        assertEquals(SymbolOverride.USE_ORIGINAL, result)
    }

    @Test
    fun nonDowngradedSymbol_useOriginal() {
        val result = FrameworkWhitelist.getSymbolSeverityOverride("open", "libunity.so")
        assertEquals(SymbolOverride.USE_ORIGINAL, result)
    }

    @Test
    fun frameworksList_populated() {
        assertTrue(FrameworkWhitelist.frameworks.isNotEmpty())
        assertTrue(FrameworkWhitelist.frameworks.size >= 20)
    }

    @Test
    fun eachFrameworkHasNameAndPatterns() {
        for (fw in FrameworkWhitelist.frameworks) {
            assertTrue(fw.name.isNotBlank())
            assertTrue(fw.libPatterns.isNotEmpty())
            assertTrue(fw.category.isNotBlank())
        }
    }
}
