package com.apkviper.ui.results

import org.junit.Assert.*
import org.junit.Test

class ResultsScreenTest {

    @Test
    fun formatSize_zeroBytes() {
        assertEquals("0 B", formatSize(0L))
    }

    @Test
    fun formatSize_subKb() {
        assertEquals("512 B", formatSize(512L))
    }

    @Test
    fun formatSize_exactlyOneKb() {
        // 1024 bytes -> 1 KB
        assertEquals("1 KB", formatSize(1024L))
    }

    @Test
    fun formatSize_kbRange() {
        assertEquals("10 KB", formatSize(10L * 1024))
    }

    @Test
    fun formatSize_exactlyOneMb() {
        assertEquals("1.0 MB", formatSize(1024L * 1024))
    }

    @Test
    fun formatSize_mbRange_usesOneDecimal() {
        assertEquals("2.5 MB", formatSize((2.5 * 1024 * 1024).toLong()))
    }

    @Test
    fun formatSize_largeMb() {
        assertEquals("100.0 MB", formatSize(100L * 1024 * 1024))
    }

    @Test
    fun formatSize_negativeBytes_treatedAsBytes() {
        // Defensive: negative sizes should not crash or emit NaN/MB.
        val s = formatSize(-5L)
        assertTrue(s.endsWith(" B"))
        assertFalse(s.contains("NaN"))
    }

    @Test
    fun formatSize_isLocaleIndependent() {
        // Must not emit locale-specific digits (e.g. Arabic ٠). Locale.ROOT is used.
        val s = formatSize((2.5 * 1024 * 1024).toLong())
        assertEquals("2.5 MB", s)
        assertTrue(s.all { it.isDigit() || it == '.' || it == ' ' || it == 'B' || it == 'K' || it == 'M' })
    }
}
