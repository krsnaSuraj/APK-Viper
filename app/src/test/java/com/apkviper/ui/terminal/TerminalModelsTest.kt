package com.apkviper.ui.terminal

import org.junit.Assert.*
import org.junit.Test

class TerminalModelsTest {

    @Test
    fun lineType_hasAllExpectedValues() {
        val values = LineType.values()
        assertEquals(7, values.size)
        assertTrue(values.contains(LineType.INFO))
        assertTrue(values.contains(LineType.WARNING))
        assertTrue(values.contains(LineType.DANGER))
        assertTrue(values.contains(LineType.SUCCESS))
        assertTrue(values.contains(LineType.HEADER))
        assertTrue(values.contains(LineType.OUTPUT))
        assertTrue(values.contains(LineType.SYSTEM))
    }

    @Test
    fun logEntry_defaultValues_usesOutputType() {
        val entry = LogEntry("test message")
        assertEquals("test message", entry.text)
        assertEquals(LineType.OUTPUT, entry.type)
        assertTrue(entry.timestamp > 0)
        assertTrue(entry.id > 0)
    }

    @Test
    fun logEntry_customType_reflected() {
        val entry = LogEntry("warning!", LineType.WARNING)
        assertEquals("warning!", entry.text)
        assertEquals(LineType.WARNING, entry.type)
    }

    @Test
    fun logEntry_idsAreIncrementing() {
        val e1 = LogEntry("a")
        val e2 = LogEntry("b")
        assertEquals(e1.id + 1, e2.id)
    }

    @Test
    fun logEntry_idsAreUnique() {
        val ids = (1..100).map { LogEntry("x" + it).id }.toSet()
        assertEquals(100, ids.size)
    }

    @Test
    fun logEntry_equalTextDifferentType_notEqual() {
        val info = LogEntry("msg", LineType.INFO)
        val warn = LogEntry("msg", LineType.WARNING)
        assertNotEquals(info, warn)
    }

    @Test
    fun logEntry_timestampsAreReasonable() {
        val before = System.currentTimeMillis()
        val entry = LogEntry("timing test")
        val after = System.currentTimeMillis()
        assertTrue(entry.timestamp >= before)
        assertTrue(entry.timestamp <= after + 100)
    }

    @Test
    fun logEntry_timestampCanBeExplicit() {
        val fixed = 12345L
        val entry = LogEntry("explicit", LogEntry("dummy").type, fixed, 999L)
        assertEquals(fixed, entry.timestamp)
        assertEquals(999L, entry.id)
    }

    @Test
    fun terminalTemplates_scanStart_returnsThreeEntries() {
        val entries = TerminalTemplates.scanStart("test.apk", "brutal")
        assertEquals(3, entries.size)
        assertEquals(LineType.INFO, entries[0].type)
        assertTrue(entries[0].text.contains("test.apk"))
        assertEquals(LineType.INFO, entries[1].type)
        assertTrue(entries[1].text.contains("BRUTAL"))
        assertEquals(LineType.SYSTEM, entries[2].type)
        assertTrue(entries[2].text.contains("Timestamp"))
    }

    @Test
    fun terminalTemplates_scanStart_emptyFilename_stillValid() {
        val entries = TerminalTemplates.scanStart("", "standard")
        assertEquals(3, entries.size)
        assertTrue(entries[0].text.contains("Scan started for"))
        assertTrue(entries[1].text.contains("STANDARD"))
    }

    @Test
    fun terminalTemplates_scanPhase_returnsInfoEntry() {
        val entry = TerminalTemplates.scanPhase(3, 8, "Analyzing DEX")
        assertEquals(LineType.INFO, entry.type)
        assertEquals("Phase 3/8: Analyzing DEX", entry.text)
    }

    @Test
    fun terminalTemplates_scanPhase_edgePhases_formatsCorrectly() {
        val first = TerminalTemplates.scanPhase(1, 8, "Start")
        assertEquals("Phase 1/8: Start", first.text)

        val last = TerminalTemplates.scanPhase(8, 8, "Finalize")
        assertEquals("Phase 8/8: Finalize", last.text)
    }

    @Test
    fun terminalTemplates_scanFinding_criticalMapsToDanger() {
        val entry = TerminalTemplates.scanFinding("CRITICAL", "Critical issue found")
        assertEquals(LineType.DANGER, entry.type)
        assertEquals("Critical issue found", entry.text)
    }

    @Test
    fun terminalTemplates_scanFinding_highMapsToDanger() {
        val entry = TerminalTemplates.scanFinding("HIGH", "High risk")
        assertEquals(LineType.DANGER, entry.type)
    }

    @Test
    fun terminalTemplates_scanFinding_mediumMapsToWarning() {
        val entry = TerminalTemplates.scanFinding("MEDIUM", "Medium risk")
        assertEquals(LineType.WARNING, entry.type)
    }

    @Test
    fun terminalTemplates_scanFinding_lowMapsToInfo() {
        val entry = TerminalTemplates.scanFinding("LOW", "Low risk")
        assertEquals(LineType.INFO, entry.type)
    }

    @Test
    fun terminalTemplates_scanFinding_infoMapsToInfo() {
        val entry = TerminalTemplates.scanFinding("INFO", "Informational")
        assertEquals(LineType.INFO, entry.type)
    }

    @Test
    fun terminalTemplates_scanFinding_unknownSeverityDefaultsToWarning() {
        val entry = TerminalTemplates.scanFinding("UNKNOWN", "Unknown")
        assertEquals(LineType.WARNING, entry.type)
    }

    @Test
    fun terminalTemplates_scanFinding_caseInsensitiveSeverity() {
        assertEquals(LineType.DANGER, TerminalTemplates.scanFinding("critical", "x").type)
        assertEquals(LineType.DANGER, TerminalTemplates.scanFinding("Critical", "x").type)
        assertEquals(LineType.WARNING, TerminalTemplates.scanFinding("medium", "x").type)
        assertEquals(LineType.INFO, TerminalTemplates.scanFinding("low", "x").type)
    }

    @Test
    fun terminalTemplates_scanFinding_emptySeverity_defaultsToWarning() {
        val entry = TerminalTemplates.scanFinding("", "Empty severity")
        assertEquals(LineType.WARNING, entry.type)
    }

    @Test
    fun terminalTemplates_scanFinding_emptyMessage_preservesEmptyText() {
        val entry = TerminalTemplates.scanFinding("HIGH", "")
        assertEquals("", entry.text)
        assertEquals(LineType.DANGER, entry.type)
    }

    @Test
    fun terminalTemplates_scanComplete_score70plus_danger() {
        val entries = TerminalTemplates.scanComplete(70, "CRITICAL")
        assertEquals(2, entries.size)
        assertEquals(LineType.SUCCESS, entries[0].type)
        assertEquals(LineType.DANGER, entries[1].type)
        assertTrue(entries[1].text.contains("70/100"))
        assertTrue(entries[1].text.contains("CRITICAL"))
    }

    @Test
    fun terminalTemplates_scanComplete_score99_danger() {
        assertEquals(LineType.DANGER, TerminalTemplates.scanComplete(99, "HIGH")[1].type)
    }

    @Test
    fun terminalTemplates_scanComplete_score50to69_warning() {
        val entries = TerminalTemplates.scanComplete(50, "MEDIUM")
        assertEquals(LineType.SUCCESS, entries[0].type)
        assertEquals(LineType.WARNING, entries[1].type)
        assertTrue(entries[1].text.contains("50/100"))

        assertEquals(LineType.WARNING, TerminalTemplates.scanComplete(69, "MEDIUM")[1].type)
    }

    @Test
    fun terminalTemplates_scanComplete_score30to49_info() {
        val entries = TerminalTemplates.scanComplete(30, "LOW")
        assertEquals(LineType.INFO, entries[1].type)

        assertEquals(LineType.INFO, TerminalTemplates.scanComplete(49, "LOW")[1].type)
    }

    @Test
    fun terminalTemplates_scanComplete_scoreBelow30_success() {
        val entries = TerminalTemplates.scanComplete(0, "SAFE")
        assertEquals(LineType.SUCCESS, entries[1].type)

        assertEquals(LineType.SUCCESS, TerminalTemplates.scanComplete(29, "SAFE")[1].type)
    }

    @Test
    fun terminalTemplates_scanComplete_boundaryValues() {
        assertEquals(LineType.DANGER, TerminalTemplates.scanComplete(70, "x")[1].type)
        assertEquals(LineType.WARNING, TerminalTemplates.scanComplete(50, "x")[1].type)
        assertEquals(LineType.INFO, TerminalTemplates.scanComplete(30, "x")[1].type)
        assertEquals(LineType.SUCCESS, TerminalTemplates.scanComplete(0, "x")[1].type)
    }

    @Test
    fun terminalTemplates_scanComplete_negativeScore_usesSuccess() {
        val entries = TerminalTemplates.scanComplete(-1, "INVALID")
        assertEquals(LineType.SUCCESS, entries[1].type)
    }
}
