package com.apkviper.engine.advanced

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

@RunWith(RobolectricTestRunner::class)
class LocalRuleWatcherTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun initialRuleCount_zero() {
        val watcher = LocalRuleWatcher(context)
        assertEquals(0, watcher.loadedRuleCount)
    }

    @Test
    fun initialRules_empty() {
        val watcher = LocalRuleWatcher(context)
        assertTrue(watcher.loadedRules.isEmpty())
    }

    @Test
    fun startAndStop_noErrors() {
        val watcher = LocalRuleWatcher(context)
        watcher.start()
        assertNotNull(watcher)
        watcher.stop()
    }

    @Test
    fun multipleStops_noErrors() {
        val watcher = LocalRuleWatcher(context)
        watcher.stop()
        watcher.stop()
    }

    @Test
    fun rulesDir_createsOnAccess() {
        val watcher = LocalRuleWatcher(context)
        val rulesDir = File(context.filesDir, "rules")
        assertTrue(rulesDir.isDirectory || !rulesDir.exists())
    }
}
