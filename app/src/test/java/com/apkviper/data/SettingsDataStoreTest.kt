package com.apkviper.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SettingsDataStoreTest {

    private lateinit var context: Context
    private lateinit var settings: SettingsDataStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        settings = SettingsDataStore(context)
    }

    @Test
    fun setAutoUpdate_false_reflectedInFlow() = runBlocking {
        settings.setAutoUpdate(false)
        assertEquals(false, settings.autoUpdate.first())
    }

    @Test
    fun setAutoUpdate_true_reflectedInFlow() = runBlocking {
        settings.setAutoUpdate(true)
        assertEquals(true, settings.autoUpdate.first())
    }

    @Test
    fun setAutoUpdate_toggleValues_reflectedCorrectly() = runBlocking {
        settings.setAutoUpdate(true)
        assertEquals(true, settings.autoUpdate.first())

        settings.setAutoUpdate(false)
        assertEquals(false, settings.autoUpdate.first())

        settings.setAutoUpdate(true)
        assertEquals(true, settings.autoUpdate.first())
    }

    @Test
    fun updateSignatureStatus_allValues_reflectedInFlows() = runBlocking {
        settings.updateSignatureStatus(
            yaraCount = 100L,
            hashCount = 500L,
            ipCount = 25L,
            domainCount = 40L
        )

        assertEquals(100L, settings.yaraRuleCount.first())
        assertEquals(500L, settings.hashDbSize.first())
        assertEquals(25L, settings.intelIpCount.first())
        assertEquals(40L, settings.intelDomainCount.first())
    }

    @Test
    fun updateSignatureStatus_timestampUpdated() = runBlocking {
        settings.updateSignatureStatus(1L, 2L, 3L, 4L)
        val ts = settings.lastUpdateTimestamp.first()
        assertTrue("Timestamp should be positive after update", ts > 0)
    }

    @Test
    fun updateSignatureStatus_zeros_areStored() = runBlocking {
        settings.updateSignatureStatus(0L, 0L, 0L, 0L)

        assertEquals(0L, settings.yaraRuleCount.first())
        assertEquals(0L, settings.hashDbSize.first())
        assertEquals(0L, settings.intelIpCount.first())
        assertEquals(0L, settings.intelDomainCount.first())
    }

    @Test
    fun updateSignatureStatus_veryLargeNumbers_areStored() = runBlocking {
        settings.updateSignatureStatus(
            yaraCount = Long.MAX_VALUE,
            hashCount = Long.MAX_VALUE,
            ipCount = Long.MAX_VALUE,
            domainCount = Long.MAX_VALUE
        )

        assertEquals(Long.MAX_VALUE, settings.yaraRuleCount.first())
        assertEquals(Long.MAX_VALUE, settings.hashDbSize.first())
        assertEquals(Long.MAX_VALUE, settings.intelIpCount.first())
        assertEquals(Long.MAX_VALUE, settings.intelDomainCount.first())
    }

    @Test
    fun updateSignatureStatus_callMultipleTimes_overwritesCorrectly() = runBlocking {
        settings.updateSignatureStatus(10L, 20L, 30L, 40L)
        settings.updateSignatureStatus(50L, 60L, 70L, 80L)

        assertEquals(50L, settings.yaraRuleCount.first())
        assertEquals(60L, settings.hashDbSize.first())
        assertEquals(70L, settings.intelIpCount.first())
        assertEquals(80L, settings.intelDomainCount.first())
    }

    @Test
    fun flows_remainConsistent_afterMultipleWrites() = runBlocking {
        settings.setAutoUpdate(false)
        settings.updateSignatureStatus(5L, 10L, 15L, 20L)

        assertEquals(false, settings.autoUpdate.first())
        assertEquals(5L, settings.yaraRuleCount.first())
        assertEquals(10L, settings.hashDbSize.first())
        assertEquals(15L, settings.intelIpCount.first())
        assertEquals(20L, settings.intelDomainCount.first())
        assertTrue(settings.lastUpdateTimestamp.first() > 0)
    }

    @Test
    fun updateSignatureStatus_onlyAffectsSignatureFlows_notAutoUpdate() = runBlocking {
        settings.setAutoUpdate(false)
        settings.updateSignatureStatus(99L, 199L, 299L, 399L)

        assertEquals(false, settings.autoUpdate.first())
    }

    @Test
    fun setAutoUpdate_onlyAffectsAutoUpdate_notSignatureFlows() = runBlocking {
        settings.updateSignatureStatus(7L, 8L, 9L, 10L)
        settings.setAutoUpdate(true)

        assertEquals(7L, settings.yaraRuleCount.first())
        assertEquals(8L, settings.hashDbSize.first())
    }
}
