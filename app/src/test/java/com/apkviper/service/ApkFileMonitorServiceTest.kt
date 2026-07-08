package com.apkviper.service

import android.app.NotificationManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ApkFileMonitorServiceTest {

    private lateinit var service: ApkFileMonitorService

    @Before
    fun setUp() {
        service = Robolectric.buildService(ApkFileMonitorService::class.java).create().get()
    }

    @Test
    fun companionConstants_haveExpectedValues() {
        assertEquals("apk_monitor", ApkFileMonitorService.CHANNEL_ID)
        assertEquals(2001, ApkFileMonitorService.NOTIFICATION_ID)
    }

    @Test
    fun createChannels_createsApkMonitorChannel() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        ApkFileMonitorService.createChannels(context)
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = nm.getNotificationChannel(ApkFileMonitorService.CHANNEL_ID)
        assertNotNull("apk_monitor channel must exist", channel)
        assertEquals(NotificationManager.IMPORTANCE_DEFAULT, channel.importance)
    }

    @Test
    fun onCreate_createsChannel() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        assertNotNull(nm.getNotificationChannel(ApkFileMonitorService.CHANNEL_ID))
    }

    @Test
    fun onStartCommand_withNullIntent_returnsSticky() {
        val result = service.onStartCommand(null, 0, 1)
        assertEquals(android.app.Service.START_STICKY, result)
    }

    @Test
    fun onStartCommand_withIntent_returnsSticky() {
        val result = service.onStartCommand(android.content.Intent(service, ApkFileMonitorService::class.java), 0, 1)
        assertEquals(android.app.Service.START_STICKY, result)
    }

    @Test
    fun onBind_returnsNull() {
        assertNull(service.onBind(android.content.Intent(service, ApkFileMonitorService::class.java)))
    }

    @Test
    fun onDestroy_doesNotThrow() {
        service.onDestroy()
    }

    @Test
    fun onDestroy_withActiveObserver_doesNotThrow() {
        // onCreate already attempted to start observing; destroying must not crash.
        service.onDestroy()
        service.onDestroy()
    }
}
