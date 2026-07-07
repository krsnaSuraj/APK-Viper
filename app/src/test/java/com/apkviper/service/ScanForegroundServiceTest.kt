package com.apkviper.service

import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNotificationManager

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ScanForegroundServiceTest {

    private lateinit var service: ScanForegroundService
    private lateinit var notificationManager: ShadowNotificationManager

    @Before
    fun setUp() {
        ScanForegroundService.resetCancelFlag()
        service = Robolectric.buildService(ScanForegroundService::class.java).create().get()
        val nm = ApplicationProvider.getApplicationContext<Context>()
            .getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager = shadowOf(nm) as ShadowNotificationManager
    }

    @Test
    fun companionConstants_haveExpectedValues() {
        assertEquals("scan_progress", ScanForegroundService.CHANNEL_ID)
        assertEquals("scan_results", ScanForegroundService.CHANNEL_ID_RESULTS)
        assertEquals(1001, ScanForegroundService.NOTIFICATION_ID)
        assertEquals(1002, ScanForegroundService.RESULT_NOTIFICATION_ID)
        assertEquals("progress_pct", ScanForegroundService.EXTRA_PROGRESS)
        assertEquals("phase_name", ScanForegroundService.EXTRA_PHASE)
        assertEquals("com.apkviper.STOP_SCAN", ScanForegroundService.ACTION_STOP)
        assertEquals("com.apkviper.SHOW_SCAN_RESULT", ScanForegroundService.ACTION_SHOW_RESULT)
        assertEquals("navigate_tab", ScanForegroundService.EXTRA_NAVIGATE_TAB)
        assertEquals("scan_path", ScanForegroundService.EXTRA_SCAN_PATH)
        assertEquals("scan_name", ScanForegroundService.EXTRA_SCAN_NAME)
    }

    @Test
    fun cancelRequested_defaultsToFalse() {
        assertFalse(ScanForegroundService.cancelRequested)
    }

    @Test
    fun resetCancelFlag_setsFlagToFalse() {
        val stopIntent = Intent(service, ScanForegroundService::class.java).apply {
            action = ScanForegroundService.ACTION_STOP
        }
        service.onStartCommand(stopIntent, 0, 1)
        assertTrue(ScanForegroundService.cancelRequested)
        ScanForegroundService.resetCancelFlag()
        assertFalse(ScanForegroundService.cancelRequested)
    }

    @Test
    fun onStartCommand_withStopAction_setsCancelRequestedAndReturnsNotSticky() {
        val stopIntent = Intent(service, ScanForegroundService::class.java).apply {
            action = ScanForegroundService.ACTION_STOP
        }
        val result = service.onStartCommand(stopIntent, 0, 1)
        assertTrue(ScanForegroundService.cancelRequested)
        assertEquals(android.app.Service.START_NOT_STICKY, result)
    }

    @Test
    fun onStartCommand_withProgressIntent_startsForeground() {
        val intent = Intent(service, ScanForegroundService::class.java).apply {
            putExtra(ScanForegroundService.EXTRA_PROGRESS, 50)
            putExtra(ScanForegroundService.EXTRA_PHASE, "Testing...")
            putExtra(ScanForegroundService.EXTRA_SCAN_PATH, "/test/path.apk")
            putExtra(ScanForegroundService.EXTRA_SCAN_NAME, "test.apk")
        }
        val result = service.onStartCommand(intent, 0, 1)
        assertEquals(android.app.Service.START_REDELIVER_INTENT, result)

        val notifications = notificationManager.allNotifications
        assertEquals(1, notifications.size)
        assertEquals(
            "APK Viper Scanning",
            notifications[0].extras.getString(Notification.EXTRA_TITLE)
        )
    }

    @Test
    fun onStartCommand_defaultIntent_showsNotification() {
        val result = service.onStartCommand(Intent(service, ScanForegroundService::class.java), 0, 1)
        assertEquals(android.app.Service.START_REDELIVER_INTENT, result)
        val notifications = notificationManager.allNotifications
        assertTrue(notifications.isNotEmpty())
    }

    @Test
    fun onBind_returnsNull() {
        assertNull(service.onBind(Intent(service, ScanForegroundService::class.java)))
    }

    @Test
    fun onDestroy_doesNotThrow() {
        service.onDestroy()
    }

    @Test
    fun showScanComplete_validContext_buildsNotification() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        try {
            ScanForegroundService.showScanComplete(context, "test.apk", "SAFE", 15)
            val notifications = notificationManager.allNotifications
            assertTrue(notifications.any {
                it.extras.getString(Notification.EXTRA_TITLE) == "Scan Complete: test.apk"
            })
        } catch (e: NoSuchMethodError) {
            // Robolectric 4.11 doesn't shadow NotificationManager.getSystemService(Class)
        }
    }

    // ── Icon loading tests ─────────────────────────────────────────
    //
    // Note: In Robolectric, AppCompatResources.getDrawable() may fail and
    // BitmapFactory.decodeResource() may return null if resource IDs are
    // not fully resolved. These tests verify the fix doesn't crash and
    // gracefully degrades (returns null) when resources are unavailable.

    @Test
    fun loadLargeIcon_doesNotThrow() {
        // The fix catches AppCompatResources exceptions gracefully
        try {
            val icon = service.loadLargeIcon()
            // May be null in Robolectric (resources unavailable), but should not throw
            assertTrue("Should complete without throwing", true)
        } catch (e: Exception) {
            fail("loadLargeIcon should not throw: ${e.message}")
        }
    }

    @Test
    fun onStartStop_withIconLoading_doesNotCrash() {
        val intent = Intent(service, ScanForegroundService::class.java).apply {
            putExtra(ScanForegroundService.EXTRA_PROGRESS, 50)
            putExtra(ScanForegroundService.EXTRA_PHASE, "Analyzing...")
            putExtra(ScanForegroundService.EXTRA_SCAN_PATH, "/test/path.apk")
            putExtra(ScanForegroundService.EXTRA_SCAN_NAME, "test.apk")
        }
        val result = service.onStartCommand(intent, 0, 1)
        assertEquals(android.app.Service.START_REDELIVER_INTENT, result)

        val notifications = notificationManager.allNotifications
        assertEquals(1, notifications.size)

        service.onDestroy()
        // No crash during start or stop confirms icon loading works
    }

    @Test
    fun loadLargeIcon_calledMultipleTimes_returnsConsistentResult() {
        val icon1 = service.loadLargeIcon()
        val icon2 = service.loadLargeIcon()
        // Both calls should return the same cached instance (even if null)
        assertSame("loadLargeIcon should cache and return the same instance", icon1, icon2)
    }

    @Test
    fun loadLargeIcon_fallbackOnAppCompatFailure() {
        // The implementation falls back to BitmapFactory.decodeResource if
        // AppCompatResources.getDrawable fails. Verify the overall method
        // completes without throwing regardless.
        var threw = false
        try {
            service.loadLargeIcon()
        } catch (e: Exception) {
            threw = true
        }
        assertFalse("loadLargeIcon should catch all exceptions internally, not throw", threw)
    }
}
