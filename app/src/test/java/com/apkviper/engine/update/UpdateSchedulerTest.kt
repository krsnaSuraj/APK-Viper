package com.apkviper.engine.update

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class UpdateSchedulerTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun scheduleThenCancel_doesNotCrash() {
        UpdateScheduler.schedule(context)
        UpdateScheduler.cancel(context)
    }

    @Test
    fun cancelThenScheduleThenCancel_doesNotCrash() {
        UpdateScheduler.cancel(context)
        UpdateScheduler.schedule(context)
        UpdateScheduler.cancel(context)
    }

    @Test
    fun receiver_onReceive_nullIntent_doesNotCrash() {
        val receiver = UpdateSchedulerReceiver()
        receiver.onReceive(context, null)
    }

    @Test
    fun receiver_onReceive_validIntent_doesNotCrash() {
        val receiver = UpdateSchedulerReceiver()
        val intent = android.content.Intent(context, UpdateSchedulerReceiver::class.java)
        receiver.onReceive(context, intent)
    }

    @Test
    fun receiver_onReceiveWithAction_doesNotCrash() {
        val receiver = UpdateSchedulerReceiver()
        val intent = android.content.Intent("com.apkviper.action.SCHEDULED_UPDATE")
        receiver.onReceive(context, intent)
    }
}
