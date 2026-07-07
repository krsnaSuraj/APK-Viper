package com.apkviper

import android.app.Application
import com.apkviper.engine.update.UpdateScheduler
import com.apkviper.service.ApkFileMonitorService
import com.apkviper.service.ScanForegroundService

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        ScanForegroundService.createChannels(this)
        ApkFileMonitorService.createChannels(this)
        UpdateScheduler.schedule(this)
    }
}
