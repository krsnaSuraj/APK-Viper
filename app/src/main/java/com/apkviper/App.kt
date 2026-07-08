package com.apkviper

import android.app.Application
import com.apkviper.engine.update.UpdateScheduler
import com.apkviper.service.ApkFileMonitorService
import com.apkviper.service.ScanForegroundService
import java.util.Locale

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // Force English / US locale so all on-device number and date formatting
        // (threat scores, file sizes, timestamps, hashes) uses ASCII digits and
        // the Gregorian calendar - regardless of the device's language setting.
        // This keeps the app UI and generated PDFs fully English and avoids
        // locale-specific digits (e.g. Devanagari) rendering as missing glyphs.
        Locale.setDefault(Locale.US)
        ScanForegroundService.createChannels(this)
        ApkFileMonitorService.createChannels(this)
        UpdateScheduler.schedule(this)
    }
}
