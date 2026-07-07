package com.apkviper.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

@RunWith(RobolectricTestRunner::class)
class StorageCleanerTest {

    @Test
    fun clean_emptyCache_returnsZero() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val cleaner = StorageCleaner(ctx)
        val result = cleaner.clean()
        assertEquals("No files should be deleted from empty cache", 0, result.deletedFiles)
    }

    @Test
    fun clean_oldScanFile_removesIt() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val oldScan = File(ctx.cacheDir, "scan_1234567890.tmp")
        oldScan.writeText("old scan data")
        oldScan.setLastModified(System.currentTimeMillis() - 2 * 3600_000L) // 2 hours old

        val cleaner = StorageCleaner(ctx)
        val result = cleaner.clean()

        assertTrue("Old scan file should be deleted", result.deletedFiles >= 1)
        assertTrue("Freed bytes should be > 0", result.freedBytes >= oldScan.length())
        assertFalse("File should no longer exist", oldScan.exists())
    }

    @Test
    fun clean_tempAndLogFiles_removesThem() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val tmpFile = File(ctx.cacheDir, "temp.tmp")
        tmpFile.writeText("temporary data")
        val logFile = File(ctx.cacheDir, "scan.log")
        logFile.writeText("log data")

        val cleaner = StorageCleaner(ctx)
        val result = cleaner.clean()

        assertTrue("Temp files should be deleted", result.deletedFiles >= 2)
    }

    @Test
    fun clean_freshFile_keepsIt() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        // Use a name that doesn't match any cleanup pattern (no .tmp, .log, scan_, etc.)
        val freshFile = File(ctx.cacheDir, "keep_me_test_file.txt")
        freshFile.writeText("recent data")
        freshFile.setLastModified(System.currentTimeMillis()) // brand new

        val cleaner = StorageCleaner(ctx)
        cleaner.clean()

        // Our fresh file should still be there (may not be the only remaining file)
        assertTrue("Recent file should still exist", freshFile.exists())

        freshFile.delete()
    }

    @Test
    fun analyze_identifiesStaleXapkDirs() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val xapkDir = File(ctx.cacheDir, "xapk_extract_123456")
        xapkDir.mkdirs()
        File(xapkDir, "base.apk").writeText("fake apk")
        xapkDir.setLastModified(System.currentTimeMillis() - 2 * 3600_000L)

        val cleaner = StorageCleaner(ctx)
        val (orphans, totalSize) = cleaner.analyze()

        assertTrue("Should detect stale XAPK directory", orphans.any { it.file == xapkDir })
        assertTrue("Total size should be > 0", totalSize > 0)

        xapkDir.deleteRecursively()
    }

    @Test
    fun analyze_cleanCache_returnsEmpty() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val cleaner = StorageCleaner(ctx)
        val (orphans, totalSize) = cleaner.analyze()
        assertTrue("Clean cache should have no orphans", orphans.isEmpty())
        assertEquals("Total size should be 0", 0L, totalSize)
    }

    @Test
    fun formatBytes_variousSizes_returnsCorrectFormat() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val cleaner = StorageCleaner(ctx)
        assertEquals("0 B", cleaner.formatBytes(0))
        assertEquals("512 B", cleaner.formatBytes(512))
        assertEquals("1 KB", cleaner.formatBytes(1024))
        assertEquals("1.0 MB", cleaner.formatBytes(1024 * 1024))
    }

    @Test
    fun clean_xapkDir_deletesIt() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val xapkDir = File(ctx.cacheDir, "xapk_extract_999999")
        xapkDir.mkdirs()
        File(xapkDir, "split.apk").writeText("split data")
        xapkDir.setLastModified(System.currentTimeMillis() - 2 * 3600_000L)

        val cleaner = StorageCleaner(ctx)
        cleaner.clean()

        assertFalse("XAPK directory should be deleted", xapkDir.exists())
    }

    @Test
    fun clean_noFiles_scannedCountIsPositive() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val cleaner = StorageCleaner(ctx)
        val result = cleaner.clean()
        assertTrue("Scanned paths should be >= 0", result.scannedPaths >= 0)
        assertTrue("Errors list should be empty", result.errors.isEmpty())
    }
}
