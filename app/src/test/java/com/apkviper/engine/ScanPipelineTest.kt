package com.apkviper.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ScanPipelineTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun constructor_createsInstance() {
        val pipeline = ScanPipeline(context)
        assertNotNull(pipeline)
    }

    @Test
    fun shutdown_doesNotCrash() {
        val pipeline = ScanPipeline(context)
        pipeline.shutdown()
    }

    @Test
    fun shutdown_calledTwice_doesNotCrash() {
        val pipeline = ScanPipeline(context)
        pipeline.shutdown()
        pipeline.shutdown()
    }

    @Test
    fun scan_withInvalidContentUri_throwsExtractionException() {
        runBlocking<Unit> {
            val pipeline = ScanPipeline(context)
            try {
                pipeline.scan(
                    apkUri = "content://nonexistent.authority/path",
                    apkName = "test.apk",
                    onProgress = { _, _, _ -> },
                    onFinding = { _, _ -> },
                    onLog = { _, _ -> }
                )
                fail("scan() should throw when URI is invalid")
            } catch (e: Exception) {
                assertNotNull("Exception should have a message", e.message)
            }
        }
    }

    @Test
    fun scan_withNonexistentFileUri_throwsExtractionException() {
        runBlocking<Unit> {
            val pipeline = ScanPipeline(context)
            try {
                pipeline.scan(
                    apkUri = "file:///nonexistent_dir/foo.apk",
                    apkName = "foo.apk",
                    onProgress = { _, _, _ -> },
                    onFinding = { _, _ -> },
                    onLog = { _, _ -> }
                )
                fail("scan() should throw when file does not exist")
            } catch (e: Exception) {
                assertNotNull("Exception should have a message", e.message)
            }
        }
    }

    @Test
    fun scan_cancellation_stopsGracefully() {
        runBlocking<Unit> {
            val pipeline = ScanPipeline(context)
            val job = launch(Dispatchers.IO) {
                try {
                    pipeline.scan(
                        apkUri = "content://nonexistent/path",
                        apkName = "test.apk",
                        onProgress = { _, _, _ -> },
                        onFinding = { _, _ -> },
                        onLog = { _, _ -> }
                    )
                } catch (_: CancellationException) {
                    // Expected: cancellation before/during extraction
                } catch (_: Exception) {
                    // Expected: extraction failure due to content resolver
                }
            }
            yield()
            job.cancelAndJoin()
        }
    }

    @Test
    fun formatSize_zeroBytes_returnsB() {
        assertEquals("0 B", invokeFormatSize(0L))
    }

    @Test
    fun formatSize_under1KB_returnsBytes() {
        assertEquals("1023 B", invokeFormatSize(1023L))
    }

    @Test
    fun formatSize_exactly1KB_returnsKB() {
        assertEquals("1 KB", invokeFormatSize(1024L))
    }

    @Test
    fun formatSize_1MB_returnsMB() {
        assertEquals("1.0 MB", invokeFormatSize(1048576L))
    }

    @Test
    fun formatSize_1GB_returnsMB() {
        assertEquals("1.00 GB", invokeFormatSize(1073741824L))
    }

    @Test
    fun formatSize_negative_handled() {
        val result = invokeFormatSize(-1L)
        assertTrue("Negative size should still produce output", result.isNotBlank())
    }

    @Test
    fun scan_errorLogsViaOnLogCallback() {
        runBlocking<Unit> {
            val pipeline = ScanPipeline(context)
            val logMessages = mutableListOf<String>()
            try {
                pipeline.scan(
                    apkUri = "file:///nonexistent_test.apk",
                    apkName = "nonexistent_test.apk",
                    onProgress = { _, _, _ -> },
                    onFinding = { _, _ -> },
                    onLog = { msg, _ -> logMessages.add(msg) }
                )
            } catch (_: Exception) {
            }
            assertTrue(
                "Should have logged an error about extraction failure, got: $logMessages",
                logMessages.any { it.contains("extract", ignoreCase = true) }
            )
        }
    }

    @Test
    fun cancel_setsParseCancelledFlag() {
        val pipeline = ScanPipeline(context)
        assertFalse(pipeline.parseCancelled)
        pipeline.cancel()
        assertTrue(pipeline.parseCancelled)
    }

    @Test
    fun cancel_thenShutdown_isSafe() {
        val pipeline = ScanPipeline(context)
        pipeline.cancel()
        pipeline.shutdown()
        assertTrue(pipeline.parseCancelled)
    }

    @Test
    fun shutdown_thenCancel_isSafe() {
        val pipeline = ScanPipeline(context)
        pipeline.shutdown()
        pipeline.cancel()
        assertTrue(pipeline.parseCancelled)
    }

    private fun invokeFormatSize(bytes: Long): String {
        val pipeline = ScanPipeline(context)
        val method = ScanPipeline::class.java.getDeclaredMethod(
            "formatSize", Long::class.javaPrimitiveType
        )
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return method.invoke(pipeline, bytes) as String
    }
}
