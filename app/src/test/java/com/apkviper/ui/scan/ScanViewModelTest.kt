package com.apkviper.ui.scan

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import com.apkviper.ui.terminal.LineType
import com.apkviper.ui.terminal.LogEntry
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ScanViewModelTest {

    private lateinit var application: Application
    private lateinit var viewModel: ScanViewModel

    @Before
    fun setUp() {
        ScanViewModel.activeScanPath = null
        application = ApplicationProvider.getApplicationContext()
        viewModel = ScanViewModel(application)
    }

    @Test
    fun scanUiState_defaultValues() {
        val state = ScanUiState()
        assertTrue(state.lines.isEmpty())
        assertFalse(state.isScanning)
        assertFalse(state.isPreparing)
        assertFalse(state.scanComplete)
        assertEquals(0, state.currentPhase)
        assertEquals(com.apkviper.engine.ScanPipeline.TOTAL_PHASE_COUNT, state.totalPhases)
        assertEquals(0f, state.progress, 0.001f)
        assertEquals("Preparing...", state.currentActivity)
        assertEquals(0, state.etaSeconds)
        assertNull(state.result)
        assertNull(state.errorMessage)
        assertEquals("", state.apkPath)
        assertEquals("", state.apkName)
    }

    @Test
    fun constructor_initializesSuccessfully() {
        assertNotNull(viewModel)
        assertNotNull(viewModel.uiState)
        assertNull(viewModel.lastCompletedResult)
    }

    @Test
    fun reset_returnsStateToDefaults() {
        viewModel.reset()
        val stateAfter = viewModel.uiState.value
        assertTrue(stateAfter.lines.isEmpty())
        assertFalse(stateAfter.isScanning)
        assertFalse(stateAfter.isPreparing)
        assertFalse(stateAfter.scanComplete)
        assertEquals(0f, stateAfter.progress, 0.001f)
        assertEquals("Preparing...", stateAfter.currentActivity)
        assertNull(stateAfter.errorMessage)
        assertNull(stateAfter.result)
        assertEquals("", stateAfter.apkPath)
        assertEquals("", stateAfter.apkName)
    }

    @Test
    fun reset_calledMultipleTimes_doesNotCrash() {
        viewModel.reset()
        viewModel.reset()
        viewModel.reset()
        val state = viewModel.uiState.value
        assertFalse(state.isScanning)
    }

    @Test
    fun cancelScan_withoutStarting_doesNotCrash() {
        viewModel.cancelScan()
        val state = viewModel.uiState.value
        assertFalse(state.isScanning)
    }

    @Test
    fun cancelScan_setsScanCancelledFlag() {
        viewModel.cancelScan()
        assertTrue(ScanViewModel.scanCancelled)
    }

    @Test
    fun cancelScan_afterReset_doesNotCrash() {
        viewModel.reset()
        viewModel.cancelScan()
        assertNull(viewModel.lastCompletedResult)
    }

    @Test
    fun lastCompletedResult_defaultsToNull() {
        assertNull(viewModel.lastCompletedResult)
    }

    @Test
    fun activeScanPath_readWrite() {
        assertNull(ScanViewModel.activeScanPath)
        ScanViewModel.activeScanPath = "/tmp/test.apk"
        assertEquals("/tmp/test.apk", ScanViewModel.activeScanPath)
        ScanViewModel.activeScanPath = null
        assertNull(ScanViewModel.activeScanPath)
    }

    @Test
    fun activeScanPath_multipleWrites() {
        ScanViewModel.activeScanPath = "/a.apk"
        assertEquals("/a.apk", ScanViewModel.activeScanPath)
        ScanViewModel.activeScanPath = "/b.apk"
        assertEquals("/b.apk", ScanViewModel.activeScanPath)
        ScanViewModel.activeScanPath = null
        assertNull(ScanViewModel.activeScanPath)
    }

    @Test
    fun uiState_isStateFlow() = runBlocking {
        val initial = viewModel.uiState.first()
        assertNotNull(initial)
    }

    @Test
    fun scanEventBus_emitCompleted_doesNotThrow() {
        ScanEventBus.emitCompleted()
    }

    @Test
    fun scanEventBus_emitCompleted_collectReceivesEvent() = runBlocking {
        val collected = mutableListOf<Unit>()
        val job = CoroutineScope(Dispatchers.Unconfined).launch {
            ScanEventBus.scanCompleted.collect { collected.add(it) }
        }
        ScanEventBus.emitCompleted()
        delay(100)
        job.cancel()
        assertTrue(collected.isNotEmpty())
        assertEquals(1, collected.size)
    }

    @Test
    fun scanEventBus_multipleEmissions_allReceived() = runBlocking {
        val collected = mutableListOf<Unit>()
        val job = CoroutineScope(Dispatchers.Unconfined).launch {
            ScanEventBus.scanCompleted.collect { collected.add(it) }
        }
        ScanEventBus.emitCompleted()
        ScanEventBus.emitCompleted()
        ScanEventBus.emitCompleted()
        delay(100)
        job.cancel()
        assertEquals(3, collected.size)
    }

    @Test
    fun startScan_withEmptyPath_doesNotCrash() {
        viewModel.startScan("", "test.apk")
        val state = viewModel.uiState.value
        assertNotNull(state)
    }

    @Test
    fun startScan_withEmptyName_doesNotCrash() {
        viewModel.startScan("/path/to/test.apk", "")
        val state = viewModel.uiState.value
        assertNotNull(state)
    }

    @Test
    fun startScan_setsInitialState() {
        viewModel.startScan("/path/apk.apk", "apk.apk")
        val state = viewModel.uiState.value
        assertEquals("apk.apk", state.apkName)
        assertEquals("/path/apk.apk", state.apkPath)
    }

    @Test
    fun reset_clearsSavedResult() {
        viewModel.reset()
        assertNull(viewModel.lastCompletedResult)
    }

    @Test
    fun cancelScan_callsPipelineCancel() {
        viewModel.startScan("/path/test.apk", "test.apk")
        viewModel.cancelScan()
        assertFalse(viewModel.uiState.value.isScanning)
    }

    @Test
    fun startScan_whenAlreadyScanning_returnsEarly() {
        viewModel.startScan("/path/test.apk", "test.apk")
        val state1 = viewModel.uiState.value
        viewModel.startScan("/path/test.apk", "test.apk")
        val state2 = viewModel.uiState.value
        assertEquals(state1.isScanning, state2.isScanning)
    }

    @Test
    fun scanUiState_copyWithValues() {
        val lines = listOf(LogEntry("test", LineType.INFO))
        val state = ScanUiState(
            lines = lines,
            isScanning = true,
            progress = 0.5f,
            currentActivity = "Testing",
            apkPath = "/test.apk",
            apkName = "test.apk"
        )
        assertEquals(1, state.lines.size)
        assertTrue(state.isScanning)
        assertEquals(0.5f, state.progress, 0.001f)
        assertEquals("Testing", state.currentActivity)
        assertEquals("/test.apk", state.apkPath)
        assertEquals("test.apk", state.apkName)
    }
}
