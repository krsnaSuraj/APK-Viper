package com.apkviper.data

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.apkviper.model.*
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ScanDaoTest {
    private lateinit var db: AppDatabase
    private lateinit var dao: ScanDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        dao = db.scanDao()
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun createResult(
        apkName: String = "test.apk",
        threatLevel: ThreatLevel = ThreatLevel.SAFE,
        threatScore: Int = 0,
        findings: List<Finding> = emptyList(),
        timestamp: Long = System.currentTimeMillis()
    ): ScanResult = ScanResult(
        apkName = apkName,
        apkPath = "/path/$apkName",
        sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        fileSize = 1024L,
        scanMode = "quick",
        threatLevel = threatLevel,
        threatScore = threatScore,
        findings = findings,
        decompileTime = 100L,
        scanTime = 500L,
        timestamp = timestamp
    )

    @Test
    fun insertAndReadBack() = runBlocking {
        val result = createResult()
        val id = dao.insert(result)
        assertTrue(id > 0)
        val recent = dao.getRecent()
        assertEquals(1, recent.size)
        assertEquals(result.apkName, recent[0].apkName)
    }

    @Test
    fun getRecent_returnsLatestFirst() = runBlocking {
        val old = createResult(apkName = "old.apk", timestamp = 1000L)
        val mid = createResult(apkName = "mid.apk", timestamp = 2000L)
        val latest = createResult(apkName = "latest.apk", timestamp = 3000L)
        dao.insert(old)
        dao.insert(mid)
        dao.insert(latest)
        val recent = dao.getRecent()
        assertEquals(3, recent.size)
        assertEquals("latest.apk", recent[0].apkName)
        assertEquals("mid.apk", recent[1].apkName)
        assertEquals("old.apk", recent[2].apkName)
    }

    @Test
    fun getRecent_limitsTo10() = runBlocking {
        for (i in 1..15) {
            dao.insert(createResult(apkName = "test$i.apk", timestamp = i * 1000L))
        }
        val recent = dao.getRecent()
        assertEquals(10, recent.size)
    }

    @Test
    fun deleteSpecificScan() = runBlocking {
        val r1 = createResult(apkName = "keep.apk")
        val r2 = createResult(apkName = "delete.apk")
        val id1 = dao.insert(r1)
        dao.insert(r2)
        assertEquals(2, dao.getCount())
        dao.delete(r2.copy(id = 2))
        assertEquals(1, dao.getCount())
        val remaining = dao.getRecent()
        assertEquals("keep.apk", remaining[0].apkName)
    }

    @Test
    fun deleteAll() = runBlocking {
        dao.insert(createResult())
        dao.insert(createResult())
        dao.deleteAll()
        assertEquals(0, dao.getCount())
        assertTrue(dao.getRecent().isEmpty())
    }

    @Test
    fun getCount_returnsCorrectCount() = runBlocking {
        assertEquals(0, dao.getCount())
        dao.insert(createResult())
        assertEquals(1, dao.getCount())
        dao.insert(createResult())
        assertEquals(2, dao.getCount())
    }

    @Test
    fun getAverageScore_returnsNullWhenEmpty() = runBlocking {
        assertNull(dao.getAverageScore())
    }

    @Test
    fun getAverageScore_singleResult() = runBlocking {
        dao.insert(createResult(threatScore = 50))
        val avg = dao.getAverageScore()
        assertNotNull(avg)
        assertEquals(50.0, avg!!, 0.001)
    }

    @Test
    fun getAverageScore_multipleResults() = runBlocking {
        dao.insert(createResult(threatScore = 30))
        dao.insert(createResult(threatScore = 70))
        val avg = dao.getAverageScore()
        assertNotNull(avg)
        assertEquals(50.0, avg!!, 0.001)
    }

    @Test
    fun getAverageScore_allZeros() = runBlocking {
        dao.insert(createResult(threatScore = 0))
        dao.insert(createResult(threatScore = 0))
        val avg = dao.getAverageScore()
        assertNotNull(avg)
        assertEquals(0.0, avg!!, 0.001)
    }

    @Test
    fun getMaliciousCount_zeroWhenEmpty() = runBlocking {
        assertEquals(0, dao.getMaliciousCount())
    }

    @Test
    fun getMaliciousCount_noMalicious() = runBlocking {
        dao.insert(createResult(threatLevel = ThreatLevel.SAFE))
        dao.insert(createResult(threatLevel = ThreatLevel.LOW))
        assertEquals(0, dao.getMaliciousCount())
    }

    @Test
    fun getMaliciousCount_countsCritical() = runBlocking {
        dao.insert(createResult(threatLevel = ThreatLevel.CRITICAL, threatScore = 90))
        dao.insert(createResult(threatLevel = ThreatLevel.SAFE))
        assertEquals(1, dao.getMaliciousCount())
    }

    @Test
    fun getMaliciousCount_countsMalicious() = runBlocking {
        dao.insert(createResult(threatLevel = ThreatLevel.MALICIOUS, threatScore = 100))
        dao.insert(createResult(threatLevel = ThreatLevel.LOW))
        assertEquals(1, dao.getMaliciousCount())
    }

    @Test
    fun getMaliciousCount_multipleMalicious() = runBlocking {
        dao.insert(createResult(threatLevel = ThreatLevel.CRITICAL, threatScore = 90))
        dao.insert(createResult(threatLevel = ThreatLevel.MALICIOUS, threatScore = 100))
        dao.insert(createResult(threatLevel = ThreatLevel.MEDIUM))
        assertEquals(2, dao.getMaliciousCount())
    }

    @Test
    fun insertWithFindings_roundTrips() = runBlocking {
        val findings = listOf(
            Finding(FindingCategory.CODE, Severity.CRITICAL, "Remote code exec", "RCE detected", details = "Runtime.exec", file = "Main.java"),
            Finding(FindingCategory.MANIFEST, Severity.MEDIUM, "Exported activity", "debug", file = "AndroidManifest.xml")
        )
        val result = createResult(
            apkName = "findings_test.apk",
            threatLevel = ThreatLevel.HIGH,
            threatScore = 75,
            findings = findings
        )
        dao.insert(result)
        val recent = dao.getRecent()
        assertEquals(1, recent.size)
        val loaded = recent[0]
        assertEquals(2, loaded.findings.size)
        assertEquals(FindingCategory.CODE, loaded.findings[0].category)
        assertEquals("Remote code exec", loaded.findings[0].title)
        assertEquals("Main.java", loaded.findings[0].file)
        assertEquals(FindingCategory.MANIFEST, loaded.findings[1].category)
    }

    @Test
    fun insertWithAllFields_roundTrips() = runBlocking {
        val result = ScanResult(
            apkName = "full.apk",
            apkPath = "/path/full.apk",
            sha256 = "aa",
            fileSize = 999L,
            scanMode = "deep",
            threatLevel = ThreatLevel.HIGH,
            threatScore = 65,
            findings = listOf(Finding(FindingCategory.STRING, Severity.INFO, "URL", "http://example.com")),
            decompileTime = 200L,
            scanTime = 1000L,
            timestamp = 12345L,
            classification = "adware",
            remediations = listOf("Remove permissions", "Use HTTPS"),
            appLabel = "FullApp",
            packageName = "com.example.full",
            versionName = "2.0",
            versionCode = 200,
            minSdk = 26,
            targetSdk = 34
        )
        val id = dao.insert(result)
        assertTrue(id > 0)
        val loaded = dao.getRecent()[0]
        assertEquals("FullApp", loaded.appLabel)
        assertEquals("com.example.full", loaded.packageName)
        assertEquals("2.0", loaded.versionName)
        assertEquals(200L, loaded.versionCode)
        assertEquals(26, loaded.minSdk)
        assertEquals(34, loaded.targetSdk)
        assertEquals("adware", loaded.classification)
        assertEquals(2, loaded.remediations.size)
    }

    @Test
    fun insertReplacesOnConflict() = runBlocking {
        val r1 = createResult(apkName = "same.apk")
        val id1 = dao.insert(r1)
        val r2 = r1.copy(id = id1, threatScore = 100, threatLevel = ThreatLevel.MALICIOUS)
        dao.insert(r2)
        assertEquals(1, dao.getCount())
        assertEquals(100, dao.getRecent()[0].threatScore)
    }

    @Test
    fun emptyDatabase_getRecentEmpty() = runBlocking {
        assertTrue(dao.getRecent().isEmpty())
    }

    @Test
    fun deleteNonExistent_doesNotCrash() = runBlocking {
        dao.delete(createResult())
    }

    @Test
    fun deleteAllOnEmptyDatabase_doesNotCrash() = runBlocking {
        dao.deleteAll()
        assertEquals(0, dao.getCount())
    }
}
