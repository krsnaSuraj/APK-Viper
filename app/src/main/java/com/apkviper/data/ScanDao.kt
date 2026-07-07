package com.apkviper.data

import androidx.room.*
import com.apkviper.model.*

@Dao
interface ScanDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(result: ScanResult): Long

    @Query("SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT 10")
    suspend fun getRecent(): List<ScanResult>

    @Query("SELECT * FROM scan_results ORDER BY timestamp ASC")
    suspend fun getTimeline(): List<ScanResult>

    @Query("SELECT * FROM scan_results WHERE packageName = :pkg ORDER BY timestamp ASC")
    suspend fun getByPackageName(pkg: String): List<ScanResult>

    @Query("DELETE FROM scan_results")
    suspend fun deleteAll()

    @Delete
    suspend fun delete(scan: ScanResult)

    @Query("SELECT COUNT(*) FROM scan_results")
    suspend fun getCount(): Int

    @Query("SELECT AVG(threatScore) FROM scan_results")
    suspend fun getAverageScore(): Double?

    @Query("SELECT COUNT(*) FROM scan_results WHERE threatLevel IN ('CRITICAL', 'MALICIOUS')")
    suspend fun getMaliciousCount(): Int
}
