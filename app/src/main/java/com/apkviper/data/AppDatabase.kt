package com.apkviper.data

import android.content.Context
import androidx.room.*
import com.apkviper.model.Finding
import com.apkviper.model.FindingCategory
import com.apkviper.model.FindingConfidence
import com.apkviper.model.ScanResult
import com.apkviper.model.Severity
import org.json.JSONArray
import org.json.JSONObject

/**
 * Manual, reflection-free JSON converters (built on the Android `org.json` runtime).
 *
 * Why not Gson here: Gson relies on reflective instantiation of the Kotlin `Finding`
 * data class and reflective enum handling. Under R8 full mode (`android.enableR8.fullMode=true`)
 * that reflection silently fails on-device, so the `findings` column deserialized to an
 * EMPTY list on reload — producing the "history shows no threats" bug while the live scan
 * (in-memory, never serialized) was fine. `org.json` uses explicit `valueOf`/`name` for
 * enums and direct field access, which is fully R8-safe.
 */
class FindingListConverter {

    @TypeConverter
    fun fromString(value: String): List<Finding> {
        if (value.isBlank()) return emptyList()
        return try {
            val arr = JSONArray(value)
            val out = ArrayList<Finding>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                 out.add(
                    Finding(
                        category = FindingCategory.valueOf(o.getString("category")),
                        severity = Severity.valueOf(o.getString("severity")),
                        title = o.getString("title"),
                        description = o.optString("description", ""),
                        details = o.optString("details", "").takeIf { it.isNotEmpty() },
                        file = o.optString("file", "").takeIf { it.isNotEmpty() },
                        line = if (o.has("line") && !o.isNull("line")) o.getInt("line") else null,
                        confidence = run {
                            val c = o.optString("confidence", "")
                            if (c.isBlank()) FindingConfidence.HIGH else FindingConfidence.valueOf(c)
                        },
                        ruleSource = o.optString("ruleSource", "").takeIf { it.isNotEmpty() }
                    )
                )
            }
            out
        } catch (e: Exception) {
            // Surface (don't silently swallow) so failures are observable in logs.
            android.util.Log.e("AppDatabase", "Failed to deserialize findings: ${e.message}", e)
            emptyList()
        }
    }

    @TypeConverter
    fun fromList(list: List<Finding>): String {
        val arr = JSONArray()
        for (f in list) {
            val o = JSONObject()
            o.put("category", f.category.name)
            o.put("severity", f.severity.name)
            o.put("title", f.title)
            o.put("description", f.description)
            o.put("confidence", f.confidence.name)
            if (f.details != null) o.put("details", f.details)
            if (f.file != null) o.put("file", f.file)
            if (f.line != null) o.put("line", f.line)
            if (f.ruleSource != null) o.put("ruleSource", f.ruleSource)
            arr.put(o)
        }
        return arr.toString()
    }
}

class RemediationListConverter {

    @TypeConverter
    fun fromString(value: String): List<String> {
        if (value.isBlank()) return emptyList()
        return try {
            val arr = JSONArray(value)
            val out = ArrayList<String>(arr.length())
            for (i in 0 until arr.length()) out.add(arr.getString(i))
            out
        } catch (e: Exception) {
            android.util.Log.e("AppDatabase", "Failed to deserialize remediations: ${e.message}", e)
            emptyList()
        }
    }

    @TypeConverter
    fun fromList(list: List<String>): String {
        val arr = JSONArray()
        for (s in list) arr.put(s)
        return arr.toString()
    }
}

@Database(
    entities = [ScanResult::class],
    version = 5,
    exportSchema = false
)
@TypeConverters(FindingListConverter::class, RemediationListConverter::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "apk_viper.db"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
