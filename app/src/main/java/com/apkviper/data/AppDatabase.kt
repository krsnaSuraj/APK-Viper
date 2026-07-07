package com.apkviper.data

import android.content.Context
import androidx.room.*
import com.apkviper.model.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

class FindingListConverter {
    private val gson = Gson()

    @TypeConverter
    fun fromString(value: String): List<Finding> {
        return try {
            gson.fromJson(value, object : TypeToken<List<Finding>>() {}.type)
        } catch (e: Exception) {
            android.util.Log.e("AppDatabase", "Failed to deserialize findings", e)
            emptyList()
        }
    }

    @TypeConverter
    fun fromList(list: List<Finding>): String {
        return gson.toJson(list)
    }
}

class RemediationListConverter {
    private val gson = Gson()

    @TypeConverter
    fun fromString(value: String): List<String> {
        return try {
            gson.fromJson(value, object : TypeToken<List<String>>() {}.type)
        } catch (e: Exception) {
            android.util.Log.e("AppDatabase", "Failed to deserialize remediations", e)
            emptyList()
        }
    }

    @TypeConverter
    fun fromList(list: List<String>): String {
        return gson.toJson(list)
    }
}

@Database(
    entities = [ScanResult::class],
    version = 4,
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
