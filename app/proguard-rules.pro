# R8 full mode removes library/package info by default — keep for crash reporting
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
-keep public class * extends java.lang.Exception

# Room — keep entities and DAOs
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep @androidx.room.Dao class *
-keepclassmembers class * {
    @androidx.room.* <fields>;
    @androidx.room.* <methods>;
}

# Gson — keep model classes
-keep class com.google.gson.** { *; }
-keep class com.apkviper.model.** { *; }
-keepclassmembers class com.apkviper.model.** { *; }

# Compose
-dontwarn androidx.compose.**

# Kotlin serialization/reflection
-keep class kotlin.Metadata { *; }
-keep class kotlin.reflect.** { *; }

# Coroutines
-dontwarn kotlinx.coroutines.**

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# Keep R (resources)
-keep class **.R { *; }
-keep class **.R$* { *; }

# Strip all Log calls in release
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}

# R8's optimizer (proguard-android-optimize.txt) emits bytecode that fails the
# ART verifier on some devices (java.lang.VerifyError: register has type
# Reference but expected Integer), crashing the scan coroutine. Disable only
# the optimization pass - shrinking + obfuscation are kept so the APK stays
# small and the rule/engine logic stays hidden.
-dontoptimize
