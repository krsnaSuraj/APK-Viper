package com.apkviper.engine.native

/**
 * Framework Whitelisting Engine — identifies known game engines, crash reporters,
 * C++ runtimes, and standard libraries. Symbols from whitelisted frameworks
 * are downgraded from CRITICAL/HIGH to INFO/LOW because system(), fork(),
 * execve(), ptrace() are normal operations for game engines and crash handlers.
 */

object FrameworkWhitelist {

    // SHA256 fingerprints of known framework .so files (truncated to first 16 chars for matching)
    // These are common library hashes from Unity, Unreal, Flutter, React Native, etc.
    data class FrameworkSignature(
        val name: String,
        val category: String, // "game_engine", "crash_reporter", "runtime", "ad_sdk", "standard_lib"
        val libPatterns: List<String>
    )

    val frameworks = listOf(
        // Game Engines
        FrameworkSignature("Unity Engine", "game_engine",
            listOf("libunity", "libil2cpp", "libmono", "libunity-native-trace")),
        FrameworkSignature("Unreal Engine", "game_engine",
            listOf("libUE4", "libUnreal", "libue4", "libunreal")),
        FrameworkSignature("Godot Engine", "game_engine",
            listOf("libgodot", "libgodot_android")),
        FrameworkSignature("Cocos2d-x", "game_engine",
            listOf("libcocos2d", "libcocos2dcpp", "libcocos2djs")),

        // Cross-platform frameworks
        FrameworkSignature("Flutter", "cross_platform",
            listOf("libflutter", "libapp.so")),
        FrameworkSignature("React Native", "cross_platform",
            listOf("libreactnativejni", "libreact_nativemodule")),
        FrameworkSignature("Xamarin/MAUI", "cross_platform",
            listOf("libxamarin-app", "libmonodroid", "libmonosgen")),
        FrameworkSignature("Cordova/PhoneGap", "cross_platform",
            listOf("libcordova", "libphonegap")),
        FrameworkSignature("Firebase C++ SDK", "cross_platform",
            listOf("libfirebasecpp", "libfirebase", "libadmob")),

        // Media / graphics frameworks (commonly ship versioned/obfuscated .so names)
        FrameworkSignature("GStreamer", "standard_lib",
            listOf("libgstreamer", "libgst", "libgstbase")),
        FrameworkSignature("OpenCV", "standard_lib",
            listOf("libopencv", "libopencv_world", "libopencv_core")),
        FrameworkSignature("TensorFlow Lite", "standard_lib",
            listOf("libtensorflowlite", "libtensorflow", "libtfkernel")),
        FrameworkSignature("Realm", "standard_lib",
            listOf("librealm", "librealmjs")),

        // Jetpack / AndroidX / Kotlin native runtime libs (ship arbitrary names)
        FrameworkSignature("AndroidX / Jetpack", "standard_lib",
            listOf("libandroidx", "libdatastore", "libcompose", "libskiko", "libkotlin",
                "libcollection", "liblifecycle", "libnavigation", "libroom")),
        FrameworkSignature("Google Play Services", "standard_lib",
            listOf("libgms", "libplay", "libgoogle", "libcrashpadhandler")),

        // Crash & analytics reporters
        FrameworkSignature("Firebase Crashlytics", "crash_reporter",
            listOf("libcrashlytics", "libcrashlytics-common", "libcrashlytics-handler", "libcrashlytics-native")),
        FrameworkSignature("Bugsnag", "crash_reporter",
            listOf("libbugsnag", "libbugsnag-ndk", "libbugsnag-plugin-android-ndk")),
        FrameworkSignature("Sentry", "crash_reporter",
            listOf("libsentry", "libsentry-android", "libsentry-native")),
        FrameworkSignature("AppCenter", "crash_reporter",
            listOf("libappcenter", "libappcenter-crashes")),
        FrameworkSignature("SignalHandler", "crash_reporter",
            listOf("libcrashpad", "libbreakpad", "libnativecrash")),

        // Ad SDKs (commonly have native components)
        FrameworkSignature("AppLovin", "ad_sdk",
            listOf("libapplovin", "libapplovin-native-crash-reporter")),
        FrameworkSignature("Unity Ads", "ad_sdk",
            listOf("libunityads")),
        FrameworkSignature("AdMob", "ad_sdk",
            listOf("libadmob")),

        // Standard runtimes (present in almost every native app)
        FrameworkSignature("C++ STL Runtime", "runtime",
            listOf("libc++_shared", "libc++", "libgnustl_shared", "libstlport_shared")),
        FrameworkSignature("OpenSSL/BoringSSL", "standard_lib",
            listOf("libcrypto", "libssl", "libboringssl", "libboringssl_native")),
        FrameworkSignature("SQLite", "standard_lib",
            listOf("libsqlite3", "libsqlite", "libsqlcipher")),
        FrameworkSignature("libc / Bionic", "standard_lib",
            listOf("libc.so", "libm.so", "libdl.so", "libstdc++")),
        FrameworkSignature("WebView/Chromium", "standard_lib",
            listOf("libwebview", "libchromium", "libchromium_android_linker")),
        FrameworkSignature("OpenGL/Vulkan", "standard_lib",
            listOf("libGLESv2", "libGLESv3", "libEGL", "libvulkan", "libGLES")),
        FrameworkSignature("OpenSLES/AAudio", "standard_lib",
            listOf("libOpenSLES", "libOpenMAXAL", "libaaudio")),
        FrameworkSignature("MediaCodec", "standard_lib",
            listOf("libstagefright", "libmedia", "libaudioutils")),
    )

    private val frameworkLookup: Map<String, FrameworkSignature> = run {
        val map = mutableMapOf<String, FrameworkSignature>()
        frameworks.forEach { fw ->
            fw.libPatterns.forEach { pattern ->
                map[pattern.lowercase()] = fw
            }
        }
        map
    }

    /**
     * Check if a given .so file belongs to a known framework.
     */
    fun match(libPath: String): FrameworkSignature? {
        val filename = libPath.lowercase().substringAfterLast('/').removeSuffix(".so")
        // Direct match
        frameworkLookup[filename]?.let { return it }
        // Partial match — check if any framework pattern is a substring
        frameworkLookup.entries.forEach { (key, fw) ->
            if (filename.contains(key)) return fw
        }
        return null
    }

    /**
     * Determine severity override for a native symbol based on framework context.
     * Game engines and crash reporters legitimately use fork/execve/ptrace/system.
     */
    fun getSymbolSeverityOverride(symbol: String, libPath: String): SymbolOverride {
        val fw = match(libPath) ?: return SymbolOverride.USE_ORIGINAL

        // Symbols that are NORMAL in game engines and crash reporters
        val downgradedInAllFrameworks = setOf(
            "ptrace", "fork", "execve", "execvp", "execl",
            "system", "popen", "dlopen", "dlsym", "mmap", "mprotect",
            "memcpy", "strcpy", "sprintf", "getenv", "setenv",
            "unlink", "readdir", "access"
        )

        if (symbol.lowercase() in downgradedInAllFrameworks) {
            return when (fw.category) {
                "game_engine", "crash_reporter", "runtime", "standard_lib" ->
                    SymbolOverride.DOWNGRADE_TO_INFO
                "cross_platform" -> SymbolOverride.DOWNGRADE_TO_LOW
                "ad_sdk" -> SymbolOverride.DOWNGRADE_TO_LOW
                else -> SymbolOverride.USE_ORIGINAL
            }
        }

        // Network symbols are normal in ad SDKs and cross-platform frameworks
        val networkInFrameworks = setOf("socket", "connect", "sendto", "recvfrom")
        if (symbol.lowercase() in networkInFrameworks) {
            return when (fw.category) {
                "game_engine", "crash_reporter", "ad_sdk", "cross_platform", "standard_lib" ->
                    SymbolOverride.DOWNGRADE_TO_LOW
                else -> SymbolOverride.USE_ORIGINAL
            }
        }

        return SymbolOverride.USE_ORIGINAL
    }

    enum class SymbolOverride { USE_ORIGINAL, DOWNGRADE_TO_INFO, DOWNGRADE_TO_LOW }
}
