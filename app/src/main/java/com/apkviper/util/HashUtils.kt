package com.apkviper.util

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

object HashUtils {

    private const val BUFFER_SIZE = 8192

    fun sha256(file: File): String = hashFile(file, "SHA-256")
    fun md5(file: File): String = hashFile(file, "MD5")

    private fun hashFile(file: File, algorithm: String): String {
        val digest = try {
            MessageDigest.getInstance(algorithm)
        } catch (e: Exception) {
            throw IllegalStateException("Hash algorithm unavailable: $algorithm", e)
        }
        if (!file.exists() || !file.isFile || !file.canRead()) {
            throw IllegalArgumentException("Cannot read file: ${file.absolutePath}")
        }
        val buffer = ByteArray(BUFFER_SIZE)
        try {
            FileInputStream(file).use { fis ->
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
        } catch (e: Exception) {
            throw IllegalStateException("Failed to hash file: ${file.name}", e)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
