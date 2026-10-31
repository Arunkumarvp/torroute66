// SPDX-License-Identifier: BSD-2-Clause
package org.pqveil.app.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class KeystoreManager(private val context: Context) {

    companion object {
        private const val TAG = "PQVeil.Keystore"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "pqveil_identity_wrapping_key_v1"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128
        private const val MAGIC_HEADER = 0x50515345 // 'PQSE' (PQVeil Seed Envelope)
        private const val ENVELOPE_VERSION: Byte = 1
        private const val SEED_FILE_NAME = "pqveil_sealed_seed.bin"
    }

    data class KeySecurityReport(
        val isHardwareBacked: Boolean,
        val securityLevel: String,
        val hasStrongBoxFeature: Boolean,
        val isInsideSecureHardware: Boolean
    )

    data class WrappedSeedEnvelope(
        val version: Byte,
        val iv: ByteArray,
        val ciphertextAndTag: ByteArray
    )

    fun checkSecurityLevel(): KeySecurityReport {
        val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            false
        }

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = keyStore.getKey(KEY_ALIAS, null) as? SecretKey

        if (key == null) {
            return KeySecurityReport(
                isHardwareBacked = false,
                securityLevel = "Key Not Generated",
                hasStrongBoxFeature = hasStrongBox,
                isInsideSecureHardware = false
            )
        }

        return try {
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo

            val securityLevelStr = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox Dedicated HSM"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "ARM TrustZone / TEE"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software Keystore"
                    else -> "Unknown Security Level"
                }
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) "Hardware TEE" else "Software"
            }

            @Suppress("DEPRECATION")
            val isHw = keyInfo.isInsideSecureHardware

            KeySecurityReport(
                isHardwareBacked = isHw,
                securityLevel = securityLevelStr,
                hasStrongBoxFeature = hasStrongBox,
                isInsideSecureHardware = isHw
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed auditing KeyInfo security level: ${e.message}")
            KeySecurityReport(
                isHardwareBacked = false,
                securityLevel = "Audit Failed: ${e.message}",
                hasStrongBoxFeature = hasStrongBox,
                isInsideSecureHardware = false
            )
        }
    }

    fun getOrCreateWrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) {
            return existing
        }

        Log.i(TAG, "Generating AES-256-GCM wrapping key in Android Keystore...")
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val specBuilder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                try {
                    specBuilder.setIsStrongBoxBacked(true)
                } catch (e: Exception) {
                    Log.w(TAG, "StrongBox request failed, falling back to standard TEE")
                }
            }
        }

        keyGenerator.init(specBuilder.build())
        return keyGenerator.generateKey()
    }

    /**
     * Encrypts and serializes a high-entropy seed into a versioned envelope:
     * [Magic 4B: 'PQSE'] || [Version 1B] || [IV 12B] || [Ciphertext + Tag]
     */
    fun wrapSeed(seedBytes: ByteArray): ByteArray {
        val key = getOrCreateWrappingKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(seedBytes)

        val header = ByteArray(5)
        header[0] = (MAGIC_HEADER shr 24).toByte()
        header[1] = (MAGIC_HEADER shr 16).toByte()
        header[2] = (MAGIC_HEADER shr 8).toByte()
        header[3] = MAGIC_HEADER.toByte()
        header[4] = ENVELOPE_VERSION

        return header + iv + ciphertext
    }

    /**
     * Unwraps and validates a versioned seed envelope.
     * Rejects corrupted data, altered IVs, or tampered GCM auth tags.
     */
    fun unwrapSeed(envelope: ByteArray): ByteArray {
        require(envelope.size > 5 + GCM_IV_LENGTH + 16) { "Corrupt envelope: invalid length" }

        val magic = ((envelope[0].toInt() and 0xFF) shl 24) or
                ((envelope[1].toInt() and 0xFF) shl 16) or
                ((envelope[2].toInt() and 0xFF) shl 8) or
                (envelope[3].toInt() and 0xFF)

        require(magic == MAGIC_HEADER) { "Invalid magic header: expected 'PQSE'" }
        require(envelope[4] == ENVELOPE_VERSION) { "Unsupported envelope version: ${envelope[4]}" }

        val iv = envelope.sliceArray(5 until 5 + GCM_IV_LENGTH)
        val ciphertext = envelope.sliceArray(5 + GCM_IV_LENGTH until envelope.size)

        val key = getOrCreateWrappingKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        return cipher.doFinal(ciphertext)
    }

    /**
     * Persists wrapped seed to internal app storage.
     */
    fun saveSealedSeed(wrappedSeed: ByteArray) {
        val file = File(context.filesDir, SEED_FILE_NAME)
        FileOutputStream(file).use { it.write(wrappedSeed) }
    }

    fun loadSealedSeed(): ByteArray? {
        val file = File(context.filesDir, SEED_FILE_NAME)
        if (!file.exists()) return null
        return file.readBytes()
    }

    /**
     * Securely destroys the wrapping key and clears sealed seed storage.
     */
    fun secureDelete() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
            Log.i(TAG, "Wrapping key alias '$KEY_ALIAS' purged from Android Keystore")
        }
        val file = File(context.filesDir, SEED_FILE_NAME)
        if (file.exists()) {
            // Overwrite with zeros before deletion
            val zeros = ByteArray(file.length().toInt())
            FileOutputStream(file).use { it.write(zeros) }
            file.delete()
            Log.i(TAG, "Sealed seed file securely wiped and deleted")
        }
    }
}
