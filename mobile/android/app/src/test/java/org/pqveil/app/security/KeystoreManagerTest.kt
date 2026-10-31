// SPDX-License-Identifier: BSD-2-Clause
package org.pqveil.app.security

import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeystoreManagerTest {

    private fun generateTestAesKey(): SecretKey {
        val kg = KeyGenerator.getInstance("AES")
        kg.init(256)
        return kg.generateKey()
    }

    private fun wrapSeedWithKey(key: SecretKey, seedBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(seedBytes)

        val header = ByteArray(5)
        header[0] = 0x50.toByte() // 'P'
        header[1] = 0x51.toByte() // 'Q'
        header[2] = 0x53.toByte() // 'S'
        header[3] = 0x45.toByte() // 'E'
        header[4] = 1 // Version

        return header + iv + ciphertext
    }

    private fun unwrapSeedWithKey(key: SecretKey, envelope: ByteArray): ByteArray {
        require(envelope.size > 5 + 12 + 16) { "Corrupt envelope: invalid length" }
        assertEquals(0x50.toByte(), envelope[0])
        assertEquals(0x51.toByte(), envelope[1])
        assertEquals(0x53.toByte(), envelope[2])
        assertEquals(0x45.toByte(), envelope[3])
        assertEquals(1.toByte(), envelope[4])

        val iv = envelope.sliceArray(5 until 17)
        val ciphertext = envelope.sliceArray(17 until envelope.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        return cipher.doFinal(ciphertext)
    }

    @Test
    fun testWrapAndUnwrapRoundTrip() {
        val key = generateTestAesKey()
        val random = SecureRandom()

        // Test 32-byte ML-DSA-65 seed
        val dsaSeed = ByteArray(32).apply { random.nextBytes(this) }
        val wrappedDsa = wrapSeedWithKey(key, dsaSeed)
        val unwrappedDsa = unwrapSeedWithKey(key, wrappedDsa)
        assertArrayEquals("ML-DSA-65 seed must match original after unwrapping", dsaSeed, unwrappedDsa)

        // Test 64-byte ML-KEM-768 seed
        val kemSeed = ByteArray(64).apply { random.nextBytes(this) }
        val wrappedKem = wrapSeedWithKey(key, kemSeed)
        val unwrappedKem = unwrapSeedWithKey(key, wrappedKem)
        assertArrayEquals("ML-KEM-768 seed must match original after unwrapping", kemSeed, unwrappedKem)
    }

    @Test(expected = AEADBadTagException::class)
    fun testTamperedCiphertextRejection() {
        val key = generateTestAesKey()
        val seed = ByteArray(32) { 0xAA.toByte() }
        val envelope = wrapSeedWithKey(key, seed)

        // Flip a byte in the ciphertext payload
        envelope[envelope.size - 1] = (envelope[envelope.size - 1].toInt() xor 0x01).toByte()

        // AES-GCM must detect alteration and throw AEADBadTagException
        unwrapSeedWithKey(key, envelope)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testTruncatedEnvelopeRejection() {
        val key = generateTestAesKey()
        val truncated = ByteArray(10) // Too short to hold magic, version, IV, and tag
        unwrapSeedWithKey(key, truncated)
    }

    @Test(expected = AssertionError::class)
    fun testInvalidMagicHeaderRejection() {
        val key = generateTestAesKey()
        val seed = ByteArray(32) { 0xBB.toByte() }
        val envelope = wrapSeedWithKey(key, seed)

        // Corrupt magic header byte
        envelope[0] = 0x00
        unwrapSeedWithKey(key, envelope)
    }
}

