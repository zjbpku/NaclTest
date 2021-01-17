package com.fidroid.nacltest

import android.util.Base64
import org.libsodium.jni.Sodium
import org.libsodium.jni.SodiumConstants
import org.libsodium.jni.crypto.Random
import org.libsodium.jni.keys.KeyPair
import java.nio.charset.StandardCharsets

object NaclUtils {
    /**
     *
     * @return KeyPair
     */
    fun generateKeyPair(): KeyPair {
        val seeds = Random().randomBytes(SodiumConstants.SECRETKEY_BYTES)
        return KeyPair(seeds)
    }


    fun encrypt(rawBytes: ByteArray, base64ServerPublicKey: ByteArray?, localPrivateKey: ByteArray?): ByteArray? {
        val noncelen = Sodium.crypto_box_noncebytes()
        val nonce = ByteArray(noncelen)
        Sodium.randombytes_buf(nonce, noncelen)
        val ciphertext = ByteArray(Sodium.crypto_box_macbytes() + rawBytes.size)
        val ret = Sodium.crypto_box_easy(ciphertext, rawBytes, rawBytes.size, nonce, base64ServerPublicKey, localPrivateKey)
        if (ret == 0) {
            val data = ByteArray(noncelen + ciphertext.size)
            System.arraycopy(nonce, 0, data, 0, noncelen)
            System.arraycopy(ciphertext, 0, data, noncelen, ciphertext.size)
            return data
        }
        return null
    }

    fun encrypt(rawBytes: ByteArray, base64ServerPublicKey: String?, base64LocalPrivateKey: String?): ByteArray? {
        val hubPublicKey = Base64.decode(base64ServerPublicKey, Base64.NO_WRAP)
        val localPrivateKey = Base64.decode(base64LocalPrivateKey, Base64.NO_WRAP)
        return encrypt(rawBytes, hubPublicKey, localPrivateKey)
    }

    fun encrypt(text: String, base64ServerPublicKey: String?, base64LocalPrivateKey: String?): ByteArray? {
        val rawBytes = text.toByteArray(StandardCharsets.UTF_8)
        return encrypt(rawBytes, base64ServerPublicKey, base64LocalPrivateKey)
    }

    fun decrypt(encryptedBytes: ByteArray, base64ServerPublicKey: ByteArray?, localPrivateKey: ByteArray?): ByteArray? {
        val nonce = encryptedBytes.copyOf(24)
        val encrptedData = encryptedBytes.copyOfRange(24, encryptedBytes.size)
        val decrypted = ByteArray(encrptedData.size - Sodium.crypto_box_macbytes())
        val ret = Sodium.crypto_box_open_easy(decrypted, encrptedData, encrptedData.size, nonce, base64ServerPublicKey, localPrivateKey)
        return if (ret == 0) decrypted else null
    }

    fun decrypt(encryptedBytes: ByteArray, base64ServerPublicKey: String?, base64LocalPrivateKey: String?): ByteArray? {
        val hubPublicKey = Base64.decode(base64ServerPublicKey, Base64.NO_WRAP)
        val localPrivateKey = Base64.decode(base64LocalPrivateKey, Base64.NO_WRAP)
        return decrypt(encryptedBytes, hubPublicKey, localPrivateKey)
    }

    fun decrypt(encryptedText: String, base64ServerPublicKey: String?, base64LocalPrivateKey: String?): ByteArray? {
        val encryptedBytes = encryptedText.toByteArray(StandardCharsets.UTF_8)
        return decrypt(encryptedBytes, base64ServerPublicKey, base64LocalPrivateKey)
    }
}