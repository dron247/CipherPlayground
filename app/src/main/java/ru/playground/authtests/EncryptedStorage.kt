package ru.playground.authtests

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal
import kotlin.collections.ArrayList

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
class EncryptedStorage(
        private val context: Context,
        private val vault: IDataVault,
        private val secretKeyAlias: String,
        private val keystoreId: String = "AndroidKeyStore"
) {
    companion object {
        private const val KEY_PAIR_GENERATOR_ALGORITHM = "RSA"
        private const val RSA_MODE = "RSA/ECB/PKCS1Padding"
        private const val AES_MODE = "AES/ECB/PKCS7Padding"
        private const val ANDROID_OPEN_SSL = "AndroidOpenSSL"
        private const val CIPHER_PROVIDER = "BC"
        private const val SECRET_KEY_SPEC_ALGORITHM = "AES"
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(keystoreId).also {
            it.load(null)
        }
    }

    private val secretKey: Key
        get() {
            fun decodeKeySpec(encodedSpec: String): Key {
                val encrypted = Base64.decode(encodedSpec, Base64.DEFAULT)
                val key = rsaDecrypt(secretKeyAlias, encrypted)
                return SecretKeySpec(key, SECRET_KEY_SPEC_ALGORITHM)
            }

            var retVal = vault.read(secretKeyAlias, null)
            if (retVal != null) return decodeKeySpec(retVal)

            val key = ByteArray(16)
            val secureRandom = SecureRandom()
            secureRandom.nextBytes(key)

            val encryptedKey = rsaEncrypt(secretKeyAlias, key)
            retVal = Base64.encodeToString(encryptedKey, Base64.DEFAULT)
            vault.write(secretKeyAlias, retVal)
            return decodeKeySpec(retVal)
        }

    //region RSA pairs
    private fun getKey(alias: String): KeyStore.Entry {
        if (!keyStore.containsAlias(alias)) {
            val start = Calendar.getInstance()
            val end = Calendar.getInstance().also {
                it.add(Calendar.YEAR, 30)
            }

            val spec = KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(X500Principal("CN=$alias"))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()

            KeyPairGenerator.getInstance(KEY_PAIR_GENERATOR_ALGORITHM).apply {
                initialize(spec)
                generateKeyPair()
            }
        }
        return keyStore.getEntry(alias, null)
    }

    @Throws(Exception::class)
    private fun rsaEncrypt(keyAlias: String, secret: ByteArray): ByteArray {
        val privateKeyEntry = getKey(keyAlias) as KeyStore.PrivateKeyEntry
        val inputCipher = Cipher.getInstance(RSA_MODE, ANDROID_OPEN_SSL).apply {
            init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)
        }

        val outputStream = ByteArrayOutputStream()
        CipherOutputStream(outputStream, inputCipher).run {
            write(secret)
            close()
        }

        return outputStream.toByteArray()
    }

    @Throws(Exception::class)
    private fun rsaDecrypt(keyAlias: String, encrypted: ByteArray): ByteArray {
        val privateKeyEntry = getKey(keyAlias) as KeyStore.PrivateKeyEntry
        val outputCipher = Cipher.getInstance(RSA_MODE, ANDROID_OPEN_SSL).apply {
            init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)
        }

        val cipherInputStream = CipherInputStream(ByteArrayInputStream(encrypted), outputCipher)
        val values = ArrayList<Byte>()
        var current = -1
        while (cipherInputStream.read().also { current = it } != -1) {
            values.add(current.toByte())
        }

        return values.toByteArray()
    }
    //endregion


    //region public methods
    /**
     * Performs data encoding and then puts a result into provided storage
     * @param alias encoded data identifier
     * @param value a string to encode
     */
    @Throws(Exception::class)
    fun put(alias: String, value: String) {
        val bytes = value.toByteArray()
        val cipher = Cipher.getInstance(AES_MODE, CIPHER_PROVIDER).also {
            it.init(Cipher.ENCRYPT_MODE, secretKey)
        }
        val encoded = cipher.doFinal(bytes)
        val b64Encoded = Base64.encodeToString(encoded, Base64.DEFAULT)
        vault.write(alias, b64Encoded)
    }

    /**
     * Finds an encoded value inside provided secret storage, and decodes it
     * @param alias encoded data identifier
     * @return a string with encoded data, or null if not found
     */
    fun get(alias: String): String? {
        val b64Encoded = vault.read(alias, null) ?: return null

        val cipher = Cipher.getInstance(AES_MODE, CIPHER_PROVIDER).also {
            it.init(Cipher.DECRYPT_MODE, secretKey)
        }

        val encoded = Base64.decode(b64Encoded, Base64.DEFAULT)
        val decoded = cipher.doFinal(encoded)
        return String(decoded)
    }
    //endregion


}

interface IDataVault {
    fun write(key: String, value: String)
    fun read(key: String, defaultValue: String? = null): String?
}