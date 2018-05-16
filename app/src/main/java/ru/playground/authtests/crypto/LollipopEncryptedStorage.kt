package ru.playground.authtests.crypto

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
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal
import kotlin.collections.ArrayList


//@TargetApi(Build.VERSION_CODES.LOLLIPOP)
class LollipopEncryptedStorage(
        private val context: Context,
        private val vault: IDataVault,
        private val secretKeyAlias: String,
        private val keystoreId: String = "AndroidKeyStore"
) : IEncryptedStorage {
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

    private fun decodeKeySpec(encodedSpec: String): Key {
        val encrypted = Base64.decode(encodedSpec, Base64.DEFAULT)
        val key = rsaDecrypt(secretKeyAlias, encrypted)
        return SecretKeySpec(key, SECRET_KEY_SPEC_ALGORITHM)
    }

    override val secretKey: Key
        get() {
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
    private fun initKeyPairIfNeeded(alias: String) {
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
    }

    private fun getCipher(): Cipher {
        try {
            return if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) { // below android m
                Cipher.getInstance(RSA_MODE, ANDROID_OPEN_SSL) // error in android 6: InvalidKeyException: Need RSA private or public key
            } else { // android m and above
                Cipher.getInstance(RSA_MODE, "AndroidKeyStoreBCWorkaround") // error in android 5: NoSuchProviderException: Provider not available: AndroidKeyStoreBCWorkaround
            }
        } catch (exception: Exception) {
            throw RuntimeException("getCipher: Failed to get an instance of Cipher", exception)
        }
    }

    @Throws(Exception::class)
    private fun rsaEncrypt(keyAlias: String, secret: ByteArray): ByteArray {
        initKeyPairIfNeeded(keyAlias)
        val privateKeyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        val inputCipher = getCipher().apply {
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
        val privateKeyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        val outputCipher = getCipher()
        outputCipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)

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
     * @param secret defaults to random secret key, use [keyFrom] static method to apply non random key
     */
    @Throws(Exception::class)
    override fun put(alias: String, value: String, secret: Key) {
        val bytes = value.toByteArray()
        val cipher = Cipher.getInstance(AES_MODE, CIPHER_PROVIDER).also {
            it.init(Cipher.ENCRYPT_MODE, secret)
        }
        val encoded = cipher.doFinal(bytes)
        val b64Encoded = Base64.encodeToString(encoded, Base64.DEFAULT)
        vault.write(alias, b64Encoded)
    }

    /**
     * Finds an encoded value inside provided secret storage, and decodes it
     * @param alias encoded data identifier
     * @param secret defaults to random secret key, use [keyFrom] static method to apply non random key
     * @return a string with encoded data, or null if not found
     */
    @Throws(BadPaddingException::class)
    override fun get(alias: String, secret: Key): String? {
        val b64Encoded = vault.read(alias, null) ?: return null

        val cipher = Cipher.getInstance(AES_MODE, CIPHER_PROVIDER).also {
            it.init(Cipher.DECRYPT_MODE, secret)
        }

        val encoded = Base64.decode(b64Encoded, Base64.DEFAULT)
        val decoded = cipher.doFinal(encoded)
        return String(decoded)
    }

    /**
     * Creates encrypting key from given input string
     */
    @Throws(IllegalArgumentException::class)
    override fun keyFrom(input: String): Key {
        if (input.isEmpty()) throw IllegalArgumentException("Key must be longer than 0")
        val bytes = input.toByteArray()
        if (bytes.size > 16) throw IllegalArgumentException("Key size must be 16 bytes max")
        val keyBytes = ByteArray(16)
        keyBytes.fill(0)
        bytes.forEachIndexed({ index, byte ->
            keyBytes[index] = byte
        })
        return SecretKeySpec(keyBytes, LollipopEncryptedStorage.SECRET_KEY_SPEC_ALGORITHM)
    }
    //endregion
}

