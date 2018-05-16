package ru.playground.authtests

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.util.Base64
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


@TargetApi(Build.VERSION_CODES.M)
class TouchIdKeyStoreProvider {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val CIPHER_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    }

    /**
     * A keystore for our keys
     */
    private val keystore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).also {
            it.load(null)
        }
    }

    private val cipher: Cipher by lazy {
        Cipher.getInstance(CIPHER_TRANSFORMATION)
    }

    private val keyPairGenerator: KeyPairGenerator by lazy {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
    }

    private fun isKeyReady(alias: String): Boolean =
            keystore.containsAlias(alias) || generateNewKeyPair(alias)


    private fun generateNewKeyPair(keyAlias: String): Boolean {
        keyPairGenerator.initialize(
                KeyGenParameterSpec
                        .Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setUserAuthenticationRequired(true)
                        .build()
        )
        keyPairGenerator.generateKeyPair()
        return true
    }

    private fun deleteKey(alias: String) {
        try {
            keystore.deleteEntry(alias)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }


    @Throws(KeyStoreException::class, NoSuchAlgorithmException::class, UnrecoverableKeyException::class, InvalidKeyException::class)
    private fun initDecodeCipher(mode: Int, alias: String) {
        val key = keystore.getKey(alias, null) as PrivateKey
        cipher.init(mode, key)
    }

    @Throws(KeyStoreException::class, InvalidKeySpecException::class, NoSuchAlgorithmException::class, InvalidKeyException::class, InvalidAlgorithmParameterException::class)
    private fun initEncodeCipher(mode: Int, alias: String) {
        val key = keystore.getCertificate(alias).publicKey
        val unrestricted = KeyFactory.getInstance(key.algorithm).generatePublic(X509EncodedKeySpec(key.encoded))
        val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        cipher.init(mode, unrestricted, spec)
    }

    private fun initCipher(mode: Int, keyAlias: String): Boolean {
        try {
            keystore.load(null)
            when (mode) {
                Cipher.ENCRYPT_MODE -> initEncodeCipher(mode, keyAlias)
                Cipher.DECRYPT_MODE -> initDecodeCipher(mode, keyAlias)
                else -> return false
            }
            return true
        } catch (ex: Exception) {
            when (ex) {
                is KeyPermanentlyInvalidatedException -> deleteKey(keyAlias)
                else -> ex.printStackTrace()
            }
            return false
        }
    }


    fun encode(alias: String, input: String): String? {
        try {
            if (isKeyReady(alias) && initCipher(Cipher.ENCRYPT_MODE, alias)) {
                val bytes = cipher.doFinal(input.toByteArray())
                return Base64.encodeToString(bytes, Base64.NO_WRAP)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun decode(encodedString: String, decrypter: Cipher): String? {
        try {
            val bytes = Base64.decode(encodedString, Base64.NO_WRAP)
            return String(decrypter.doFinal(bytes))
        } catch (exception: Exception) {
            exception.printStackTrace()
        }

        return null
    }


    fun getCryptoObjectFor(key: String): FingerprintManagerCompat.CryptoObject? {
        return if (isKeyReady(key) && initCipher(Cipher.DECRYPT_MODE, key)) {
            FingerprintManagerCompat.CryptoObject(cipher)
        } else null
    }

}

