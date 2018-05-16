package ru.playground.authtests.crypto

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.Key
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/*
WARNING DOES NOT WORK COMPLETELY, Left here for some reasons
 */
@TargetApi(Build.VERSION_CODES.M)
class MarshmallowEncryptedStorage(
        private val vault: IDataVault,
        private val secretKeyAlias: String,
        private val keystoreProvider: String = "AndroidKeyStore"
) : IEncryptedStorage {
    companion object {
        private const val CIPHER_MODE = "AES/GCM/NoPadding"//"RSA/ECB/PKCS1Padding"
        private const val SECRET_KEY_SPEC_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val FIXED_IV = "twelve_bytes"
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(keystoreProvider).also {
            it.load(null)
        }
    }

    private fun getCipher(): Cipher {
        try {
            return Cipher.getInstance(CIPHER_MODE, "AndroidOpenSSL") // error in android 5: NoSuchProviderException: Provider not available: AndroidKeyStoreBCWorkaround
        } catch (exception: Exception) {
            throw RuntimeException("getCipher: Failed to get an instance of Cipher", exception)
        }
    }

    //region RSA pairs

    private fun initKeyPairIfNeeded(alias: String) {
        if (!keyStore.containsAlias(alias)) {
            val keyGenerator = KeyGenerator.getInstance(SECRET_KEY_SPEC_ALGORITHM, keystoreProvider)
            keyGenerator.init(
                    KeyGenParameterSpec.Builder(alias,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setRandomizedEncryptionRequired(false)
                            .build()
            )
            keyGenerator.generateKey()
        }
    }

    //endregion

    //region interface members
    override val secretKey: Key
        get() {
            initKeyPairIfNeeded(secretKeyAlias)
            return keyStore.getKey(secretKeyAlias, null)
        }

    override fun put(alias: String, value: String, secret: Key) {
        initKeyPairIfNeeded(alias)
        val cipher = getCipher().also {
            it.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(128, FIXED_IV.toByteArray()))
        }
        val encodedBytes = cipher.doFinal(value.toByteArray())
        vault.write(alias, Base64.encodeToString(encodedBytes, Base64.DEFAULT))
    }

    override fun get(alias: String, secret: Key): String? {
        val cipher = getCipher().also {
            it.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, FIXED_IV.toByteArray()))
        }
        val encoded = vault.read(alias) ?: return null
        val decoded = cipher.doFinal(Base64.decode(encoded, Base64.DEFAULT))
        return String(decoded)
    }

    override fun keyFrom(input: String): Key {
        if (input.isEmpty()) throw IllegalArgumentException("Key must be longer than 0")
        val bytes = input.toByteArray()
        if (bytes.size > 16) throw IllegalArgumentException("Key size must be 16 bytes max")
        //initKeyPairIfNeeded(input)
        val keyBytes = ByteArray(16)
        keyBytes.fill(0)
        bytes.forEachIndexed({ index, byte ->
            keyBytes[index] = byte
        })

        return SecretKeySpec(keyBytes, SECRET_KEY_SPEC_ALGORITHM)
    }
    //endregion
}