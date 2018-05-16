package ru.playground.authtests.crypto

import java.security.Key
import javax.crypto.BadPaddingException

interface IEncryptedStorage {
    val secretKey: Key

    /**
     * Performs data encoding and then puts a result into provided storage
     * @param alias encoded data identifier
     * @param value a string to encode
     * @param secret defaults to random secret key, use [keyFrom] static method to apply non random key
     */
    @Throws(Exception::class)
    fun put(alias: String, value: String, secret: Key = secretKey)

    /**
     * Finds an encoded value inside provided secret storage, and decodes it
     * @param alias encoded data identifier
     * @param secret defaults to random secret key, use [keyFrom] static method to apply non random key
     * @return a string with encoded data, or null if not found
     */
    @Throws(BadPaddingException::class)
    fun get(alias: String, secret: Key = secretKey): String?

    /**
     * Creates encrypting key from given input string
     */
    fun keyFrom(input: String): Key
}