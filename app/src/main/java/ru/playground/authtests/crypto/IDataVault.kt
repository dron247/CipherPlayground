package ru.playground.authtests.crypto

interface IDataVault {
    fun write(key: String, value: String)
    fun read(key: String, defaultValue: String? = null): String?
}