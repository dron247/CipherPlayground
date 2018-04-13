package ru.playground.authtests

import android.content.SharedPreferences

//inline fun <T, R> T.run(block: T.() → R): R
inline fun SharedPreferences.edit(block: SharedPreferences.Editor.() -> Unit) {
    this.edit().run {
        block()
        apply()
    }
}