package ru.playground.authtests

import android.content.SharedPreferences
import android.os.Bundle
import android.preference.PreferenceManager
import android.support.v7.app.AppCompatActivity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast

class MainActivity : AppCompatActivity(), View.OnClickListener {

    companion object {
        const val PIN = "pin"
    }

    private lateinit var keyStoreProvider: KeyStoreProvider
    private lateinit var preferences: SharedPreferences

    lateinit var buttonDecipherPin: Button
    lateinit var buttonRememberPin: Button
    lateinit var editPin: EditText

    private val hasPin by lazy {
        preferences.contains(PIN)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        editPin = findViewById(R.id.editPin)

        buttonDecipherPin = findViewById<Button>(R.id.buttonDecipherPin).also {
            it.setOnClickListener(this)
        }
        buttonRememberPin = findViewById<Button>(R.id.buttonRememberPin).also {
            it.setOnClickListener(this)
        }

        keyStoreProvider = KeyStoreProvider()
        preferences = PreferenceManager.getDefaultSharedPreferences(this)
    }

    override fun onClick(clickedView: View) {
        when (clickedView.id) {
            buttonDecipherPin.id -> decipherPin()
            buttonRememberPin.id -> rememberPin(editPin.text.toString())
        }
    }

    private fun rememberPin(pin: String) {
        if (pin.length < 3) {
            Toast.makeText(this, "Короткий пин", Toast.LENGTH_SHORT).show()
            return
        }

        when (touchIdState) {
            TouchIdState.NOT_SUPPORTED -> toast("NOT SUPPORTED")
            TouchIdState.NOT_SECURED -> toast("NOT SECURED")
            TouchIdState.NO_FINGERPRINTS -> toast("NO FINGERPRINTS")
            TouchIdState.READY -> {
                val encoded = keyStoreProvider.encode(PIN, pin)
                preferences.edit().run {
                    putString(PIN, encoded)
                    apply()
                }
            }
        }

    }


    private fun decipherPin() {
        if (!hasPin) {
            toast("Нет сохраненного пина")
            return
        }
    }

    private fun toast(string: String) {
        Toast.makeText(this, string, Toast.LENGTH_SHORT).show()
    }

}
