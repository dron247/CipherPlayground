package ru.playground.authtests

import android.content.SharedPreferences
import android.os.Bundle
import android.preference.PreferenceManager
import android.support.v7.app.AlertDialog
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

        buttonDecipherPin = findViewById(R.id.buttonDecipherPin)
        buttonRememberPin = findViewById(R.id.buttonRememberPin)

        keyStoreProvider = KeyStoreProvider()
        preferences = PreferenceManager.getDefaultSharedPreferences(this)
    }

    override fun onStart() {
        super.onStart()
        buttonDecipherPin.setOnClickListener(this)
        buttonRememberPin.setOnClickListener(this)
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

        val encoded = keyStoreProvider.encode(PIN, pin)
        preferences.edit {
            putString(PIN, encoded)
        }

    }


    private fun decipherPin() {
        if (!hasPin) {
            toast("Нет сохраненного пина")
            return
        }

        when (touchIdState) {
            TouchIdState.NOT_SUPPORTED -> toast("NOT SUPPORTED")
            TouchIdState.NOT_SECURED -> toast("NOT SECURED")
            TouchIdState.NO_FINGERPRINTS -> toast("NO FINGERPRINTS")
            TouchIdState.READY -> {
                val cryptoObject = keyStoreProvider.getCryptoObjectFor(PIN)
                if (cryptoObject != null) {
                    toast("Use your finger to get a pin")
                    //
                } else {
                    preferences.edit {
                        remove(PIN)
                    }
                    toast("Removed memorized PIN due to fingerprint set change")
                }
            }
        }
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun alert(message: String) {
        val builder = AlertDialog.Builder(this)
    }

}
