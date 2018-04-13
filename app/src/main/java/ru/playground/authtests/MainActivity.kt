package ru.playground.authtests

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.preference.PreferenceManager
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
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

    var fingerprintHelper: FingerprintHelper? = null

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

    override fun onStop() {
        super.onStop()
        fingerprintHelper?.cancel()
    }

    override fun onClick(clickedView: View) {
        when (clickedView.id) {
            buttonDecipherPin.id -> decipherPin()
            buttonRememberPin.id -> rememberPin(editPin.text.toString())
        }
    }

    private fun rememberPin(pin: String) {
        if (pin.length < 3) {
            toast("PIN is too short")
            return
        }

        val encoded = keyStoreProvider.encode(PIN, pin)
        preferences.edit {
            putString(PIN, encoded)
        }

    }


    private fun decipherPin() {
        if (!hasPin) {
            alert("No saved PIN")
            return
        }

        when (touchIdState) {
            TouchIdState.NOT_SUPPORTED -> toast("NOT SUPPORTED")
            TouchIdState.NOT_SECURED -> toast("NOT SECURED")
            TouchIdState.NO_FINGERPRINTS -> toast("NO FINGERPRINTS")
            TouchIdState.READY -> {
                val cryptoObject = keyStoreProvider.getCryptoObjectFor(PIN)
                if (cryptoObject != null) {
                    toast("Use your finger to get a PIN")
                    fingerprintHelper = FingerprintHelper(this)
                    fingerprintHelper?.let {
                        it.errorListener = this::alert
                        it.successListener = this::onAuthSuccess
                        it.start(cryptoObject)
                    }
                } else {
                    preferences.edit {
                        remove(PIN)
                    }
                    alert("Removed memorized PIN due to fingerprint set change")
                }
            }
        }
    }

    private fun onAuthSuccess(result: FingerprintManagerCompat.AuthenticationResult?) {
        result?.let {
            val cipher = it.cryptoObject.cipher
            val encoded = preferences.getString(PIN, null)
            if (encoded != null || cipher != null) {
                val decoded = keyStoreProvider.decode(PIN, encoded, cipher!!)
                alert(decoded ?: "decoded is null WTF")
            }
        }
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun alert(message: String) {
        val dialog = AlertDialog.Builder(this)
                .setMessage(message)
                .setCancelable(false)
                .setPositiveButton("Close", { dialog, _ -> dialog.dismiss() })
                .create()
        dialog.show()
    }

    class FingerprintHelper(private val context: Context) : FingerprintManagerCompat.AuthenticationCallback() {
        private var cancellationSignal: CancellationSignal? = null
        var errorListener: ((errorMessage: String) -> Unit)? = null
        var successListener: ((result: FingerprintManagerCompat.AuthenticationResult?) -> Unit)? = null

        fun start(cryptoObject: FingerprintManagerCompat.CryptoObject) {
            cancellationSignal = CancellationSignal()
            val managerCompat = FingerprintManagerCompat.from(context)
            managerCompat.authenticate(cryptoObject, 0, cancellationSignal, this, null)
        }

        fun cancel() {
            cancellationSignal?.cancel()
            errorListener = null
            successListener = null
        }

        override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
            errorListener?.invoke(errString.toString())
        }

        override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
            successListener?.invoke(result)
        }

        override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
            errorListener?.invoke(helpString.toString())
        }

        override fun onAuthenticationFailed() {
            errorListener?.invoke("Failed")
        }
    }

}
