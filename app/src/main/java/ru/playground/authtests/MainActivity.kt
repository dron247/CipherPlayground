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
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import ru.playground.authtests.crypto.IDataVault
import ru.playground.authtests.crypto.IEncryptedStorage
import ru.playground.authtests.crypto.SimpleEncryptedStorage
import javax.crypto.BadPaddingException

class MainActivity : AppCompatActivity(), View.OnClickListener {

    companion object {
        const val PIN = "pin"
    }

    private lateinit var touchIdKeyStoreProvider: TouchIdKeyStoreProvider
    private val preferences: SharedPreferences by lazy {
        PreferenceManager.getDefaultSharedPreferences(this)
    }

    private val vault: IDataVault by lazy {
        object : IDataVault {
            override fun write(key: String, value: String) {
                preferences.edit {
                    putString(key, value)
                }
            }

            override fun read(key: String, defaultValue: String?): String? =
                    preferences.getString(key, defaultValue)

        }
    }


    private var fingerprintHelper: FingerprintHelper? = null

    private val encryptedStorage: IEncryptedStorage by lazy {
        SimpleEncryptedStorage(this, vault, "authTestsSecret")
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        touchIdKeyStoreProvider = TouchIdKeyStoreProvider()
    }

    override fun onStart() {
        super.onStart()
        buttonDecipherPin.setOnClickListener(this)
        buttonRememberPin.setOnClickListener(this)
        buttonEncryptToken.setOnClickListener(this)
        buttonDecryptToken.setOnClickListener(this)
        buttonEncryptTokenWithPin.setOnClickListener(this)
        buttonDecryptTokenWithPin.setOnClickListener(this)
    }

    override fun onStop() {
        super.onStop()
        fingerprintHelper?.cancel()
    }

    override fun onClick(clickedView: View) {
        when (clickedView.id) {
            buttonDecipherPin.id -> decipherPin()
            buttonRememberPin.id -> rememberPin(editPin.text.toString())
            buttonEncryptToken.id -> encodeToken(editToken.text.toString())
            buttonDecryptToken.id -> decodeToken()
            buttonEncryptTokenWithPin.id -> encodeToken(editToken.text.toString(), editPin.text.toString())
            buttonDecryptTokenWithPin.id -> decodeToken(editPin.text.toString())
        }
    }

    private fun decodeToken() {
        val str = encryptedStorage.get("token") ?: "empty"
        alert(str)
    }

    private fun encodeToken(input: String) {
        encryptedStorage.put("token", input)
        toast("Encoded value: ${editToken.text}")
    }


    private fun decodeToken(pass: String) {
        try {
            val str = encryptedStorage
                    .get("token2", secret = encryptedStorage.keyFrom(pass)) ?: "empty"
            alert(str)
        } catch (bpe: BadPaddingException) {
            alert("Incorrect password")
        }

    }

    private fun encodeToken(input: String, pass: String) {
        encryptedStorage.put("token2", input, secret = encryptedStorage.keyFrom(pass))
        toast("Encoded value: ${editToken.text}")
    }

    private fun rememberPin(pin: String) {
        if (pin.length < 3) {
            toast("PIN is too short")
            return
        }

        val encoded = touchIdKeyStoreProvider.encode(PIN, pin)
        preferences.edit {
            putString(PIN, encoded)
        }

    }


    private fun decipherPin() {
        if (!preferences.contains(PIN)) {
            alert("No saved PIN")
            return
        }

        when (touchIdState) {
            TouchIdState.NOT_SUPPORTED -> toast("NOT SUPPORTED")
            TouchIdState.NOT_SECURED -> toast("NOT SECURED")
            TouchIdState.NO_FINGERPRINTS -> toast("NO FINGERPRINTS")
            TouchIdState.READY -> {
                val cryptoObject = touchIdKeyStoreProvider.getCryptoObjectFor(PIN)
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
                val decoded = touchIdKeyStoreProvider.decode(encoded, cipher!!)
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
