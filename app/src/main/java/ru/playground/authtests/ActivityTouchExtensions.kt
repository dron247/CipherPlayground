package ru.playground.authtests

import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat


/**
 * Check if we have hardware installed or not
 */
val Context.isTouchIdAvailable: Boolean
    get() = FingerprintManagerCompat.from(this).isHardwareDetected


/**
 * Describes possible states of fingerprint sensor
 */
enum class TouchIdState {
    NOT_SUPPORTED,
    NOT_SECURED,
    NO_FINGERPRINTS,
    READY
}

/**
 * Provides an information about fingerprints hardware state
 */
val Context.touchIdState: TouchIdState
    @TargetApi(Build.VERSION_CODES.M)
    get() {
        //if not available just return
        if (!this.isTouchIdAvailable) return TouchIdState.NOT_SUPPORTED

        val keyguardManager = this.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        //target api 23, we should not get here if its lower
        if (!keyguardManager.isDeviceSecure) return TouchIdState.NOT_SECURED

        val fingerprintManagerCompat = FingerprintManagerCompat.from(this)
        if (!fingerprintManagerCompat.hasEnrolledFingerprints()) return TouchIdState.NO_FINGERPRINTS
        return TouchIdState.READY

    }