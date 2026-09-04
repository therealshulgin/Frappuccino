package org.stream.crypto.capture

import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import timber.log.Timber
import java.util.ArrayDeque
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * Detects vigorous "frappuccino shake" gestures using the accelerometer.
 *
 * Trigger : `|magnitude - GRAVITY_EARTH|` above [joltThreshold] counts as one
 * jolt, 3 jolts inside 1 s fire, then 5 s of cooldown. The count, the window
 * and the cooldown are the constants below. The threshold is not one of them —
 * it is a constructor parameter, MED 7.0 m/s² by default, LOW 10.0 or HIGH 5.0
 * through [thresholdFor] and the user's sensitivity setting.
 *
 * The calibration story is ordinary human motion : walking peaks around 1.2G,
 * running around 2G, a deliberate shake 3-5G. Those are absolute magnitudes
 * whereas the code tests a delta above gravity, so read them as an order of
 * magnitude and not as a proven rejection bound — they have not been
 * re-measured since the threshold became configurable. Measure before moving
 * one, because a false positive is not a cosmetic annoyance : the trigger
 * starts a recording, vibrates the phone for 200 ms and shows a toast
 * (`StreamActivity.buildShakeDetector`), so a phone that fires in a pocket
 * exposes the person carrying it.
 */
class ShakeDetector(
    private val sensorManager: SensorManager,
    /**
     * Jolt magnitude (m/s² above gravity) that counts as one
     * jolt. Defaults to [JOLT_THRESHOLD] (= MED sensitivity, the historical
     * hard-coded value). Higher = a firmer shake is required. Build it from
     * a user setting via [thresholdFor].
     */
    private val joltThreshold: Float = JOLT_THRESHOLD,
    private val onShakeDetected: () -> Unit
) : SensorEventListener {

    companion object {
        const val JOLT_THRESHOLD = 7.0f      // m/s² above gravity (firm shake, not cocktail)
        const val JOLT_COUNT_THRESHOLD = 3   // jolts required in window
        const val WINDOW_MS = 1000L          // detection window
        const val DEBOUNCE_MS = 5000L        // cooldown after trigger

        /**
         * Map a user sensitivity setting ("LOW"|"MED"|"HIGH") to
         * the jolt threshold. Higher sensitivity = lower threshold = easier
         * to trigger. MED reproduces the historical hard-coded behaviour.
         */
        fun thresholdFor(sensitivity: String): Float = when (sensitivity) {
            "HIGH" -> 5.0f
            "LOW" -> 10.0f
            else -> JOLT_THRESHOLD // MED = 7.0
        }
    }

    private val joltTimestamps = ArrayDeque<Long>()
    private var lastTriggerMs = 0L
    private var isListening = false

    fun start() {
        if (isListening) return
        val accelerometer = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        if (accelerometer != null) {
            sensorManager.registerListener(this, accelerometer, SensorManager.SENSOR_DELAY_NORMAL)
            isListening = true
            Timber.d("ShakeDetector started")
        } else {
            Timber.w("No accelerometer available")
        }
    }

    fun stop() {
        if (!isListening) return
        sensorManager.unregisterListener(this)
        isListening = false
        joltTimestamps.clear()
        Timber.d("ShakeDetector stopped")
    }

    override fun onSensorChanged(event: SensorEvent) {
        val x = event.values[0]
        val y = event.values[1]
        val z = event.values[2]

        val magnitude = sqrt(x * x + y * y + z * z)
        val delta = abs(magnitude - SensorManager.GRAVITY_EARTH)

        if (delta > joltThreshold) {
            val now = System.currentTimeMillis()
            joltTimestamps.addLast(now)

            // Prune old jolts outside window
            while (joltTimestamps.isNotEmpty() && joltTimestamps.first < now - WINDOW_MS) {
                joltTimestamps.removeFirst()
            }

            if (joltTimestamps.size >= JOLT_COUNT_THRESHOLD) {
                if (now - lastTriggerMs > DEBOUNCE_MS) {
                    lastTriggerMs = now
                    joltTimestamps.clear()
                    Timber.d("SHAKE DETECTED! Triggering stream.")
                    onShakeDetected()
                }
            }
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
}
