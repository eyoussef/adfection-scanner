package dev.adfection.scanner.data

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persisted scanner configuration.
 *
 * Exposes a [StateFlow] snapshot so the UI and the VPN service observe the same values without
 * polling; every setter writes through to [SharedPreferences] and then publishes.
 */
class Settings(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences("adfection_settings", Context.MODE_PRIVATE)

    private val _state = MutableStateFlow(read())
    val state: StateFlow<Config> = _state.asStateFlow()

    /** Mutable snapshot of everything the scanner needs at runtime. */
    data class Config(
        /** Sinkhole responses instead of forwarding to the upstream resolver. */
        val blockAds: Boolean = true,
        /** Alert (but resolve) on tracking / identity-graph domains. */
        val alertTracking: Boolean = true,
        /** Block Candiru validator + C2 endpoints. Never disable-able from the UI on purpose. */
        val blockCandiru: Boolean = true,
        /** Block ADINT (Intelos / Tekma / Bindecy) infrastructure. */
        val blockAdint: Boolean = true,
        /** Upstream resolver used for everything not blocked. */
        val upstreamDns: String = "1.1.1.1",
        /** Per-observation log throttle so a chatty ad SDK cannot flood the evidence log. */
        val logThrottleSeconds: Int = 30,
    ) {
        /** Categories that are blocked versus merely alerted. */
        fun actionFor(category: ThreatCategory, severity: Severity): Action {
            val neverBlock = category == ThreatCategory.CONTEXT
            if (neverBlock) return Action.LOGGED

            val enabled = when (category) {
                ThreatCategory.CANDIRU_VALIDATOR, ThreatCategory.CANDIRU_C2, ThreatCategory.CANDIRU_IMPLANT -> true
                ThreatCategory.ADINT -> blockAdint
                ThreatCategory.AD_DELIVERY, ThreatCategory.TRACKING -> blockAds
                ThreatCategory.CONTEXT -> false
            }
            return when {
                enabled && severity >= Severity.HIGH -> Action.BLOCKED
                enabled && severity == Severity.MEDIUM && category != ThreatCategory.TRACKING -> Action.BLOCKED
                category == ThreatCategory.TRACKING && alertTracking -> Action.ALERTED
                else -> Action.LOGGED
            }
        }
    }

    private fun read(): Config = Config(
        blockAds = prefs.getBoolean(KEY_BLOCK_ADS, true),
        alertTracking = prefs.getBoolean(KEY_ALERT_TRACKING, true),
        blockCandiru = true, // intentionally not user-configurable
        blockAdint = prefs.getBoolean(KEY_BLOCK_ADINT, true),
        upstreamDns = prefs.getString(KEY_UPSTREAM, "1.1.1.1") ?: "1.1.1.1",
        logThrottleSeconds = prefs.getInt(KEY_THROTTLE, 30),
    )

    fun setBlockAds(value: Boolean) = update(KEY_BLOCK_ADS, value)
    fun setAlertTracking(value: Boolean) = update(KEY_ALERT_TRACKING, value)
    fun setBlockAdint(value: Boolean) = update(KEY_BLOCK_ADINT, value)
    fun setThrottle(seconds: Int) = update(KEY_THROTTLE, seconds.coerceIn(0, 3600))

    fun setUpstreamDns(value: String) {
        prefs.edit { putString(KEY_UPSTREAM, value.trim()) }
        _state.value = read()
    }

    private fun update(key: String, value: Boolean) {
        prefs.edit { putBoolean(key, value) }
        _state.value = read()
    }

    private fun update(key: String, value: Int) {
        prefs.edit { putInt(key, value) }
        _state.value = read()
    }

    private companion object {
        const val KEY_BLOCK_ADS = "block_ads"
        const val KEY_ALERT_TRACKING = "alert_tracking"
        const val KEY_BLOCK_ADINT = "block_adint"
        const val KEY_UPSTREAM = "upstream_dns"
        const val KEY_THROTTLE = "log_throttle_seconds"
    }
}
