package dev.adfection.scanner.vpn

import android.content.Context
import android.util.Log
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Drives the official WireGuard userspace backend, and — critically — owns the hand-off between
 * the two mutually exclusive tunnel owners in this app.
 *
 * ## The constraint this class exists to handle
 * Android permits exactly one active VPN per user or profile; starting a new one stops the old one
 * ([VPN guide](https://developer.android.com/develop/connectivity/vpn)). The DNS scanner and a
 * WireGuard tunnel therefore **cannot run at the same time**. There is no API to nest them.
 *
 * Rather than pretend otherwise, the app exposes two modes and this class performs the switch
 * explicitly, surfacing the trade-off to the user:
 *
 * | Mode | DNS/AdFection monitoring | Traffic encrypted to a VPN gateway |
 * |---|---|---|
 * | [Mode.SCANNER] | yes | no |
 * | [Mode.TUNNEL] | no (see note) | yes |
 *
 * **Note on TUNNEL mode:** protection is not zero. If the WireGuard profile specifies `DNS = `,
 * every lookup still goes through the provider's resolver over the encrypted tunnel, so the
 * *network* is protected. What is lost is this app's local IOC matching, because the queries no
 * longer pass through our tun. The UI states this plainly.
 */
class WireGuardEngine(private val context: Context) {

    enum class Mode { SCANNER, TUNNEL }

    /** State of the WireGuard tunnel as observed by the UI. */
    data class Snapshot(
        val mode: Mode = Mode.SCANNER,
        val tunnelState: Tunnel.State = Tunnel.State.DOWN,
        val activeProfile: String? = null,
        val lastError: String? = null,
    )

    private val backend: Backend by lazy { GoBackend(context) }

    /** One [Tunnel] instance per profile name; the backend tracks them by name. */
    private var current: ProfileTunnel? = null

    @Volatile
    var lastError: String? = null
        private set

    @Volatile
    var activeProfile: String? = null
        private set

    /**
     * A tunnel bound to one parsed config.
     *
     * The WireGuard backend keys tunnels by [getName], so the name doubles as identity. Renaming a
     * profile therefore requires bringing it down first.
     */
    private inner class ProfileTunnel(
        private val profileName: String,
        val config: Config,
    ) : Tunnel {
        override fun getName(): String = profileName
        override fun onStateChange(newState: Tunnel.State) {
            Log.i(TAG, "tunnel '$profileName' -> $newState")
        }
    }

    /** Whether the WireGuard backend can run on this device (bundled native library present). */
    fun isSupported(): Boolean = runCatching {
        val version = backend.version
        version.isNotBlank()
    }.getOrElse {
        lastError = "WireGuard backend unavailable: ${it.message}"
        false
    }

    /**
     * Bring up [profileName] from its stored config.
     *
     * @return null on success, or a message to show the user.
     */
    suspend fun connect(profileName: String, rawConfig: String): String? = withContext(Dispatchers.IO) {
        lastError = null
        try {
            val config = WireGuardProfiles.parse(rawConfig)
            val tunnel = ProfileTunnel(profileName, config)
            // GoBackend.setState() throws on failure and returns the *new* state on success.
            val state = backend.setState(tunnel, Tunnel.State.UP, config)
            if (state != Tunnel.State.UP) {
                val message = "Backend reported state $state after requesting UP."
                lastError = message
                return@withContext message
            }
            current = tunnel
            activeProfile = profileName
            null
        } catch (t: Throwable) {
            // The two failure modes a user actually hits, named so the message is actionable.
            val message = when {
                t.message?.contains("Unable to configure tunnel", ignoreCase = true) == true ->
                    "The system refused the tunnel configuration. Another VPN is probably active."

                t.message?.contains("Permission", ignoreCase = true) == true ||
                    t.message?.contains("prepare", ignoreCase = true) == true ->
                    "VPN permission was not granted for this app."

                else -> "Connect failed: ${t.message ?: t::class.java.simpleName}"
            }
            lastError = message
            Log.w(TAG, "connect($profileName) failed", t)
            message
        }
    }

    /** Bring the tunnel down. Safe to call when nothing is connected. */
    suspend fun disconnect(): String? = withContext(Dispatchers.IO) {
        val tunnel = current ?: run {
            activeProfile = null
            return@withContext null
        }
        try {
            backend.setState(tunnel, Tunnel.State.DOWN, null)
            current = null
            activeProfile = null
            null
        } catch (t: Throwable) {
            val message = "Disconnect failed: ${t.message ?: t::class.java.simpleName}"
            lastError = message
            Log.w(TAG, "disconnect failed", t)
            // The tunnel is gone even if the backend reported an error, so clear local state.
            current = null
            activeProfile = null
            message
        }
    }

    fun tunnelState(): Tunnel.State = runCatching { current?.let { backend.getState(it) } }
        .getOrNull() ?: Tunnel.State.DOWN

    /** Byte counters for the active profile, or null when nothing is connected. */
    fun statistics(): Pair<Long, Long>? = runCatching {
        val tunnel = current ?: return null
        val stats = backend.getStatistics(tunnel)
        stats.totalRx() to stats.totalTx()
    }.getOrNull()

    private companion object {
        const val TAG = "AdfectionWireGuard"
    }
}
