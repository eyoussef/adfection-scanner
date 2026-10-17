package dev.adfection.scanner.vpn

import android.app.Activity
import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.wireguard.android.backend.Tunnel
import dev.adfection.scanner.R
import dev.adfection.scanner.net.AdfectionVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Coordinates the two mutually exclusive tunnel owners.
 *
 * Every transition here is explicit about what it is giving up, because the trade-off is real and
 * Android provides no way around it.
 */
class VpnViewModel(application: Application) : AndroidViewModel(application) {

    private val profiles = WireGuardProfiles(application)
    private val engine = WireGuardEngine(application)
    private val warpAccounts = WarpAccountStore(application)
    private val warpClient = WarpClient()

    private val _wireGuard = MutableStateFlow(WireGuardEngine.Snapshot())
    val wireGuard: StateFlow<WireGuardEngine.Snapshot> = _wireGuard.asStateFlow()

    private val _profileList = MutableStateFlow<List<WireGuardProfiles.Entry>>(emptyList())
    val profileList: StateFlow<List<WireGuardProfiles.Entry>> = _profileList.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    private val _warp = MutableStateFlow(WarpUiState())
    val warp: StateFlow<WarpUiState> = _warp.asStateFlow()


    /** Resolve a user-facing message. Messages are resources so they follow the device locale. */
    private fun msg(@androidx.annotation.StringRes id: Int, vararg args: Any): String =
        getApplication<Application>().getString(id, *args)

    fun consumeMessage() { _message.value = null }

    /**
     * What the WARP section shows.
     *
     * [busy] covers registration, which is a network round-trip the user has to wait on.
     * [probe] is the measurement from "Check WARP status" and is only meaningful while
     * [tunnelConnected] is true — a trace taken outside the tunnel describes direct traffic, and the
     * UI must not present it as a statement about the tunnel.
     */
    data class WarpUiState(
        val account: WarpAccount? = null,
        val busy: Boolean = false,
        val probe: WarpProbe? = null,
        val probing: Boolean = false,
        /** Whether a WireGuard tunnel owned by this app is currently up. */
        val tunnelConnected: Boolean = false,
    ) {
        val hasAccount: Boolean get() = account != null
    }

    fun refreshProfiles() {
        viewModelScope.launch {
            _profileList.value = withContext(Dispatchers.IO) { profiles.list() }
        }
    }

    fun engineSupported(): Boolean = engine.isSupported()

    /** Import a `.conf` the user picked or pasted. */
    fun importProfile(name: String, content: String) {
        viewModelScope.launch {
            val error = withContext(Dispatchers.IO) { profiles.save(name, content) }
            if (error != null) {
                _message.value = error
            } else {
                _message.value = msg(R.string.msg_profile_saved, name)
                refreshProfiles()
            }
        }
    }

    /** Import from a [android.net.Uri] chosen via the system file picker. */
    fun importProfileFromUri(name: String, uri: android.net.Uri) {
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) {
                runCatching {
                    getApplication<Application>().contentResolver
                        .openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                }.getOrNull()
            }
            if (text.isNullOrBlank()) {
                _message.value = msg(R.string.msg_file_unreadable)
            } else {
                importProfile(name, text)
            }
        }
    }

    fun deleteProfile(name: String) {
        viewModelScope.launch {
            val active = _wireGuard.value.activeProfile
            if (active == name) {
                _message.value = msg(R.string.msg_disconnect_before_delete, name)
                return@launch
            }
            withContext(Dispatchers.IO) { profiles.delete(name) }
            refreshProfiles()
        }
    }

    /**
     * Switch to WireGuard tunnel mode.
     *
     * Stops the DNS scanner first: Android would stop it anyway (one VPN per user), but doing it
     * deliberately means the scanner's own teardown runs and the UI state stays truthful.
     */
    fun connectWireGuard(name: String) {
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) { profiles.read(name) }
            if (raw == null) {
                _message.value = msg(R.string.msg_profile_unreadable, name)
                return@launch
            }

            // Hand the VPN slot over cleanly.
            AdfectionVpnService.stop(getApplication())
            delay(HANDOFF_DELAY_MS)

            val error = engine.connect(name, raw)
            if (error != null) {
                _message.value = error
            } else {
                _message.value = msg(R.string.msg_tunnel_connected, name)
            }
            refreshState()
        }
    }

    fun disconnectWireGuard() {
        viewModelScope.launch {
            val error = engine.disconnect()
            if (error != null) _message.value = error
            _message.value = msg(R.string.msg_tunnel_closed)
            refreshState()
        }
    }

    /** Switch back to scanner mode: drop the tunnel, then start the DNS inspector. */
    fun switchToScanner() {
        viewModelScope.launch {
            engine.disconnect()
            delay(HANDOFF_DELAY_MS)
            AdfectionVpnService.start(getApplication())
            _message.value = msg(R.string.msg_scanner_resumed)
            refreshState()
        }
    }

    fun refreshState() {
        viewModelScope.launch {
            val state = withContext(Dispatchers.IO) { engine.tunnelState() }
            val connected = engine.activeProfile != null && state == Tunnel.State.UP
            _wireGuard.value = WireGuardEngine.Snapshot(
                mode = if (engine.activeProfile != null) WireGuardEngine.Mode.TUNNEL else WireGuardEngine.Mode.SCANNER,
                tunnelState = state,
                activeProfile = engine.activeProfile,
                lastError = engine.lastError,
            )
            // Keep the WARP card's notion of "is the tunnel up" in step with the engine, so a probe
            // result is never presented as current after the tunnel goes down.
            _warp.value = _warp.value.copy(tunnelConnected = connected)
        }
    }

    /**
     * Import every `.conf` sitting in a folder the user picked. This is the practical path for
     * someone who generated several provider configs at once.
     */
    fun importFromTree(uri: android.net.Uri) {
        viewModelScope.launch {
            val imported = withContext(Dispatchers.IO) {
                val resolver = getApplication<Application>().contentResolver
                val tree = android.provider.DocumentsContract.buildDocumentUriUsingTree(
                    uri,
                    android.provider.DocumentsContract.getTreeDocumentId(uri),
                )
                val children = runCatching {
                    android.provider.DocumentsContract
                        .buildChildDocumentsUriUsingTree(tree, android.provider.DocumentsContract.getTreeDocumentId(tree))
                }.getOrNull() ?: return@withContext 0

                var count = 0
                runCatching {
                    resolver.query(children, arrayOf(android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)
                }.getOrNull()?.use { cursor ->
                    while (cursor.moveToNext()) {
                        val displayName = cursor.getString(0) ?: continue
                        if (!displayName.endsWith(WireGuardProfiles.SUFFIX)) continue
                        val docUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(tree, displayName)
                        val text = runCatching {
                            resolver.openInputStream(docUri)?.bufferedReader()?.use { it.readText() }
                        }.getOrNull() ?: continue
                        val name = displayName.removeSuffix(WireGuardProfiles.SUFFIX)
                        if (profiles.save(name, text) == null) count++
                    }
                }
                count
            }
            _message.value = if (imported > 0) {
                msg(R.string.msg_profiles_imported, imported)
            } else {
                msg(R.string.msg_no_conf_found)
            }
            refreshProfiles()
        }
    }

    /** Export a profile's text so the user can back it up or move it. */
    suspend fun exportProfile(name: String): String? = withContext(Dispatchers.IO) { profiles.read(name) }

    // ---------------------------------------------------------------------------------------------
    // Cloudflare WARP
    // ---------------------------------------------------------------------------------------------

    fun refreshWarp() {
        viewModelScope.launch {
            _warp.value = _warp.value.copy(account = withContext(Dispatchers.IO) { warpAccounts.load() })
        }
    }

    /**
     * Register a new WARP account and save the profile it produces.
     *
     * The generated profile is written through [WireGuardProfiles.save] rather than around it, so it
     * passes exactly the same validation as a hand-imported one: if Cloudflare ever returns something
     * unusable, the user is told here instead of discovering it on connect.
     */
    fun registerWarp() {
        viewModelScope.launch {
            if (_warp.value.busy) return@launch
            _warp.value = _warp.value.copy(busy = true)

            val result = withContext(Dispatchers.IO) { warpClient.register() }
            result
                .onSuccess { registration ->
                    val stored = withContext(Dispatchers.IO) { warpAccounts.save(registration.account) }
                    if (stored != null) {
                        _message.value = stored
                    } else {
                        val saved = withContext(Dispatchers.IO) {
                            profiles.save(WARP_PROFILE_NAME, registration.profile)
                        }
                        if (saved != null) {
                            // The account is stored but the profile is not; keeping the account
                            // means "Regenerate" can recover without burning another device slot.
                            _message.value = msg(R.string.msg_warp_profile_rejected, saved)
                        } else {
                            val license = registration.account.licenseKey?.let { " (license $it)" }.orEmpty()
                            _message.value = msg(R.string.msg_warp_created, license, WARP_PROFILE_NAME)
                        }
                    }
                }
                .onFailure { error ->
                    _message.value = error.message ?: msg(R.string.msg_warp_register_failed)
                }

            _warp.value = _warp.value.copy(
                busy = false,
                account = withContext(Dispatchers.IO) { warpAccounts.load() },
            )
            refreshProfiles()
        }
    }

    /** Rebuild the profile for the stored account without registering a second device. */
    fun regenerateWarpProfile() {
        viewModelScope.launch {
            val account = _warp.value.account
            if (account == null) {
                _message.value = msg(R.string.msg_warp_register_first)
                return@launch
            }
            if (_warp.value.busy) return@launch
            _warp.value = _warp.value.copy(busy = true)

            val result = withContext(Dispatchers.IO) { warpClient.regenerateProfile(account) }
            result
                .onSuccess { profile ->
                    val saved = withContext(Dispatchers.IO) { profiles.save(WARP_PROFILE_NAME, profile) }
                    _message.value = saved ?: msg(R.string.msg_warp_regenerated)
                }
                .onFailure { error ->
                    _message.value = error.message ?: msg(R.string.msg_warp_regenerate_failed)
                }

            _warp.value = _warp.value.copy(busy = false)
            refreshProfiles()
        }
    }

    /**
     * Ask Cloudflare whether WARP is actually carrying traffic.
     *
     * Must be run with the tunnel up to mean anything: WARP reports `off` when traffic leaves
     * unwrapped, which is the correct reading for scanner mode but not a fault.
     */
    fun probeWarp() {
        viewModelScope.launch {
            if (_warp.value.probing) return@launch
            _warp.value = _warp.value.copy(probing = true)
            val result = withContext(Dispatchers.IO) { warpClient.probeWarp() }
            _warp.value = _warp.value.copy(
                probing = false,
                probe = result.getOrNull(),
            )
            result.onFailure { _message.value = it.message ?: msg(R.string.msg_warp_check_failed) }
        }
    }

    /** Forget the stored WARP account. The profile on disk is left alone; delete it explicitly. */
    fun forgetWarpAccount() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { warpAccounts.clear() }
            _warp.value = WarpUiState()
            _message.value = msg(R.string.msg_warp_forgotten)
        }
    }

    /** A file to share the profile from. */
    fun profileFileFor(name: String): File = File(File(getApplication<Application>().filesDir, "wg"), "$name${WireGuardProfiles.SUFFIX}")

    private companion object {
        /**
         * Time for the system to tear one VpnService down before the next binds. Too short and the
         * new tunnel is rejected; long enough that the switch is not a race.
         */
        const val HANDOFF_DELAY_MS = 700L

        /** Profile name the generated WARP config is stored under. */
        const val WARP_PROFILE_NAME = "cloudflare-warp"
    }
}
