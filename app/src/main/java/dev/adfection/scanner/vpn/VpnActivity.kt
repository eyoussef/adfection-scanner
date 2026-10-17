package dev.adfection.scanner.vpn

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.wireguard.android.backend.Tunnel
import dev.adfection.scanner.R
import dev.adfection.scanner.databinding.ActivityVpnBinding
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * The VPN screen.
 *
 * Two modes that cannot coexist, presented side by side with the trade-off stated in the UI rather
 * than buried in documentation.
 */
class VpnActivity : AppCompatActivity() {

    private lateinit var binding: ActivityVpnBinding
    private val viewModel: VpnViewModel by viewModels()
    private lateinit var profileAdapter: ProfileAdapter

    private val pickConfig = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@registerForActivityResult
        val name = queryDisplayName(uri)?.removeSuffix(WireGuardProfiles.SUFFIX)
            ?: "imported-${System.currentTimeMillis() / 1000}"
        viewModel.importProfileFromUri(name, uri)
    }

    private val pickFolder = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        uri?.let { viewModel.importFromTree(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityVpnBinding.inflate(layoutInflater)
        setContentView(binding.root)

        profileAdapter = ProfileAdapter(
            onConnect = { entry -> connectProfile(entry.name) },
            onDelete = { entry -> confirmDelete(entry.name) },
            onShow = { entry -> showProfileDetails(entry) },
        )
        binding.profileList.apply {
            layoutManager = LinearLayoutManager(this@VpnActivity)
            adapter = profileAdapter
            isNestedScrollingEnabled = false
        }

        binding.buttonOpenProviders.setOnClickListener {
            startActivity(Intent(this, ProvidersActivity::class.java))
        }

        binding.buttonWarpRegister.setOnClickListener { viewModel.registerWarp() }
        binding.buttonWarpRegenerate.setOnClickListener { viewModel.regenerateWarpProfile() }
        binding.buttonWarpProbe.setOnClickListener { viewModel.probeWarp() }
        binding.buttonWarpForget.setOnClickListener { confirmForgetWarp() }

        binding.buttonImportConf.setOnClickListener {
            pickConfig.launch(arrayOf("application/octet-stream", "text/plain", "*/*"))
        }
        binding.buttonImportFolder.setOnClickListener { pickFolder.launch(null) }
        binding.buttonPasteConf.setOnClickListener { showPasteDialog() }
        binding.buttonTemplate.setOnClickListener { showTemplateDialog() }

        binding.buttonConnect.setOnClickListener {
            val name = viewModel.wireGuard.value.activeProfile
            if (name == null) {
                val first = viewModel.profileList.value.firstOrNull { it.isValid }
                if (first == null) {
                    toast(getString(R.string.vpn_no_profile_to_connect))
                } else {
                    connectProfile(first.name)
                }
            } else {
                viewModel.disconnectWireGuard()
            }
        }

        binding.buttonUseScanner.setOnClickListener { viewModel.switchToScanner() }

        observe()
        viewModel.refreshProfiles()
        viewModel.refreshState()
        viewModel.refreshWarp()
    }

    private fun observe() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.profileList.collectLatest { entries ->
                    profileAdapter.submit(entries)
                    binding.textNoProfiles.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.wireGuard.collectLatest { snapshot ->
                    val connected = snapshot.tunnelState == Tunnel.State.UP || snapshot.activeProfile != null
                    binding.textMode.text = if (connected) {
                        getString(R.string.vpn_mode_tunnel, snapshot.activeProfile ?: "?")
                    } else {
                        getString(R.string.vpn_mode_scanner)
                    }
                    // Dot mirrors the main screen: green when a tunnel is carrying traffic, quiet grey
                    // when the scanner owns the slot instead.
                    binding.modeDot.setBackgroundResource(
                        if (connected) R.drawable.bg_status_dot_live else R.drawable.bg_status_dot_idle,
                    )
                    binding.textModeWarning.visibility = if (connected) View.VISIBLE else View.GONE
                    binding.buttonConnect.text = getString(
                        if (connected) R.string.vpn_disconnect else R.string.vpn_connect
                    )
                    binding.buttonUseScanner.isEnabled = connected

                    snapshot.lastError?.let { binding.textVpnError.text = it }
                    binding.textVpnError.visibility =
                        if (snapshot.lastError.isNullOrBlank()) View.GONE else View.VISIBLE
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.warp.collectLatest { state -> renderWarp(state) }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.message.collectLatest { message ->
                    message?.let {
                        toast(it)
                        viewModel.consumeMessage()
                    }
                }
            }
        }
    }

    /**
     * Render the WARP section.
     *
     * Two things here are deliberately conservative:
     *
     * 1. **The account line reports the account, never the tunnel.** It shows the account type and
     *    WARP+ status, and says nothing about whether traffic is currently wrapped.
     * 2. **A probe result is discarded the moment the tunnel is not up.** A stored probe is a
     *    measurement of a *previous* connection; leaving it on screen after the tunnel drops would
     *    show "WARP: on" for traffic that is no longer wrapped. The result is therefore only shown
     *    while the tunnel is actually connected, and the UI states the dependency out loud.
     */
    private fun renderWarp(state: VpnViewModel.WarpUiState) {
        val account = state.account
        binding.textWarpState.text = when {
            state.busy -> getString(R.string.warp_busy)
            account == null -> getString(R.string.warp_state_none)
            else -> getString(
                R.string.warp_state_registered,
                account.shortId(),
                account.accountType ?: getString(R.string.unknown),
                plusSuffix(account),
            )
        }

        binding.buttonWarpRegister.isEnabled = !state.busy
        binding.buttonWarpRegenerate.isEnabled = !state.busy && state.hasAccount
        binding.buttonWarpForget.isEnabled = !state.busy && state.hasAccount
        binding.buttonWarpProbe.isEnabled = !state.probing

        val tunnelUp = state.tunnelConnected
        binding.buttonWarpProbe.text = getString(
            when {
                state.probing -> R.string.warp_busy
                !tunnelUp -> R.string.warp_check_needs_tunnel
                else -> R.string.warp_check
            },
        )

        // A probe taken through a tunnel that is no longer up describes traffic that is no longer
        // wrapped, so it is not shown as current.
        binding.textWarpProbe.visibility = if (state.probe == null) View.GONE else View.VISIBLE
        binding.textWarpProbe.text = state.probe?.let { probe ->
            probe.describe() + if (!tunnelUp) getString(R.string.warp_probe_now_direct) else ""
        }
        state.probe?.let { probe ->
            binding.textWarpProbe.setTextColor(
                androidx.core.content.ContextCompat.getColor(
                    this,
                    if (probe.isActive && tunnelUp) R.color.severity_low else R.color.severity_medium,
                ),
            )
        }
    }

    /**
     * The account line's WARP+ suffix.
     *
     * `warp_plus: true` is what Cloudflare returns for **every** free account (verified against the
     * live API: `account_type: free`, `warp_plus: true`, `plus_expires_at: null`, `premium_data: 0`),
     * and wgcf prints `account_type`, `premium_data` and `quota` but never `warp_plus` at all. So the
     * flag is not a subscription indicator and is not presented as one: a real subscription is only
     * claimed when the licence actually expires, which is the field Cloudflare uses for it.
     */
    private fun plusSuffix(account: WarpAccount): String =
        if (account.plusExpiresAt != null) getString(R.string.warp_plus_active) else ""

    private fun confirmForgetWarp() {
        AlertDialog.Builder(this)
            .setTitle(R.string.warp_forget)
            .setMessage(R.string.warp_forget_message)
            .setPositiveButton(android.R.string.ok) { _, _ -> viewModel.forgetWarpAccount() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Hand the VPN slot over: the scanner must stop before a WireGuard tunnel can bind. */
    private fun connectProfile(name: String) {
        val prepare = android.net.VpnService.prepare(this)
        if (prepare != null) {
            toast(getString(R.string.vpn_needs_consent))
        }
        viewModel.connectWireGuard(name)
    }

    private fun confirmDelete(name: String) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.vpn_delete_title, name))
            .setMessage(R.string.vpn_delete_message)
            .setPositiveButton(android.R.string.ok) { _, _ -> viewModel.deleteProfile(name) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showProfileDetails(entry: WireGuardProfiles.Entry) {
        val text = if (entry.isValid) {
            // Never render the private key; show only what is safe and useful for verification.
            val config = entry.config!!
            buildString {
                append("name:      ").append(entry.name).append('\n')
                append("addresses: ").append(config.`interface`.addresses.joinToString(", ")).append('\n')
                append("dns:       ").append(config.`interface`.dnsServers.joinToString(", ").ifEmpty { "(none — system resolver inside the tunnel)" }).append('\n')
                config.`interface`.mtu.ifPresent { append("mtu:       ").append(it).append('\n') }
                append("peers:     ").append(config.peers.size).append('\n')
                config.peers.firstOrNull()?.let { peer ->
                    peer.endpoint.ifPresent { append("endpoint:  ").append(it).append('\n') }
                    peer.allowedIps.let { append("allowed:   ").append(it.joinToString(", ")).append('\n') }
                }
                append("\nPrivateKey and PublicKey are intentionally not shown.")
            }
        } else {
            "This profile could not be parsed:\n\n${entry.error}"
        }

        AlertDialog.Builder(this)
            .setTitle(entry.name)
            .setMessage(text)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showPasteDialog() {
        val input = android.widget.EditText(this).apply {
            hint = getString(R.string.vpn_paste_hint)
            minLines = 8
            gravity = android.view.Gravity.TOP or android.view.Gravity.START
        }
        val nameInput = android.widget.EditText(this).apply {
            hint = getString(R.string.vpn_name_hint)
        }
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 24, 48, 0)
            addView(nameInput)
            addView(input)
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.vpn_paste_title)
            .setView(container)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val name = nameInput.text.toString().ifBlank { "imported-${System.currentTimeMillis() / 1000}" }
                viewModel.importProfile(name, input.text.toString())
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showTemplateDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.vpn_template_title)
            .setMessage(WireGuardProfiles.template())
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun queryDisplayName(uri: Uri): String? = runCatching {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        }
    }.getOrNull()

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}
