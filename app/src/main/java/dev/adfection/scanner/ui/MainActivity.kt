package dev.adfection.scanner.ui

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import dev.adfection.scanner.R
import dev.adfection.scanner.data.Action
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.databinding.ActivityMainBinding
import dev.adfection.scanner.net.AdfectionVpnService
import dev.adfection.scanner.net.ScannerState
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Single-screen console: scanner status, the two audit reports, and the evidence log.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: ScannerViewModel by viewModels()
    private lateinit var logAdapter: EventAdapter
    private lateinit var postureAdapter: FindingAdapter
    private lateinit var appAdapter: AppFindingAdapter

    /** Consent dialog for the VPN; the service is only started after an explicit grant. */
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            AdfectionVpnService.start(this)
        } else {
            toast(getString(R.string.vpn_denied))
        }
    }

    private val notificationConsent =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* advisory only */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        logAdapter = EventAdapter()
        postureAdapter = FindingAdapter()
        appAdapter = AppFindingAdapter()

        binding.logList.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = logAdapter
        }
        binding.postureList.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = postureAdapter
            isNestedScrollingEnabled = false
        }
        binding.appList.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = appAdapter
            isNestedScrollingEnabled = false
        }

        binding.toggleProtection.setOnClickListener {
            if (ScannerState.state.value.active) {
                AdfectionVpnService.stop(this)
            } else {
                requestVpnConsent()
            }
        }

        binding.buttonOpenVpn.setOnClickListener {
            startActivity(Intent(this, dev.adfection.scanner.vpn.VpnActivity::class.java))
        }

        binding.buttonRunAudit.setOnClickListener {
            viewModel.runAudits()
        }

        binding.buttonClearLog.setOnClickListener {
            viewModel.clearLog()
        }

        binding.buttonExportReport.setOnClickListener {
            viewModel.buildReport { result ->
                result
                    .onSuccess { intent ->
                        // The chooser is what makes this useful: mail, Signal, a notes app, or a direct
                        // transfer to whoever is helping. Nothing is sent automatically.
                        startActivity(Intent.createChooser(intent, getString(R.string.button_export_report)))
                    }
                    .onFailure { error ->
                        toast(getString(R.string.export_failed, error.message ?: getString(R.string.unknown)))
                    }
            }
        }

        binding.buttonLanguage.setOnClickListener { showLanguagePicker() }
        binding.rowLanguage.setOnClickListener { showLanguagePicker() }

        binding.switchBlockAds.setOnCheckedChangeListener { _, checked -> viewModel.setBlockAds(checked) }
        binding.switchAlertTracking.setOnCheckedChangeListener { _, checked -> viewModel.setAlertTracking(checked) }
        binding.switchBlockAdint.setOnCheckedChangeListener { _, checked -> viewModel.setBlockAdint(checked) }

        binding.textIndicators.text = getString(R.string.indicators_loading)

        observeState()
        observeLog()
        observeReports()

        viewModel.bootstrap()
        requestNotificationPermissionIfNeeded()
    }

    private fun observeState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                ScannerState.state.collectLatest { snapshot ->
                    binding.textStatus.text = if (snapshot.active) {
                        getString(R.string.status_active)
                    } else {
                        getString(R.string.status_inactive)
                    }
                    binding.textStats.text = getString(
                        R.string.stats_format,
                        snapshot.queriesSeen,
                        snapshot.blocked,
                        snapshot.alerted,
                    )
                    binding.toggleProtection.text = getString(
                        if (snapshot.active) R.string.action_stop_scanning else R.string.action_start_scanning
                    )
                    // The protection button keeps its rounded drawable; only the fill colour is
                    // switched, so the shape and ripple survive.
                    binding.toggleProtection.backgroundTintList = android.content.res.ColorStateList.valueOf(
                        getColor(if (snapshot.active) R.color.accent_active else R.color.accent_idle),
                    )

                    // Status dot: green while running, quiet grey when stopped.
                    binding.statusDot.setBackgroundResource(
                        if (snapshot.active) R.drawable.bg_status_dot_live else R.drawable.bg_status_dot_idle,
                    )

                    binding.textChain.text = when (snapshot.chainProgress) {
                        3 -> getString(R.string.chain_full)
                        2 -> getString(R.string.chain_two)
                        1 -> getString(R.string.chain_one)
                        else -> getString(R.string.chain_none)
                    }
                    binding.textChain.setTextColor(
                        getColor(if (snapshot.chainProgress >= 2) R.color.severity_critical else R.color.on_surface_muted)
                    )
                    // Chain dot only turns red once the sequence reaches the "escalate" stage.
                    binding.chainDot.setBackgroundResource(
                        when {
                            snapshot.chainProgress >= 2 -> R.drawable.bg_status_dot_alert
                            snapshot.chainProgress >= 1 -> R.drawable.bg_status_dot_live
                            else -> R.drawable.bg_status_dot_idle
                        },
                    )
                }
            }
        }
    }

    private fun observeLog() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.events.collectLatest { events ->
                    logAdapter.submit(events)
                    binding.textLogEmpty.visibility = if (events.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
                }
            }
        }
    }

    private fun observeReports() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.posture.collectLatest { postureAdapter.submit(it) }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.appFindings.collectLatest { appAdapter.submit(it) }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.indicatorSummary.collectLatest { summary ->
                    binding.textIndicators.text = summary
                }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.config.collectLatest { config ->
                    binding.switchBlockAds.isChecked = config.blockAds
                    binding.switchAlertTracking.isChecked = config.alertTracking
                    binding.switchBlockAdint.isChecked = config.blockAdint
                }
            }
        }
    }

    private fun requestVpnConsent() {
        val prepare = VpnService.prepare(this)
        if (prepare == null) {
            AdfectionVpnService.start(this)
        } else {
            vpnConsent.launch(Intent(prepare))
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !NotificationManagerCompat.from(this).areNotificationsEnabled()
        ) {
            notificationConsent.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun onResume() {
        super.onResume()
        refreshLanguageLabels()
        viewModel.refreshLog()
    }

    /**
     * Show the active language in both affordances.
     *
     * Called on resume as well as on change: the per-app locale can also be changed from the system's
     * own "App languages" screen on API 33+, so this activity has to re-read it rather than assume its
     * own last action was the last word.
     */
    private fun refreshLanguageLabels() {
        binding.textLanguageCurrent.text = AppLanguage.currentLabel(this)
        binding.buttonLanguage.text = AppLanguage.currentChipLabel()
    }

    /** Present the shipped languages. Selection applies immediately, without restarting the app. */
    private fun showLanguagePicker() {
        val tag = AppLanguage.currentTag()
        val labels = AppLanguage.options.map { option ->
            val active = if (option.tag.isEmpty()) tag.isBlank() else {
                tag.substringBefore('-').substringBefore('_')
                    .equals(option.tag, ignoreCase = true)
            }
            val label = AppLanguage.displayLabel(this, option)
            if (active) "\u2713  $label" else "      $label"
        }.toTypedArray()

        AlertDialog.Builder(this)
            .setTitle(R.string.language_picker_title)
            .setItems(labels) { _, which ->
                AppLanguage.apply(AppLanguage.options[which].tag)
                // Recreate so every string on screen is re-resolved for the new locale. AppCompat
                // would also apply it on the next configuration change, but doing it here means the
                // change is visible immediately rather than after navigating away and back.
                recreate()
            }
            .setMessage(R.string.language_note)
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
