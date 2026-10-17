package dev.adfection.scanner.scan

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import dev.adfection.scanner.R
import dev.adfection.scanner.data.PostureFinding
import dev.adfection.scanner.data.Severity

/**
 * Device posture checks that map directly onto AdFection attack prerequisites and Citizen Lab's
 * defensive recommendations (report 195 §11).
 *
 * Each finding names the concrete setting to change. Nothing here is a heuristic score — every
 * item is an observable, verifiable state of the device.
 */
class PostureScanner(private val context: Context) {

    fun scan(): List<PostureFinding> {
        val findings = ArrayList<PostureFinding>(10)
        val resolver = context.contentResolver

        // 0. Private DNS (DNS-over-TLS). This is the single most common reason a DNS-inspecting
        //    VPN appears to "not work": when a Private DNS hostname is configured, Android
        //    resolves through that TLS connection and bypasses the VPN's advertised DNS servers
        //    entirely, so no query ever reaches this app's tun interface.
        privateDnsMode()?.let { (mode, specifier) ->
            if (mode != "off") {
                val target = specifier.ifBlank { "automatic (the network's resolver)" }
                findings.add(
                    PostureFinding(
                        id = "private_dns_bypass",
                        title = context.getString(R.string.posture_private_dns_title),
                        detail = context.getString(R.string.posture_private_dns_detail, mode, target),
                        severity = Severity.CRITICAL,
                        remediation = context.getString(R.string.posture_private_dns_fix),
                    )
                )
            }
        }

        // 1. Advertising ID: the primary selector the attacker uses to pick a device out of a bid
        //    stream. Disabling it removes the stable identifier from the auction.
        val adIdLimit = Settings.Secure.getInt(resolver, "limit_ad_tracking", -1)
        if (adIdLimit == 0) {
            findings.add(
                PostureFinding(
                    id = "ad_id_enabled",
                    title = context.getString(R.string.posture_ad_id_title),
                    detail = context.getString(R.string.posture_ad_id_detail),
                    severity = Severity.HIGH,
                    remediation = context.getString(R.string.posture_ad_id_fix),
                )
            )
        } else if (adIdLimit < 0) {
            findings.add(
                PostureFinding(
                    id = "ad_id_unknown",
                    title = context.getString(R.string.posture_ad_id_unknown_title),
                    detail = context.getString(R.string.posture_ad_id_unknown_detail),
                    severity = Severity.LOW,
                    remediation = context.getString(R.string.posture_ad_id_unknown_fix),
                )
            )
        }

        // 2. Accessibility services: full UI read + input injection. The standard Android spyware
        //    persistence/collection path, and the only step a user can audit unaided.
        val accessibility = readEnabledServices("enabled_accessibility_services")
        val suspiciousAccessibility = accessibility.filter { entry ->
            SUSPICIOUS_ACCESSIBILITY_TERMS.any { entry.contains(it, ignoreCase = true) }
        }
        if (suspiciousAccessibility.isNotEmpty()) {
            findings.add(
                PostureFinding(
                    id = "accessibility_sideloaded",
                    title = context.getString(R.string.posture_accessibility_title),
                    detail = context.getString(
                        R.string.posture_accessibility_detail,
                        suspiciousAccessibility.joinToString(", "),
                    ),
                    severity = Severity.HIGH,
                    remediation = context.getString(R.string.posture_accessibility_fix),
                )
            )
        }

        // 3. Overlay permission: used to draw fake UI over real apps (credential/session capture).
        if (Settings.canDrawOverlays(context) == true) {
            findings.add(
                PostureFinding(
                    id = "overlay_permission",
                    title = context.getString(R.string.posture_overlay_title),
                    detail = context.getString(R.string.posture_overlay_detail),
                    severity = Severity.MEDIUM,
                    remediation = context.getString(R.string.posture_overlay_fix),
                )
            )
        }

        // 4. Developer options / ADB: enables installs and debugging from a host.
        val adbEnabled = Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1
        val devOptions = Settings.Global.getInt(
            resolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0,
        ) == 1
        if (adbEnabled || devOptions) {
            findings.add(
                PostureFinding(
                    id = "developer_options",
                    title = context.getString(R.string.posture_dev_options_title),
                    detail = context.getString(R.string.posture_dev_options_detail),
                    severity = Severity.MEDIUM,
                    remediation = context.getString(R.string.posture_dev_options_fix),
                )
            )
        }

        // 5. Unknown sources: APK sideloading outside an app store review path.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            @Suppress("DEPRECATION")
            val unknownSources = Settings.Secure.getInt(resolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            if (unknownSources) {
                findings.add(
                    PostureFinding(
                        id = "unknown_sources",
                        title = context.getString(R.string.posture_unknown_sources_title),
                        detail = context.getString(R.string.posture_unknown_sources_detail),
                        severity = Severity.MEDIUM,
                        remediation = context.getString(R.string.posture_unknown_sources_fix),
                    )
                )
            }
        }

        // 6. Another VPN is active: our DNS monitor is not seeing queries while another tunnel owns
        //    the routes. Stated plainly because it produces a silent blind spot — and named, because
        //    "monitoring is off" is not actionable while "another VPN is holding the slot" is.
        if (!isOurVpnActive()) {
            val otherVpn = findActiveVpnOwner()
            findings.add(
                if (otherVpn != null) {
                    PostureFinding(
                        id = "vpn_blind_spot_other",
                        title = context.getString(R.string.posture_other_vpn_title),
                        detail = context.getString(R.string.posture_other_vpn_detail, otherVpn),
                        severity = Severity.HIGH,
                        remediation = context.getString(R.string.posture_other_vpn_fix, otherVpn),
                    )
                } else {
                    PostureFinding(
                        id = "vpn_blind_spot",
                        title = context.getString(R.string.posture_no_vpn_title),
                        detail = context.getString(R.string.posture_no_vpn_detail),
                        severity = Severity.MEDIUM,
                        remediation = context.getString(R.string.posture_no_vpn_fix),
                    )
                }
            )
        }

        // 7. Notification permission: without it the service still runs but its alerts are silent.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            findings.add(
                PostureFinding(
                    id = "notifications_denied",
                    title = context.getString(R.string.posture_notifications_title),
                    detail = context.getString(R.string.posture_notifications_detail),
                    severity = Severity.LOW,
                    remediation = context.getString(R.string.posture_notifications_fix),
                )
            )
        }

        // 8. Automatic system updates: the exploit chain depends on unpatched browser/kernel bugs.
        if (!isAutomaticUpdatesEnabled()) {
            findings.add(
                PostureFinding(
                    id = "updates_manual",
                    title = context.getString(R.string.posture_updates_title),
                    detail = context.getString(R.string.posture_updates_detail),
                    severity = Severity.MEDIUM,
                    remediation = context.getString(R.string.posture_updates_fix),
                )
            )
        }

        // 9. Battery optimisation. A VPN service that the platform can suspend stops inspecting DNS
        //    while still appearing active in the notification shade — a silent gap in coverage that
        //    no other screen in this app can reveal.
        if (!isIgnoringBatteryOptimisations()) {
            findings.add(
                PostureFinding(
                    id = "battery_optimised",
                    title = context.getString(R.string.posture_battery_title),
                    detail = context.getString(R.string.posture_battery_detail),
                    severity = Severity.MEDIUM,
                    remediation = context.getString(R.string.posture_battery_fix),
                )
            )
        }

        // 10. No other VPN can hold the slot if this app is set as the always-on VPN, which also makes
        //     Android restart the scanner after a reboot instead of waiting for the user to notice.
        if (!isAlwaysOnVpn()) {
            findings.add(
                PostureFinding(
                    id = "not_always_on",
                    title = context.getString(R.string.posture_always_on_title),
                    detail = context.getString(R.string.posture_always_on_detail),
                    severity = Severity.LOW,
                    remediation = context.getString(R.string.posture_always_on_fix),
                )
            )
        }

        return findings
    }

    private fun readEnabledServices(key: String): List<String> =
        Settings.Secure.getString(context.contentResolver, key)
            ?.split(':')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?: emptyList()

    /**
     * Read the Private DNS mode.
     *
     * @return `(mode, specifier)` where mode is `off` / `opportunistic` / `hostname`, or null when
     *         the platform refuses the read (some OEM builds restrict it) — in which case the
     *         caller stays silent rather than guessing.
     */
    private fun privateDnsMode(): Pair<String, String>? = runCatching {
        val mode = Settings.Global.getString(context.contentResolver, "private_dns_mode") ?: return null
        val specifier = Settings.Global.getString(context.contentResolver, "private_dns_specifier") ?: ""
        mode to specifier
    }.getOrNull()

    private fun isOurVpnActive(): Boolean =
        dev.adfection.scanner.net.ScannerState.state.value.active

    /**
     * The label of whichever app is currently the active VPN, or null when it cannot be determined.
     *
     * Read from the platform's own bookkeeping rather than by enumerating VPN services, which would
     * require binding to them. Returns a label, never a package name, because the label is what the
     * user can find in Settings.
     *
     * Null is a normal outcome on ROMs that do not expose these keys, and the caller falls back to a
     * less specific message rather than guessing.
     */
    private fun findActiveVpnOwner(): String? = runCatching {
        val pkg = listOf("always_on_vpn_app", "vpn_app").firstNotNullOfOrNull { key ->
            Settings.Secure.getString(context.contentResolver, key)?.takeIf { it.isNotBlank() }
        } ?: return null

        if (pkg == context.packageName) return null

        runCatching {
            context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(pkg, 0)).toString()
        }.getOrNull() ?: pkg
    }.getOrNull()

    /**
     * Whether this app is exempt from battery optimisation.
     *
     * A granted exemption means Android will not suspend the service to save power. Reads the
     * platform's own list rather than asking for the exemption, because prompting for it is a
     * user-visible system dialog this app deliberately does not trigger from a background check.
     */
    private fun isIgnoringBatteryOptimisations(): Boolean = runCatching {
        val power = context.getSystemService(android.os.PowerManager::class.java) ?: return true
        power.isIgnoringBatteryOptimizations(context.packageName)
    }.getOrDefault(true)

    /** Whether this app is configured as the system's always-on VPN. */
    private fun isAlwaysOnVpn(): Boolean = runCatching {
        Settings.Secure.getString(context.contentResolver, "always_on_vpn_app") == context.packageName
    }.getOrDefault(true)

    private fun isAutomaticUpdatesEnabled(): Boolean =
        runCatching {
            Settings.Global.getInt(context.contentResolver, "ota_disable_automatic_update", 0) == 0
        }.getOrDefault(true)

    private companion object {
        /**
         * Names that a legitimate accessibility tool would rarely use. Kept short and specific to
         * avoid flagging real accessibility apps; matches are surfaced as HIGH but are explicitly
         * labelled as "suggestive", not conclusive.
         */
        val SUSPICIOUS_ACCESSIBILITY_TERMS = listOf(
            "spy", "monitor", "keylog", "tracker", "screenshot", "recorder",
            "remote", "assist service", "input method helper",
        )
    }
}
