package dev.adfection.scanner.scan

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
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
                        title = "Private DNS is bypassing this scanner",
                        detail = "Private DNS mode is '$mode' ($target). Android sends DNS over TLS " +
                            "straight to that resolver, so queries never reach the scanner's DNS " +
                            "interface. Monitoring will look 'broken' while this is on.",
                        severity = Severity.CRITICAL,
                        remediation = "Settings \u2192 Network & internet \u2192 Private DNS \u2192 set to " +
                            "'Off' while using this scanner. Then restart protection.",
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
                    title = "Advertising ID is active",
                    detail = "This is the identifier Discover-Tech used to select individual devices for " +
                        "infection. With it enabled, your device can be singled out in ad auctions.",
                    severity = Severity.HIGH,
                    remediation = "Settings \u2192 Privacy \u2192 Ads \u2192 Delete advertising ID (or opt out of ads personalization).",
                )
            )
        } else if (adIdLimit < 0) {
            findings.add(
                PostureFinding(
                    id = "ad_id_unknown",
                    title = "Advertising ID state could not be read",
                    detail = "The OS did not expose 'limit_ad_tracking'. Some OEM builds rename this key; " +
                        "verify ad personalization manually.",
                    severity = Severity.LOW,
                    remediation = "Settings \u2192 Privacy \u2192 Ads.",
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
                    title = "Accessibility service with suggestive name enabled",
                    detail = "Enabled services include ${suspiciousAccessibility.joinToString(", ")}. " +
                        "Accessibility services can read everything on screen and tap on your behalf.",
                    severity = Severity.HIGH,
                    remediation = "Settings \u2192 Accessibility \u2192 review every enabled service and disable anything you did not deliberately install.",
                )
            )
        }

        // 3. Overlay permission: used to draw fake UI over real apps (credential/session capture).
        if (Settings.canDrawOverlays(context) == true) {
            findings.add(
                PostureFinding(
                    id = "overlay_permission",
                    title = "This app (or another) can draw over other apps",
                    detail = "Overlay permission is a common component of credential-stealing implants.",
                    severity = Severity.MEDIUM,
                    remediation = "Settings \u2192 Apps \u2192 Special access \u2192 Display over other apps.",
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
                    title = "Developer options / USB debugging enabled",
                    detail = "USB debugging permits app installation and data extraction by anyone with " +
                        "physical access and an authorised host key.",
                    severity = Severity.MEDIUM,
                    remediation = "Disable USB debugging unless you are actively developing.",
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
                        title = "Install from unknown sources is allowed",
                        detail = "Sideloaded APKs bypass store review and are how most implants arrive.",
                        severity = Severity.MEDIUM,
                        remediation = "Settings \u2192 Security \u2192 disable unknown sources.",
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
                        title = "Another VPN is holding the single VPN slot",
                        detail = "'$otherVpn' is the active VPN. Android permits one active VPN per " +
                            "user, so this scanner cannot see any DNS traffic while it is running. " +
                            "Queries to known spyware infrastructure are going unobserved.",
                        severity = Severity.HIGH,
                        remediation = "Either stop '$otherVpn' and start this scanner, or switch to " +
                            "the tunnel screen and accept that DNS matching is paused. The two modes " +
                            "are mutually exclusive on Android.",
                    )
                } else {
                    PostureFinding(
                        id = "vpn_blind_spot",
                        title = "DNS monitoring is not active",
                        detail = "No AdFection scanner VPN is running. Without it, queries to known " +
                            "spyware infrastructure go unobserved.",
                        severity = Severity.MEDIUM,
                        remediation = "Start the scanner from the main screen.",
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
                    title = "Notifications are blocked",
                    detail = "Blocked DNS events will not be surfaced as notifications.",
                    severity = Severity.LOW,
                    remediation = "Grant notification permission to this app.",
                )
            )
        }

        // 8. Automatic system updates: the exploit chain depends on unpatched browser/kernel bugs.
        if (!isAutomaticUpdatesEnabled()) {
            findings.add(
                PostureFinding(
                    id = "updates_manual",
                    title = "Automatic system updates appear disabled",
                    detail = "Chain step 2 requires an unpatched vulnerability to escape the browser sandbox.",
                    severity = Severity.MEDIUM,
                    remediation = "Settings \u2192 System \u2192 System update \u2192 enable automatic updates.",
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
                    title = "Battery optimisation may suspend monitoring",
                    detail = "Android can suspend a background VPN service to save power. While it is " +
                        "suspended the scanner sees no DNS traffic, yet the notification still says " +
                        "protection is active.",
                    severity = Severity.MEDIUM,
                    remediation = "Settings \u2192 Apps \u2192 AdFection Scanner \u2192 Battery \u2192 " +
                        "Unrestricted. Then restart protection.",
                )
            )
        }

        // 10. No other VPN can hold the slot if this app is set as the always-on VPN, which also makes
        //     Android restart the scanner after a reboot instead of waiting for the user to notice.
        if (!isAlwaysOnVpn()) {
            findings.add(
                PostureFinding(
                    id = "not_always_on",
                    title = "Protection does not survive a reboot",
                    detail = "This app is not the always-on VPN, so monitoring stops at restart and " +
                        "stays off until it is started by hand.",
                    severity = Severity.LOW,
                    remediation = "Settings \u2192 Network & internet \u2192 VPN \u2192 AdFection Scanner " +
                        "\u2192 enable 'Always-on VPN'. Note this also prevents any other VPN (including " +
                        "the WireGuard tunnel screen) from taking the slot.",
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
