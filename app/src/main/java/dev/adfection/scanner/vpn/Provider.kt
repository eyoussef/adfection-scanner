package dev.adfection.scanner.vpn

import dev.adfection.scanner.data.Severity

/**
 * Guidance on obtaining a WireGuard profile.
 *
 * ## Why this is curated rather than a bare link list
 * This app exists to protect people targeted by mercenary spyware. Pointing such a user at an
 * arbitrary "free VPN" would be actively harmful: the majority of free VPN *apps* monetise by
 * harvesting data, and studies of the top free VPN Android apps found that one in five were
 * flagged as malware and a quarter leaked traffic or user data (CSIRO/ICSI/UC Berkeley/UNSW, 2017;
 * Zimperium 2024; CNET 2024 found >60% raise privacy concerns). In this threat model a
 * data-harvesting VPN is a downgrade: it converts a spyware problem into a different spyware
 * problem with the user's consent.
 *
 * So each entry states what the operator can see, and only services that publish WireGuard
 * configuration files — the format this app can actually import — are listed as usable.
 */
data class Provider(
    val name: String,
    /** Plain statement of what it costs, including "free" where that is true. */
    val cost: String,
    /** Concrete steps, not marketing copy. */
    val howToGetConfig: String,
    /** The trust question: what does the party operating this see about you? */
    val operatorSees: String,
    /** Whether the client/code is open for audit. Null when there is no client to audit. */
    val openSource: Boolean?,
    val severity: Severity,
    /** One-line honest verdict. */
    val verdict: String,
    val url: String,
) {
    companion object {

        /**
         * Ordered best-first for a high-risk user: control, then free-but-open, then paid,
         * then free-with-tradeoffs.
         */
        fun all(): List<Provider> = listOf(
            Provider(
                name = "Self-hosted WireGuard",
                cost = "Free on Oracle Cloud Always Free tier; otherwise ~$4/month for any small VPS.",
                howToGetConfig = "Install wg-easy (Docker) or Defguard on a small server, or run wg-quick " +
                    "directly. The panel generates the .conf for each device.",
                operatorSees = "You. Nobody else. No third party is in the path.",
                openSource = true,
                severity = Severity.LOW,
                verdict = "The only option with no third party to trust. Best choice if you can spend " +
                    "an hour setting it up — and the right one for journalists, lawyers and activists.",
                url = "https://github.com/wg-easy/wg-easy",
            ),
            Provider(
                name = "Cloudflare WARP (built in)",
                cost = "Genuinely free, no paid tier, no account purchase.",
                howToGetConfig = "Use 'Register WARP account' on the VPN screen. The app performs the " +
                    "same registration wgcf does, then stores the profile in its own private storage — " +
                    "there is no file to copy and no terminal involved.",
                operatorSees = "Cloudflare terminates your traffic and sees your source IP and " +
                    "destinations. WARP is not a normal VPN: it is Cloudflare's network, and their " +
                    "privacy policy governs it. It also does not hide your IP from Cloudflare.",
                openSource = true,
                severity = Severity.MEDIUM,
                verdict = "The best genuinely-free option, because the generator is open source and " +
                    "auditable. Do not treat it as anonymity against Cloudflare itself. One caveat " +
                    "specific to this option: Cloudflare refuses WireGuard handshakes in some regions " +
                    "as abuse prevention, and new accounts are being issued the MASQUE transport, " +
                    "which WireGuard cannot speak — use the status check to see which you get.",
                url = "https://github.com/ViRb3/wgcf",
            ),
            Provider(
                name = "Proton VPN (free tier)",
                cost = "Free tier is permanent, no data cap. Paid tiers add servers and features.",
                howToGetConfig = "Create a free account, then account.protonvpn.com \u2192 Downloads \u2192 " +
                    "WireGuard configuration \u2192 Create. The free plan can generate configs (fewer options).",
                operatorSees = "Proton. They publish audits, are based in Switzerland, and their " +
                    "clients are open source, but they still terminate the tunnel.",
                openSource = true,
                severity = Severity.LOW,
                verdict = "A credible free option with real audits behind it — the honest choice when " +
                    "self-hosting is not possible and Cloudflare is not acceptable.",
                url = "https://protonvpn.com/support/wireguard-configurations",
            ),
            Provider(
                name = "Mullvad",
                cost = "\u20ac5/month flat, no free tier.",
                howToGetConfig = "Create an account number (no email required), then generate WireGuard " +
                    "configs from the account page.",
                operatorSees = "Mullvad, who by design cannot tie an account to a person. Payment and " +
                    "account are decoupled.",
                openSource = true,
                severity = Severity.LOW,
                verdict = "Best-in-class for metadata minimisation. If you can pay \u20ac5, this is the " +
                    "strongest off-the-shelf choice.",
                url = "https://mullvad.net/en/help/wireguard",
            ),
            Provider(
                name = "IVPN",
                cost = "Paid, roughly $6/month.",
                howToGetConfig = "Create an account, then generate WireGuard configs in the client area.",
                operatorSees = "IVPN. Audited, no-logs posture, accepts anonymous payment.",
                openSource = true,
                severity = Severity.LOW,
                verdict = "Comparable to Mullvad; a reasonable alternative if you prefer their " +
                    "jurisdiction or pricing.",
                url = "https://www.ivpn.net/setup/",
            ),
            Provider(
                name = "Riseup VPN",
                cost = "Free, donation-funded, run for activists.",
                howToGetConfig = "Not importable here: Riseup ships its own Bitmask client rather than " +
                    "WireGuard .conf files. Install their app instead — but note it will take the VPN " +
                    "slot from this scanner.",
                operatorSees = "Riseup, a long-standing activist collective with a strong record.",
                openSource = true,
                severity = Severity.MEDIUM,
                verdict = "Excellent trustworthiness for activists, but it is a separate app, so it " +
                    "cannot coexist with this scanner either.",
                url = "https://riseup.net/en/vpn",
            ),
        )

        /**
         * The category this app deliberately does NOT point at, with the evidence for why.
         *
         * This is the most important text on the screen: a user who goes and installs a random
         * "Free VPN" from an app store is worse off than one who installs nothing at all, and they
         * will have done it because this app sent them looking.
         */
        fun freeVpnAppWarning(): String = """
            Avoid free VPN apps from app stores.

            Measured findings, not opinion:
            \u2022 Of the top 150 free VPN Android apps, 1 in 5 were flagged as potential malware and
              a quarter had privacy-breaking defects such as DNS leaks (CSIRO / ICSI / UC Berkeley /
              UNSW, 2017).
            \u2022 CNET's 2024 research found more than 60% of free VPN apps raised privacy concerns.
            \u2022 Repeated disclosures have found free VPN apps logging and selling user traffic,
              and shipping trackers and malware.

            Free VPN apps are usually paid for with your data. For someone being targeted for
            surveillance, that trades one observer for another \u2014 and this time you consented.

            If you cannot self-host and cannot pay, prefer the entries above, which publish real
            WireGuard configurations you can inspect as text and import here.
        """.trimIndent()
    }
}
