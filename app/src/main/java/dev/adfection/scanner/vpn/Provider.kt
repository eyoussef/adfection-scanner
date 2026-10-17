package dev.adfection.scanner.vpn

import android.content.Context
import androidx.annotation.StringRes
import dev.adfection.scanner.R
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
 *
 * ## Why the text is resource ids
 * Every field below is displayed to the user, so each is a string resource rather than a literal.
 * Holding literals here previously meant this entire screen stayed in English on every locale —
 * the guidance is the most context-sensitive text in the app, and the least excusable to leave
 * untranslated. Callers resolve through [costText] and friends, which take a `Context`.
 */
data class Provider(
    /** Product name. Proper nouns are not translated. */
    val name: String,
    @StringRes val costRes: Int,
    @StringRes val howToGetConfigRes: Int,
    @StringRes val operatorSeesRes: Int,
    /** Whether the client/code is open for audit. Null when there is no client to audit. */
    val openSource: Boolean?,
    val severity: Severity,
    @StringRes val verdictRes: Int,
    val url: String,
) {
    /** Resolved text accessors. Keeping resolution here stops call sites drifting apart. */
    fun costText(context: Context): String = context.getString(costRes)
    fun howToGetConfigText(context: Context): String = context.getString(howToGetConfigRes)
    fun operatorSeesText(context: Context): String = context.getString(operatorSeesRes)
    fun verdictText(context: Context): String = context.getString(verdictRes)

    companion object {

        /**
         * Ordered best-first for a high-risk user: control, then free-but-open, then paid,
         * then free-with-tradeoffs.
         */
        fun all(): List<Provider> = listOf(
            Provider(
                name = "Self-hosted WireGuard",
                costRes = R.string.provider_selfhosted_cost,
                howToGetConfigRes = R.string.provider_selfhosted_how,
                operatorSeesRes = R.string.provider_selfhosted_sees,
                openSource = true,
                severity = Severity.LOW,
                verdictRes = R.string.provider_selfhosted_verdict,
                url = "https://github.com/wg-easy/wg-easy",
            ),
            Provider(
                name = "Cloudflare WARP",
                costRes = R.string.provider_warp_cost,
                howToGetConfigRes = R.string.provider_warp_how,
                operatorSeesRes = R.string.provider_warp_sees,
                openSource = true,
                severity = Severity.MEDIUM,
                verdictRes = R.string.provider_warp_verdict,
                url = "https://github.com/ViRb3/wgcf",
            ),
            Provider(
                name = "Proton VPN",
                costRes = R.string.provider_proton_cost,
                howToGetConfigRes = R.string.provider_proton_how,
                operatorSeesRes = R.string.provider_proton_sees,
                openSource = true,
                severity = Severity.LOW,
                verdictRes = R.string.provider_proton_verdict,
                url = "https://protonvpn.com/support/wireguard-configurations",
            ),
            Provider(
                name = "Mullvad",
                costRes = R.string.provider_mullvad_cost,
                howToGetConfigRes = R.string.provider_mullvad_how,
                operatorSeesRes = R.string.provider_mullvad_sees,
                openSource = true,
                severity = Severity.LOW,
                verdictRes = R.string.provider_mullvad_verdict,
                url = "https://mullvad.net/en/help/wireguard",
            ),
            Provider(
                name = "IVPN",
                costRes = R.string.provider_ivpn_cost,
                howToGetConfigRes = R.string.provider_ivpn_how,
                operatorSeesRes = R.string.provider_ivpn_sees,
                openSource = true,
                severity = Severity.LOW,
                verdictRes = R.string.provider_ivpn_verdict,
                url = "https://www.ivpn.net/setup/",
            ),
            Provider(
                name = "Riseup VPN",
                costRes = R.string.provider_riseup_cost,
                howToGetConfigRes = R.string.provider_riseup_how,
                operatorSeesRes = R.string.provider_riseup_sees,
                openSource = true,
                severity = Severity.MEDIUM,
                verdictRes = R.string.provider_riseup_verdict,
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
        fun freeVpnAppWarning(context: Context): String = context.getString(R.string.provider_warning_body)
    }
}
