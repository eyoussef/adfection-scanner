package dev.adfection.scanner.vpn

import dev.adfection.scanner.data.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards on the provider guidance.
 *
 * This screen is the one place where the app can actively cause harm: by sending a surveillance
 * target to a service that harvests data. These tests assert the properties that make the guidance
 * trustworthy rather than merely present.
 */
class ProviderGuidanceTest {

    private val providers = Provider.all()

    @Test
    fun `the free-VPN-app warning is substantive and cites evidence`() {
        val warning = Provider.freeVpnAppWarning()

        // A warning that does not name a risk is decoration.
        assertTrue("must name data harvesting", warning.contains("data", ignoreCase = true))
        assertTrue("must warn about malware", warning.contains("malware", ignoreCase = true))

        // It must cite at least one concrete study rather than assert a vibe.
        assertTrue(
            "must cite measured research",
            warning.contains("CNET") || warning.contains("CSIRO") || warning.contains("2024"),
        )
        assertTrue("warning is too short to be useful", warning.length > 400)
    }

    @Test
    fun `every provider states what the operator can see`() {
        for (provider in providers) {
            assertTrue(
                "'${provider.name}' must explain operator visibility",
                provider.operatorSees.length > 40,
            )
            assertTrue(
                "'${provider.name}' must state a cost, including free",
                provider.cost.isNotBlank(),
            )
            assertTrue(
                "'${provider.name}' must give concrete steps",
                provider.howToGetConfig.length > 40,
            )
            assertTrue("'${provider.name}' must have a link", provider.url.startsWith("https://"))
        }
    }

    @Test
    fun `no generic free-VPN app is presented as a recommendation`() {
        // The failure mode this guards against: someone appends "FreeVPN: fastvpn.com" to the list
        // and the app starts recommending exactly the category it warns about.
        for (provider in providers) {
            val haystack = (provider.name + provider.verdict + provider.howToGetConfig).lowercase()
            val banned = listOf("betternet", "hola", "turbo vpn", "hotspot shield", "supervpn", "freevpn")
            for (term in banned) {
                assertFalse("'${provider.name}' mentions banned free-VPN app '$term'", haystack.contains(term))
            }
        }
    }

    @Test
    fun `self-hosting is offered first, because it has no third party to trust`() {
        assertEquals("Self-hosted WireGuard", providers.first().name)
        assertEquals(Severity.LOW, providers.first().severity)
        assertTrue(
            "the self-hosted entry must make its key advantage explicit",
            providers.first().verdict.contains("no third party", ignoreCase = true),
        )
    }

    @Test
    fun `there is at least one genuinely free option that is not an app-store VPN`() {
        val free = providers.filter { it.cost.contains("free", ignoreCase = true) }
        assertTrue("at least one free option must exist", free.isNotEmpty())

        // And it must be a config-generating service, not an app to install.
        assertTrue(
            "a free option must be config-based",
            free.any { it.url.contains("wgcf") || it.url.contains("proton") || it.url.contains("wg-easy") },
        )
    }

    @Test
    fun `services that cannot be imported are marked as such instead of looking importable`() {
        // Riseup ships its own client, not .conf files. Leading a user to try importing and fail
        // would waste their time in a situation where that has a cost.
        val riseup = providers.first { it.name.contains("Riseup") }
        assertTrue(
            "non-importable services must say so",
            riseup.howToGetConfig.contains("Not importable", ignoreCase = true),
        )
    }

    @Test
    fun `proton free tier claim matches provider documentation`() {
        // Verified against https://protonvpn.com/support/wireguard-configurations : configs can be
        // generated from the account page on a Free plan (with fewer VPN options).
        val proton = providers.first { it.name.contains("Proton") }
        assertTrue(proton.cost.contains("free", ignoreCase = true))
        assertTrue(proton.howToGetConfig.contains("WireGuard configuration", ignoreCase = true))
    }
}
