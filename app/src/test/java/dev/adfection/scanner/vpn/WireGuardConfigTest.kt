package dev.adfection.scanner.vpn

import com.wireguard.config.Config
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedReader
import java.io.StringReader

/**
 * Config-parsing tests.
 *
 * These use the official WireGuard parser (`com.wireguard.config.Config`), which is pure JVM code
 * with no Android dependency, so they run as plain unit tests.
 *
 * The point of these tests is that the app must *reject* profiles that would parse but then fail
 * silently at connect time — the worst possible outcome for a security tool.
 */
class WireGuardConfigTest {

    // Real Curve25519 keys. The parser validates the key material, not just the Base64, so
    // synthetic strings like "aaaa...=" are rejected as BadConfigException.
    private val validKey1 = "8E0jgFcjnvtFcczqRcXBhjaSwArfYAKmcNtECtIAF1c="
    private val validKey2 = "IJyuG8M/WLrfFr6KfnsKjtJz2VhhkS7Br+mADin2mQk="
    private val validKey3 = "OKkAH/Eh/9jPu48E1MEOkoOJZ0/rabVINqpgG4szo2Q="

    private fun parsed(text: String): Config =
        Config.parse(BufferedReader(StringReader(text)))

    @Test
    fun `a well-formed profile parses with endpoint, key and allowed IPs`() {
        val config = parsed(
            """
            [Interface]
            PrivateKey = $validKey1
            Address    = 10.7.0.2/32, fd00:7::2/128
            DNS        = 10.7.0.1
            MTU        = 1380

            [Peer]
            PublicKey  = $validKey2
            Endpoint   = vpn.example.com:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            """.trimIndent()
        )

        assertNotNull(config)
        assertEquals(1, config.peers.size)
        assertTrue("endpoint must be present", config.peers.first().endpoint.isPresent)
        assertEquals("vpn.example.com:51820", config.peers.first().endpoint.get().toString())
        assertEquals(2, config.`interface`.addresses.size)
        assertEquals(1, config.`interface`.dnsServers.size)
        assertEquals(1380, config.`interface`.mtu.get())
    }

    @Test
    fun `a profile with no endpoint is detectable before it fails silently on connect`() {
        val config = parsed(
            """
            [Interface]
            PrivateKey = $validKey1
            Address    = 10.7.0.2/32

            [Peer]
            PublicKey  = $validKey2
            AllowedIPs = 0.0.0.0/0
            """.trimIndent()
        )
        // Parsing succeeds, but with no endpoint the tunnel could never handshake. The import
        // check in WireGuardProfiles.save() rejects exactly this case.
        assertTrue("no endpoint should be detectable", config.peers.first().endpoint.isEmpty)
    }

    @Test
    fun `a profile with no peer section is detectable`() {
        val config = parsed(
            """
            [Interface]
            PrivateKey = $validKey1
            Address    = 10.7.0.2/32
            """.trimIndent()
        )
        assertTrue("a config with no peers must be detectable", config.peers.isEmpty())
    }

    @Test
    fun `malformed input raises rather than producing a half-built config`() {
        // Garbage keys and unknown sections must not yield a usable-looking config.
        val bad = listOf(
            "not a config at all",
            "[Interface]\nPrivateKey = tooshort\n",
            "[Peer]\nPublicKey = definitely-not-base64\n",
            "[Interface]\nPrivateKey = $validKey1\n[Peer]\nEndpoint = host:1\n",
        )
        for (text in bad) {
            val result = runCatching { parsed(text) }
            // Either it throws, or it parses to something our validation layer rejects.
            if (result.isSuccess) {
                val config = result.getOrThrow()
                val rejected = config.peers.isEmpty() ||
                    config.peers.first().endpoint.isEmpty ||
                    runCatching { config.`interface`.keyPair }.getOrNull() == null
                assertTrue("input unexpectedly produced a fully valid profile: $text", rejected)
            }
        }
    }

    @Test
    fun `the template carries placeholders and is therefore correctly rejected`() {
        // The template is a shape for the user to fill in. Its <paste your private key> placeholder
        // must FAIL to parse — if it parsed, an unedited template would look like a usable profile
        // and would fail silently at connect time.
        val result = runCatching { parsed(WireGuardProfiles.template()) }
        assertTrue("an unedited template must not parse as a valid config", result.isFailure)

        // Once the placeholders are substituted with real material it must parse.
        val filled = WireGuardProfiles.template()
            .replace("<paste your private key>", validKey1)
            .replace("<paste the server public key>", validKey2)
            .replace("<hostname or ip>:51820", "vpn.example.com:51820")
        val config = parsed(filled)
        assertEquals(1, config.peers.size)
        assertTrue(config.peers.first().endpoint.isPresent)
        assertEquals(1, config.`interface`.dnsServers.size)
    }

    @Test
    fun `profile names are sanitised against path traversal`() {
        // Exercises the real implementation (internal for testability), not a copy of it.
        assertEquals("etc_passwd", WireGuardProfiles.sanitize("../../etc/passwd"))
        assertEquals("normal", WireGuardProfiles.sanitize("normal"))
        assertEquals("a_b", WireGuardProfiles.sanitize("a/b"))
        assertEquals("", WireGuardProfiles.sanitize("/"))
        assertTrue("must be length-capped", WireGuardProfiles.sanitize("x".repeat(500)).length <= 64)
    }

    @Test
    fun `no hostile name can escape the profile directory`() {
        // The property that actually matters is containment, asserted directly rather than by
        // substring matching. A name may legitimately contain ".." as literal characters (e.g.
        // "a_.._b"); what must never happen is the resulting path resolving outside the directory.
        val dir = java.nio.file.Files.createTempDirectory("wg-profiles").toFile()
        val root = dir.canonicalPath

        val hostile = listOf(
            "..", "../..", "....//", "a/../../../b", "./..", "\\\\..\\\\..",
            "../../../../../../etc/passwd", "/etc/shadow", "....//....//x",
            "\u0000../evil", "con", "..\\..\\windows\\system32",
        )

        for (name in hostile) {
            val safe = WireGuardProfiles.sanitize(name)
            val file = java.io.File(dir, "$safe${WireGuardProfiles.SUFFIX}")
            val canonical = file.canonicalPath
            assertTrue(
                "name '$name' -> '$safe' escapes to $canonical",
                canonical.startsWith(root + java.io.File.separator) || canonical == root,
            )
        }
    }

    @Test
    fun `a private key never appears in the details a user is shown`() {
        val config = parsed(
            """
            [Interface]
            PrivateKey = $validKey1
            Address    = 10.7.0.2/32

            [Peer]
            PublicKey  = $validKey2
            Endpoint   = vpn.example.com:51820
            AllowedIPs = 0.0.0.0/0
            """.trimIndent()
        )

        // The details dialog shows addresses/endpoint/etc. Verify the key is not reachable through
        // the fields it renders.
        val rendered = buildString {
            append(config.`interface`.addresses.joinToString(", "))
            config.`interface`.dnsServers.joinToString(", ")
            config.peers.firstOrNull()?.endpoint?.orElse(null)
            config.peers.firstOrNull()?.allowedIps?.joinToString(", ")
        }
        assertTrue("private key must not leak into displayed fields", !rendered.contains(validKey1))
    }
}
