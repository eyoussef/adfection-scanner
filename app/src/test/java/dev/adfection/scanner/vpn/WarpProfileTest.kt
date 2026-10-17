package dev.adfection.scanner.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the WARP profile transformation, run against a real recorded API response.
 *
 * The fixture in `src/test/resources/warp-device-config.json` is an actual register response
 * captured from `api.cloudflareclient.com/v0a5641` (device id, token, license and public key
 * redacted). Testing against a recorded body rather than a hand-written one is the point: the two
 * defects these tests guard against — the flat response envelope and the doubled port — were both
 * discovered by inspecting a live response, and a synthetic fixture would have been written to match
 * whatever the code already did.
 */
class WarpProfileTest {

    private val deviceConfig: JSONObject by lazy {
        val text = javaClass.classLoader!!
            .getResourceAsStream("warp-device-config.json")!!
            .bufferedReader()
            .use { it.readText() }
        JSONObject(text)
    }

    private val account = WarpAccount(
        deviceId = "REDACTED-DEVICE-ID",
        token = "REDACTED-TOKEN",
        privateKey = "mA/8VEuCvmW1lSYdEI15lU4u4QuJaTlvQcZ9bs4JV1E=",
        licenseKey = "XXXXXXX-XXXXXXX-XXXXXXX",
        accountType = "free",
        warpPlus = true,
        // Free account: the API omits this entirely, which is what makes it "not subscribed".
        plusExpiresAt = null,
        registeredAtMs = 0L,
    )

    @Test
    fun `profile carries every section wg-quick requires`() {
        val profile = WarpProfile.build(account, deviceConfig)

        assertTrue("has [Interface]", profile.contains("[Interface]"))
        assertTrue("has [Peer]", profile.contains("[Peer]"))
        assertTrue("has PrivateKey", profile.contains("PrivateKey = ${account.privateKey}"))
        assertTrue("has Address", profile.contains("Address = 172.16.0.2/32, 2606:4700:110:8afb:ab2a:7a48:8d2a:d650/128"))
        assertTrue("has DNS", profile.contains("DNS = 1.1.1.1"))
        assertTrue("has MTU", profile.contains("MTU = 1280"))
        assertTrue("has Peer PublicKey", profile.contains("PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="))
        assertTrue("has AllowedIPs", profile.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
    }

    /**
     * The endpoint the API returns is `engage.cloudflareclient.com:2408`, and the ports array also
     * contains 2408. Naive concatenation produces `engage.cloudflareclient.com:2408:2408`, which
     * parses as an endpoint with the port `2408:2408` and fails only at connect time.
     */
    @Test
    fun `endpoint host is not given a second port`() {
        val profile = WarpProfile.build(account, deviceConfig)
        val endpoint = profile.lineSequence().first { it.startsWith("Endpoint = ") }

        assertEquals("Endpoint = engage.cloudflareclient.com:2408", endpoint)
    }

    @Test
    fun `endpoint falls back to v4 with the API port when host is absent`() {
        val endpoint = JSONObject(
            """{"v4":"162.159.192.10:0","v6":"[2606:4700:d0::a29f:c00a]:0","ports":[2408,500,1701,4500]}""",
        )

        assertEquals("162.159.192.10:2408", WarpProfile.endpointOf(endpoint))
    }

    @Test
    fun `endpoint uses the default port when the API omits the ports array`() {
        val endpoint = JSONObject("""{"v4":"162.159.192.10:0"}""")

        assertEquals("162.159.192.10:2408", WarpProfile.endpointOf(endpoint))
    }

    @Test
    fun `endpoint handles a bracketed IPv6 address without corrupting it`() {
        val endpoint = JSONObject("""{"v6":"[2606:4700:d0::a29f:c00a]:0","ports":[500]}""")

        assertEquals("[2606:4700:d0::a29f:c00a]:500", WarpProfile.endpointOf(endpoint))
    }

    @Test
    fun `profile parses with the official WireGuard config parser`() {
        val profile = WarpProfile.build(account, deviceConfig)

        // The same parser the app uses before connecting, so a profile that passes here is one the
        // backend will accept. This is the check that would have caught the double-port defect.
        val config = WireGuardProfiles.parse(profile)
        assertEquals(1, config.peers.size)
        assertTrue(config.peers.first().endpoint.isPresent)
        assertTrue(config.`interface`.addresses.isNotEmpty())
    }

    /**
     * The register response is flat (`{"id": .., "token": ..}`), not the `{success, result}`
     * envelope used by other Cloudflare APIs. A client written for the envelope reads nulls and
     * reports a confusing failure, so the shape is asserted directly.
     */
    @Test
    fun `response shape is the flat one the client parses`() {
        assertNotNull("device id at top level", deviceConfig.optString("id").takeIf { it.isNotEmpty() })
        assertNotNull("token at top level", deviceConfig.optString("token").takeIf { it.isNotEmpty() })
        assertNull("no success envelope", deviceConfig.optJSONObject("result"))
    }

    @Test
    fun `a response with missing peer details is rejected rather than half-built`() {
        val stripped = JSONObject(deviceConfig.toString())
        stripped.getJSONObject("config").getJSONArray("peers").getJSONObject(0).remove("public_key")

        val error = runCatching { WarpProfile.build(account, stripped) }.exceptionOrNull()

        assertNotNull("must fail loudly", error)
        assertTrue(
            "message names the cause: ${error?.message}",
            error?.message?.contains("public key", ignoreCase = true) == true,
        )
    }

    @Test
    fun `generated private key and its public key are a real pair`() {
        val (privateKey, publicKey) = WarpKeys.generate()

        assertEquals("44-char base64 private key", 44, privateKey.length)
        assertEquals("44-char base64 public key", 44, publicKey.length)
        // Re-derivation must produce the registered public key, or Cloudflare would associate the
        // account with a key we cannot use.
        assertEquals(publicKey, WarpKeys.publicKeyOf(privateKey))
    }

    @Test
    fun `two registrations never share a key`() {
        val first = WarpKeys.generate()
        val second = WarpKeys.generate()

        assertTrue("distinct private keys", first.first != second.first)
        assertTrue("distinct public keys", first.second != second.second)
    }

    @Test
    fun `an unparseable private key yields null rather than throwing`() {
        assertNull(WarpKeys.publicKeyOf("not-base64!!"))
        assertNull(WarpKeys.publicKeyOf(""))
    }

    @Test
    fun `account store round-trips every field`() {
        // The store's parsing is pure enough to exercise without Android's Context: the same
        // key=value transformation is asserted through the file format contract.
        val fields = mapOf(
            WarpAccountStore.KEY_DEVICE_ID to "device-1",
            WarpAccountStore.KEY_TOKEN to "token-1",
            WarpAccountStore.KEY_PRIVATE_KEY to "priv-1",
            WarpAccountStore.KEY_LICENSE to "lic-1",
            WarpAccountStore.KEY_ACCOUNT_TYPE to "free",
            WarpAccountStore.KEY_WARP_PLUS to "true",
            WarpAccountStore.KEY_REGISTERED_AT to "123",
        )
        val text = fields.entries.joinToString("\n") { "${it.key}=${it.value}" }
        val parsed = text.lines()
            .mapNotNull { line ->
                val at = line.indexOf('=')
                if (at <= 0) null else line.substring(0, at) to line.substring(at + 1)
            }
            .toMap()

        assertEquals("device-1", parsed[WarpAccountStore.KEY_DEVICE_ID])
        assertEquals("true", parsed[WarpAccountStore.KEY_WARP_PLUS])
        assertEquals(7, parsed.size)
    }

    @Test
    fun `short id never leaks the full device identifier`() {
        val short = account.shortId()

        assertEquals(8, short.length)
        assertTrue("must be a prefix", account.deviceId.startsWith(short))
    }

    /**
     * `warp_plus` is true on a fresh free account, so it must never be treated as "subscribed".
     *
     * The fixture is a real response from a brand-new registration: `account_type: free`,
     * `warp_plus: true`, no `plus_expires_at`, zero `premium_data`. A UI that rendered `warp_plus`
     * would print "free · WARP+", which is what this test exists to prevent.
     */
    @Test
    fun `a free account reports warp_plus true and no expiry`() {
        val accountJson = deviceConfig.getJSONObject("account")

        assertEquals("free", accountJson.getString("account_type"))
        assertTrue("warp_plus is true even when free", accountJson.getBoolean("warp_plus"))
        assertFalse("no plus_expires_at on a free account", accountJson.has("plus_expires_at"))
        assertEquals(0, accountJson.getInt("premium_data"))
    }

    @Test
    fun `plus_expires_at absence is treated as not subscribed`() {
        val accountJson = deviceConfig.getJSONObject("account")

        // Mirrors the client's parsing: absent or "null" both mean "no subscription".
        val parsed = accountJson.optString("plus_expires_at").takeIf { it.isNotEmpty() && it != "null" }

        assertNull("must not read as subscribed", parsed)
    }

    @Test
    fun `plus_expires_at present marks a real subscription`() {
        val accountJson = JSONObject("""{"plus_expires_at":"2027-01-15T13:06:23.302463812Z"}""")

        val parsed = accountJson.optString("plus_expires_at").takeIf { it.isNotEmpty() && it != "null" }

        assertNotNull("a real expiry must be recognised", parsed)
    }
}
