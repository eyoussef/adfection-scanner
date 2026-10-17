package dev.adfection.scanner.vpn

import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * The two Cloudflare WARP API calls that wgcf performs, reimplemented for Android.
 *
 * ## Why this is a reimplementation and not a port
 * wgcf is a Go CLI with a large dependency tree (uTLS, cobra, viper, the generated OpenAPI client).
 * None of that can be linked into an APK. What matters is behaviour, and behaviour here is small:
 * two HTTP requests, one keypair, and one text template — all of which are reproduced below and
 * pinned by unit tests against recorded fixtures.
 *
 * ## The parts that are not obvious
 * Three details decide whether this works, and each was verified against the live API rather than
 * assumed:
 *
 * 1. **A valid Curve25519 public key is mandatory.** The API answers `1001 Invalid public key` for
 *    a placeholder, so a dummy key cannot be used to test connectivity.
 * 2. **The register response is a flat object, not a `{success, result}` envelope.** Parsing it as
 *    the latter silently yields nulls — which is exactly how a "quietly broken" client looks.
 * 3. **`endpoint.host` already contains the port.** It arrives as `engage.cloudflareclient.com:2408`,
 *    so appending `ports[0]` produces `host:2408:2408`. wgcf strips it with `net.SplitHostPort`; the
 *    same normalisation is done in [WarpProfile].
 *
 * The `1.1.1.1/...` user agent and `CF-Client-Version` header match the Android client, as in wgcf.
 * Requests go through plain `HttpURLConnection` on the platform TLS stack; the API was confirmed to
 * accept a standard Android/OkHttp handshake, so uTLS fingerprinting is deliberately not reproduced.
 */
class WarpClient {

    /** Outcome of a registration: the stored account plus the profile it produced. */
    data class Registration(val account: WarpAccount, val profile: String)

    /**
     * Register a new device and derive its profile.
     *
     * @param deviceModel value shown for this device in the 1.1.1.1 app; defaults to the app name.
     * @return [Registration], or a failure carrying a message safe to show a user.
     */
    fun register(deviceModel: String = "AdFectionScanner"): Result<Registration> = runCatching {
        val (privateKey, publicKey) = WarpKeys.generate()

        val body = JSONObject().apply {
            put("key", publicKey)
            put("install_id", "")
            put("fcm_token", "")
            put("tos", timestamp())
            put("model", deviceModel)
            put("serial_number", "")
            put("locale", "en_US")
            put("os_version", "16.0.0")
            put("key_type", "curve25519")
            put("tunnel_type", "wireguard")
        }

        val registered = request(METHOD_POST, "$API/$API_VERSION/reg", body.toString())
            ?: error("Cloudflare returned no response. Check your connection and try again.")

        val deviceId = registered.optString("id").takeIf { it.isNotEmpty() }
            ?: error(describe(registered, "Cloudflare did not return a device id"))
        val token = registered.optString("token").takeIf { it.isNotEmpty() }
            ?: error(describe(registered, "Cloudflare did not return an access token"))

        // wgcf's `update` step: the device is not usable until WARP is enabled on it. Registration
        // leaves warp_enabled=false (verified live), and the config is fetched afterwards so the
        // returned peer is post-update rather than the pre-update snapshot.
        enableWarp(deviceId, token)

        val config = fetchDeviceConfig(deviceId, token)
            ?: error(describe(registered, "Cloudflare did not return the device configuration"))

        val accountJson = config.optJSONObject("account") ?: registered.optJSONObject("account")
        val account = WarpAccount(
            deviceId = deviceId,
            token = token,
            privateKey = privateKey,
            licenseKey = accountJson?.optString("license")?.takeIf { it.isNotEmpty() },
            accountType = accountJson?.optString("account_type")?.takeIf { it.isNotEmpty() },
            // Kept because it is what the API sent, not because it means "subscribed": a fresh free
            // account also reports warp_plus=true (verified live). UI reads plusExpiresAt instead.
            warpPlus = accountJson?.optBoolean("warp_plus") ?: false,
            plusExpiresAt = accountJson?.optString("plus_expires_at")
                ?.takeIf { it.isNotEmpty() && it != "null" },
            registeredAtMs = System.currentTimeMillis(),
        )

        Registration(account, WarpProfile.build(account, config))
    }

    /**
     * Ask Cloudflare to enable WARP on the device.
     *
     * Failure here is not fatal: the tunnel may still establish, and refusing to hand the user a
     * profile because an optional PATCH was rejected would make the app look broken for no gain.
     * The flag is reported through [probeWarp] instead.
     */
    private fun enableWarp(deviceId: String, token: String) {
        val body = JSONObject().put("warp_enabled", true).toString()
        runCatching { request(METHOD_PATCH, "$API/$API_VERSION/reg/$deviceId", body, token) }
    }

    /** Re-fetch this device's configuration. Used by [regenerateProfile] and by tests. */
    fun fetchDeviceConfig(deviceId: String, token: String): JSONObject? =
        request(METHOD_GET, "$API/$API_VERSION/reg/$deviceId", body = null, token = token)

    /**
     * Rebuild a profile for an account that is already stored.
     *
     * This is the "regenerate" path: Cloudflare may hand out a different endpoint or address, so a
     * user whose tunnel stopped working can refresh without registering a second account and
     * burning a device slot on the account.
     */
    fun regenerateProfile(account: WarpAccount): Result<String> = runCatching {
        val config = fetchDeviceConfig(account.deviceId, account.token)
            ?: error("Cloudflare did not return the device configuration for this account.")
        WarpProfile.build(account, config)
    }

    /**
     * Read back what Cloudflare says about this connection, via `https://www.cloudflare.com/cdn-cgi/trace`.
     *
     * The value of `warp` is the honest answer to "is WARP actually carrying my traffic", which
     * matters here because a WARP-over-WireGuard tunnel can be silently refused for the user's
     * region while every local indicator still says "up".
     */
    fun probeWarp(): Result<WarpProbe> = runCatching {
        val text = rawGet(TRACE_URL) ?: error("Could not reach the WARP trace endpoint.")
        val fields = text.lineSequence()
            .mapNotNull { line ->
                val at = line.indexOf('=')
                if (at <= 0) null else line.substring(0, at) to line.substring(at + 1)
            }
            .toMap()
        WarpProbe(
            warp = fields["warp"] ?: "unknown",
            gateway = fields["gateway"],
            colo = fields["colo"],
            ip = fields["ip"],
        )
    }

    private fun request(method: String, url: String, body: String?, token: String? = null): JSONObject? {
        val text = exchange(method, url, body, token) ?: return null
        return runCatching { JSONObject(text) }.getOrElse {
            error("Cloudflare returned a response this app could not parse (${it.message}).")
        }
    }

    private fun rawGet(url: String): String? = exchange(METHOD_GET, url, body = null, token = null)

    private fun exchange(method: String, url: String, body: String?, token: String?): String? {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = true
            // Match the official Android client, as wgcf does. Not a disguise: the API is the same
            // one the official app calls, and it was confirmed to answer this header set.
            setRequestProperty("User-Agent", USER_AGENT)
            setRequestProperty("CF-Client-Version", CLIENT_VERSION)
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Connection", "Keep-Alive")
            token?.let { setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            }
        }

        return try {
            if (body != null) {
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader()?.use(BufferedReader::readText).orEmpty()

            if (code !in 200..299) {
                val message = runCatching { JSONObject(text) }.getOrNull()
                    ?.let { describe(it, "") }
                    ?: text.take(200)
                // 429 is the one error users actually hit on a shared network, so name it.
                if (code == 429) {
                    error("Cloudflare is rate-limiting this network. Wait a minute and try again.")
                }
                error("Cloudflare rejected the request (HTTP $code)${if (message.isBlank()) "" else ": $message"}")
            }
            text.ifBlank { null }
        } catch (t: java.io.IOException) {
            error("Could not reach Cloudflare: ${t.message ?: t::class.java.simpleName}")
        } finally {
            connection.disconnect()
        }
    }

    /** Pull Cloudflare's own error text out of a response, so failures are not opaque. */
    private fun describe(json: JSONObject, fallback: String): String {
        val errors = json.optJSONArray("errors")
        if (errors != null && errors.length() > 0) {
            val first = errors.optJSONObject(0)
            val message = first?.optString("message").orEmpty()
            val code = first?.optInt("code", 0) ?: 0
            if (message.isNotEmpty()) return "$message (code $code)"
        }
        return fallback
    }

    private fun timestamp(): String = SimpleDateFormat(TIMESTAMP_PATTERN, Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }
        .format(Date())

    companion object {
        const val API = "https://api.cloudflareclient.com"
        const val API_VERSION = "v0a5641"
        const val TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
        const val USER_AGENT = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
        const val CLIENT_VERSION = "a-6.38.9-5641"

        private const val METHOD_GET = "GET"
        private const val METHOD_POST = "POST"
        private const val METHOD_PATCH = "PATCH"
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 15_000
        private const val TIMESTAMP_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    }
}

/**
 * What `cdn-cgi/trace` reports about this connection.
 *
 * [warp] is one of `on`, `off`, `plus`, or `unknown` when the endpoint could not be read. This is
 * deliberately reported alongside the tunnel state: "the tunnel is up" and "WARP is carrying my
 * traffic" are different claims, and only the second one is useful to the user.
 */
data class WarpProbe(
    val warp: String,
    val gateway: String?,
    val colo: String?,
    val ip: String?,
) {
    val isActive: Boolean get() = warp == "on" || warp == "plus"

    fun describe(): String = buildString {
        append("WARP: ").append(warp)
        colo?.let { append(" \u00b7 edge ").append(it) }
        gateway?.let { append(" \u00b7 gateway ").append(it) }
    }
}

/**
 * Turns a Cloudflare device configuration into a wg-quick profile text.
 *
 * Kept separate from the network code so the transformation — the part with the port trap in it —
 * is unit-testable against a recorded fixture without a network.
 */
internal object WarpProfile {

    fun build(account: WarpAccount, deviceConfig: JSONObject): String {
        val config = deviceConfig.optJSONObject("config")
            ?: error("The device configuration contained no WireGuard settings.")

        val peer = config.optJSONArray("peers")?.optJSONObject(0)
            ?: error("The device configuration contained no peer.")

        val peerPublicKey = peer.optString("public_key").takeIf { it.isNotEmpty() }
            ?: error("The peer had no public key.")

        val endpoint = endpointOf(peer.optJSONObject("endpoint"))

        val addresses = StringBuilder()
        config.optJSONObject("interface")?.optJSONObject("addresses")?.let { addr ->
            addr.optString("v4").takeIf { it.isNotEmpty() }?.let { addresses.append(it).append("/32") }
            addr.optString("v6").takeIf { it.isNotEmpty() }?.let {
                if (addresses.isNotEmpty()) addresses.append(", ")
                addresses.append(it).append("/128")
            }
        }
        if (addresses.isEmpty()) {
            error("The device configuration contained no interface address.")
        }

        return buildString {
            append("[Interface]\n")
            append("PrivateKey = ").append(account.privateKey).append('\n')
            append("Address = ").append(addresses).append('\n')
            append("DNS = ").append(DNS).append('\n')
            append("MTU = ").append(MTU).append('\n')
            append("[Peer]\n")
            append("PublicKey = ").append(peerPublicKey).append('\n')
            append("AllowedIPs = ").append(ALLOWED_IPS).append('\n')
            append("Endpoint = ").append(endpoint).append('\n')
        }
    }

    /**
     * Resolve `host:port` from the API's endpoint object.
     *
     * The API is inconsistent between the two shapes it returns:
     * - `host` is already a complete `host:port` (`engage.cloudflareclient.com:2408`) and must be
     *   passed through **unchanged** — appending `ports[0]` to it yields `...:2408:2408`.
     * - `v4`/`v6` carry a *placeholder* port that is always `:0` and must be dropped before the real
     *   port is applied.
     *
     * Only a literal `:0` is treated as a placeholder. Both the doubled-port and the
     * "stripped-a-valid-port" defects were caught by tests against a live response, so the
     * distinction is deliberate rather than cosmetic.
     */
    internal fun endpointOf(endpoint: JSONObject?): String {
        endpoint ?: error("The peer had no endpoint.")

        val host = endpoint.optString("host").takeIf { it.isNotEmpty() }
        if (host != null) return host

        val raw = endpoint.optString("v4").takeIf { it.isNotEmpty() }
            ?: endpoint.optString("v6").takeIf { it.isNotEmpty() }
            ?: error("The peer endpoint had no host or address.")

        val ports = endpoint.optJSONArray("ports")
        val port = if (ports != null && ports.length() > 0) ports.optInt(0, DEFAULT_PORT) else DEFAULT_PORT
        return "${stripPlaceholderPort(raw)}:$port"
    }

    /** Drop the API's `:0` placeholder so the real port can be applied exactly once. */
    private fun stripPlaceholderPort(host: String): String {
        // Bracketed IPv6: [2606:4700:d0::a29f:c00a]:0
        if (host.startsWith("[")) {
            val close = host.indexOf(']')
            if (close < 0) return host
            return if (host.substring(close + 1) == ":$PLACEHOLDER_PORT") {
                host.substring(0, close + 1)
            } else {
                host
            }
        }
        return host.removeSuffix(":$PLACEHOLDER_PORT")
    }

    /** The resolvers the official WARP profile uses. Inside the tunnel these are Cloudflare's. */
    const val DNS = "1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001"

    /** Same MTU the official Android app and wgcf use, for compatibility. */
    const val MTU = 1280

    const val ALLOWED_IPS = "0.0.0.0/0, ::/0"
    private const val DEFAULT_PORT = 2408
    private const val PLACEHOLDER_PORT = "0"
}
