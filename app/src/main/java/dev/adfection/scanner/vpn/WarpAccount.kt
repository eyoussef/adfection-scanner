package dev.adfection.scanner.vpn

import android.content.Context
import com.wireguard.crypto.KeyPair
import java.io.File

/**
 * A Cloudflare WARP account registered from this device, in the shape wgcf uses.
 *
 * ## Why this app registers its own account instead of shipping one
 * [wgcf] is a CLI: the user runs `wgcf register`, then `wgcf generate`, then copies a `.conf` into
 * a WireGuard client by hand. That is three steps and a file transfer for a user who may be on the
 * device the spyware is targeting — and each manual hop is a chance to leak the profile or give up.
 * The same two API calls can run inside the app, so the profile never leaves app-private storage.
 *
 * ## What is generated, and what is not
 * Only what Cloudflare's registration API returns: one address pair, one peer, one endpoint. The
 * private key is generated here with the WireGuard library's own `KeyPair`, so the only party that
 * ever holds it is this app. Nothing is bundled, and no third party is contacted — the same
 * posture as a hand-imported profile.
 *
 * ## The transport caveat, which is not this code's to fix
 * A WARP-over-WireGuard tunnel depends on Cloudflare answering handshakes for the user's network.
 * They refuse in regions subject to abuse-prevention, with no client-side workaround, and accounts
 * are now provisioned for MASQUE (`tunnel_protocol: masque`) — a transport WireGuard cannot speak.
 * Registration still succeeds and still returns peer details; whether the handshake is answered is
 * decided by Cloudflare. [WarpClient.probeWarp] exists so the app can report the truth rather than
 * claiming success.
 *
 * [wgcf]: https://github.com/ViRb3/wgcf
 */
data class WarpAccount(
    val deviceId: String,
    val token: String,
    /** Base64 Curve25519 private key. Generated on-device; never transmitted anywhere but here. */
    val privateKey: String,
    val licenseKey: String?,
    val accountType: String?,
    /**
     * Cloudflare's `warp_plus` flag.
     *
     * Note for callers: this is **not** a subscription indicator. The API returns `true` for every
     * fresh free account (`account_type: free` alongside `warp_plus: true`), which was confirmed
     * against the live API. A real WARP+ subscription is signalled by [plusExpiresAt]; this field is
     * retained only because it is what the API sent.
     */
    val warpPlus: Boolean,
    /**
     * `plus_expires_at` from the account object, or null when absent.
     *
     * This is the field that actually distinguishes a subscribed account from a free one. Stored as
     * the raw ISO string rather than a parsed date: nothing computes with it, and keeping the source
     * text avoids a timezone round-trip that could shift the displayed value.
     */
    val plusExpiresAt: String?,
    val registeredAtMs: Long,
) {
    /** A short, non-secret handle for the UI. The device id is opaque, so show its head only. */
    fun shortId(): String = deviceId.take(8)
}

/**
 * Persistence for [WarpAccount].
 *
 * Stored in the app's private files directory as a flat `key=value` file rather than JSON: it keeps
 * the Android-only `org.json` out of the storage path so it stays testable on a plain JVM, and the
 * format has no nesting to get wrong.
 *
 * The private key is a credential: it is written to app-private storage only, never to shared
 * storage, and never logged.
 */
class WarpAccountStore(private val context: Context) {

    private val file: File get() = File(context.filesDir, "warp/account.properties")

    fun load(): WarpAccount? = runCatching {
        if (!file.exists()) return null
        val map = file.readLines()
            .mapNotNull { line ->
                val at = line.indexOf('=')
                if (at <= 0) null else line.substring(0, at) to line.substring(at + 1)
            }
            .toMap()

        val deviceId = map[KEY_DEVICE_ID].orEmpty()
        val token = map[KEY_TOKEN].orEmpty()
        val privateKey = map[KEY_PRIVATE_KEY].orEmpty()
        // A partial record is not a usable account; treat it as absent so the UI offers a fresh
        // registration instead of failing later with a confusing network error.
        if (deviceId.isEmpty() || token.isEmpty() || privateKey.isEmpty()) return null

        WarpAccount(
            deviceId = deviceId,
            token = token,
            privateKey = privateKey,
            licenseKey = map[KEY_LICENSE]?.takeIf { it.isNotEmpty() },
            accountType = map[KEY_ACCOUNT_TYPE]?.takeIf { it.isNotEmpty() },
            warpPlus = map[KEY_WARP_PLUS] == "true",
            plusExpiresAt = map[KEY_PLUS_EXPIRES_AT]?.takeIf { it.isNotEmpty() },
            registeredAtMs = map[KEY_REGISTERED_AT]?.toLongOrNull() ?: 0L,
        )
    }.getOrNull()

    fun save(account: WarpAccount): String? = runCatching {
        file.parentFile?.mkdirs()
        file.writeText(
            buildString {
                append(KEY_DEVICE_ID).append('=').append(account.deviceId).append('\n')
                append(KEY_TOKEN).append('=').append(account.token).append('\n')
                append(KEY_PRIVATE_KEY).append('=').append(account.privateKey).append('\n')
                append(KEY_LICENSE).append('=').append(account.licenseKey.orEmpty()).append('\n')
                append(KEY_ACCOUNT_TYPE).append('=').append(account.accountType.orEmpty()).append('\n')
                append(KEY_WARP_PLUS).append('=').append(account.warpPlus).append('\n')
                append(KEY_PLUS_EXPIRES_AT).append('=').append(account.plusExpiresAt.orEmpty()).append('\n')
                append(KEY_REGISTERED_AT).append('=').append(account.registeredAtMs).append('\n')
            },
        )
        null
    }.getOrElse { "Could not store the WARP account: ${it.message}" }

    fun clear(): Boolean = runCatching { file.delete() }.getOrDefault(false)

    internal companion object {
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_TOKEN = "token"
        const val KEY_PRIVATE_KEY = "private_key"
        const val KEY_LICENSE = "license_key"
        const val KEY_ACCOUNT_TYPE = "account_type"
        const val KEY_WARP_PLUS = "warp_plus"
        const val KEY_PLUS_EXPIRES_AT = "plus_expires_at"
        const val KEY_REGISTERED_AT = "registered_at"
    }
}

/**
 * Key material for a registration.
 *
 * [KeyPair] comes from the bundled official WireGuard library, so the curve arithmetic is the same
 * code that will later perform the handshake — not a second implementation that could disagree
 * with it. It runs on a plain JVM (no native library), which is why the pairing is unit-testable.
 */
internal object WarpKeys {

    /** @return base64 private key to store, base64 public key to register. */
    fun generate(): Pair<String, String> {
        val pair = KeyPair()
        return pair.privateKey.toBase64() to pair.publicKey.toBase64()
    }

    /** Re-derive the public key from a stored private key, to verify a record after a reload. */
    fun publicKeyOf(privateKeyB64: String): String? = runCatching {
        val key = com.wireguard.crypto.Key.fromBase64(privateKeyB64)
        KeyPair(key).publicKey.toBase64()
    }.getOrNull()
}
