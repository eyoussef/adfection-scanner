package dev.adfection.scanner.vpn

import android.content.Context
import com.wireguard.config.Config
import java.io.BufferedReader
import java.io.File
import java.io.StringReader

/**
 * Storage and validation for user-supplied WireGuard profiles.
 *
 * ## Why the app does not ship a VPN provider
 * WireGuard needs a gateway to connect to: an endpoint, a server public key, and an address
 * assigned to this device. Those are *service* credentials, not client software. Every serious
 * provider issues them per-account, so the right design is a client that accepts a profile the
 * user already has — which is exactly what the official WireGuard app does.
 *
 * Profiles are stored in the app's private files directory, never in shared/external storage, and
 * are never uploaded. A profile contains a private key; it is treated as a secret.
 */
class WireGuardProfiles(private val context: Context) {

    private val dir: File get() = File(context.filesDir, "wg").apply { if (!exists()) mkdirs() }

    /** A profile on disk plus its parse result. */
    data class Entry(
        val name: String,
        val file: File,
        val config: Config?,
        val error: String?,
    ) {
        val isValid: Boolean get() = config != null
    }

    fun list(): List<Entry> = (dir.listFiles { f -> f.isFile && f.name.endsWith(SUFFIX) } ?: emptyArray())
        .sortedBy { it.name }
        .map { file ->
            val name = file.name.removeSuffix(SUFFIX)
            runCatching {
                val text = file.readText()
                Entry(name, file, parse(text), null)
            }.getOrElse { error ->
                Entry(name, file, null, error.message ?: error::class.java.simpleName)
            }
        }

    /**
     * Validate and store a profile.
     *
     * Validation is real: the config must parse *and* contain at least one peer with an endpoint,
     * otherwise it is a file that would silently fail to connect.
     *
     * @return null on success, or a human-readable reason for rejection.
     */
    fun save(name: String, content: String): String? {
        val safe = sanitize(name)
        if (safe.isEmpty()) return "Profile name must contain letters or digits."

        val config = try {
            parse(content)
        } catch (t: Throwable) {
            return "Not a valid WireGuard config: ${t.message}"
        }

        if (config.peers.isEmpty()) return "Config has no [Peer] section."
        val peer = config.peers.first()
        if (!peer.endpoint.isPresent) return "[Peer] has no Endpoint (host:port)."

        // Interface.getPrivateKey() is not public API; getKeyPair() is. A config with no key at
        // all yields a null keyPair, which would handshake and fail silently on connect.
        val keyPair = runCatching { config.`interface`.keyPair }.getOrNull()
        if (

            keyPair == null || runCatching { keyPair.privateKey }.getOrNull() == null
        ) {
            return "[Interface] has no PrivateKey."
        }
        if (runCatching { peer.publicKey }.getOrNull() == null) return "[Peer] has no PublicKey."

        runCatching {
            File(dir, "$safe$SUFFIX").writeText(content.trim() + "\n")
        }.onFailure { return "Could not write profile: ${it.message}" }
        return null
    }

    fun delete(name: String): Boolean = File(dir, "${sanitize(name)}$SUFFIX").delete()

    fun read(name: String): String? = runCatching {
        File(dir, "${sanitize(name)}$SUFFIX").readText()
    }.getOrNull()

    companion object {
        const val SUFFIX = ".conf"

        /**
         * Strip anything that could escape the profile directory.
         *
         * Exposed (internal) so the unit tests exercise the real implementation rather than a copy
         * of it — a test of a re-implementation proves nothing about the shipped code.
         */
        internal fun sanitize(name: String): String =
            name.trim().replace(Regex("[^A-Za-z0-9._-]"), "_").take(64).trim('_', '.')

        /**
         * Parse a wg-quick config. [Config.parse] is the official parser from the WireGuard
         * library, so anything the official client accepts, this accepts.
         */
        fun parse(text: String): Config = Config.parse(BufferedReader(StringReader(text)))

        /**
         * A minimal, self-contained profile template. It is deliberately *not* pre-filled with a
         * third-party endpoint: inventing one would be a fake default that fails on first use.
         */
        fun template(): String = """
            [Interface]
            PrivateKey = <paste your private key>
            Address    = 10.7.0.2/32
            DNS        = 10.7.0.1

            [Peer]
            PublicKey  = <paste the server public key>
            Endpoint   = <hostname or ip>:51820
            AllowedIPs = 0.0.0.0/0, ::/0
        """.trimIndent()
    }
}
