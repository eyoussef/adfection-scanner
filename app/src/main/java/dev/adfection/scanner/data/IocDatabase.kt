package dev.adfection.scanner.data

import android.content.Context
import dev.adfection.scanner.engine.IocMatcher
import dev.adfection.scanner.engine.TsvIocLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Loads the bundled indicator file from `assets/iocs.tsv`.
 *
 * The indicator set is shipped in-app rather than fetched so the scanner keeps working when the
 * device is offline or the C2-adjacent infrastructure it hunts for is unreachable. Reloading is
 * cheap (~2k lines) and happens on demand from the UI.
 */
class IocDatabase(private val context: Context) {

    @Volatile
    private var cached: Loaded? = null

    data class Loaded(
        val matcher: IocMatcher,
        val iocs: List<Ioc>,
        val problems: List<String>,
        val loadedAt: Long,
        /**
         * When this indicator set was compiled, as declared in the file's own header.
         *
         * The whole detection claim rests on this date. `iocs.tsv` is a snapshot: the attacker rotates
         * CloudFront hosts and NOAS sub-domains, and every published indicator eventually stops
         * matching anything. Reporting the age is what stops the user believing they are covered by a
         * list that stopped being current months ago.
         */
        val compiledAt: String? = null,
    ) {
        val indicatorCount: Int get() = iocs.size
        val sourceCount: Int get() = iocs.map { it.source }.toSet().size
    }

    /** Load (or return the cached copy). */
    suspend fun load(force: Boolean = false): Loaded = withContext(Dispatchers.IO) {
        if (!force) cached?.let { return@withContext it }
        loadBlocking().also { if (force) cached = it }
    }

    /** Synchronous accessor for the VPN service, which loads before starting the read loop. */
    @Synchronized
    fun loadBlocking(): Loaded {
        cached?.let { return it }
        val text = context.assets.open(ASSET_NAME).use { stream ->
            BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).readText()
        }
        val parsed = TsvIocLoader.parse(text)
        val loaded = Loaded(
            matcher = parsed.toMatcher(),
            iocs = parsed.iocs,
            problems = parsed.problems,
            loadedAt = System.currentTimeMillis(),
            compiledAt = readCompiledAt(text),
        )
        cached = loaded
        return loaded
    }

    /** Header parsing lives in [IndicatorFreshness] so the age arithmetic is unit-testable. */
    private fun readCompiledAt(text: String): String? = IndicatorFreshness.compiledAtFrom(text)

    companion object {
        const val ASSET_NAME = "iocs.tsv"

    }
}
