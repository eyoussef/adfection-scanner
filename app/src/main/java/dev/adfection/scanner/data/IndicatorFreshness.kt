package dev.adfection.scanner.data

import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * Freshness of the bundled indicator set.
 *
 * Separated from [IocDatabase] (which needs a `Context`) so the arithmetic that drives the user-facing
 * warning is testable on a plain JVM. The distinction matters: a stale list silently becomes a false
 * negative generator, and no other part of the app can detect that.
 */
object IndicatorFreshness {

    /** A month-old list is still worth matching against, but must stop being called current coverage. */
    const val STALE_AFTER_DAYS = 30L

    /**
     * Whole days between a `yyyy-MM-dd` compile date and [now].
     *
     * @return null when the date is absent or unparseable — callers must treat that as "unknown", not
     *         as "fresh", so an undated file is never reported as current.
     */
    fun ageInDays(compiled: String?, now: Long): Long? {
        if (compiled.isNullOrBlank()) return null
        return runCatching {
            val parsed = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply {
                isLenient = false
                timeZone = TimeZone.getTimeZone("UTC")
            }.parse(compiled.trim()) ?: return null
            ((now - parsed.time) / DAY_MS).coerceAtLeast(0)
        }.getOrNull()
    }

    /**
     * Whether the set should be reported as stale.
     *
     * An unknown age returns true: without a date there is no way to demonstrate the list is current,
     * and claiming coverage that cannot be substantiated is the failure mode this exists to prevent.
     */
    fun isStale(compiled: String?, now: Long): Boolean = ageInDays(compiled, now)
        ?.let { it >= STALE_AFTER_DAYS }
        ?: true

    /** Pull `Compiled: YYYY-MM-DD` out of a `#`-prefixed header line. */
    fun compiledAtFrom(headerText: String, scanLines: Int = 25): String? = headerText.lineSequence()
        .take(scanLines)
        .firstOrNull { it.startsWith("#") && it.contains(MARKER, ignoreCase = true) }
        ?.substringAfter(MARKER, "")
        ?.trim()
        ?.trimStart(':', ' ')
        ?.takeIf { it.isNotEmpty() }

    private const val MARKER = "Compiled:"
    private const val DAY_MS = 24 * 60 * 60 * 1000L
}
