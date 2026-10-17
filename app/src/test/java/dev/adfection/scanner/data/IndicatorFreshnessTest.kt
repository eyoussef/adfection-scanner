package dev.adfection.scanner.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

/**
 * Tests for indicator-set freshness.
 *
 * This logic decides whether the app warns the user that its detection data has expired. Getting it
 * wrong in the "fresh" direction is the dangerous failure: the user believes they are covered by
 * indicators that stopped matching months ago, and a clean log is then read as evidence of safety.
 */
class IndicatorFreshnessTest {

    private fun at(date: String): Long =
        java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
            .parse(date)!!.time

    @Test
    fun `a compile date yields its age in whole days`() {
        val age = IndicatorFreshness.ageInDays("2026-10-01", at("2026-10-17T12:00:00Z"))

        assertEquals(16L, age)
    }

    @Test
    fun `a same-day compile date is zero days old`() {
        assertEquals(0L, IndicatorFreshness.ageInDays("2026-10-17", at("2026-10-17T23:00:00Z")))
    }

    @Test
    fun `a missing compile date has no age rather than a default`() {
        assertNull(IndicatorFreshness.ageInDays(null, at("2026-10-17T12:00:00Z")))
        assertNull(IndicatorFreshness.ageInDays("", at("2026-10-17T12:00:00Z")))
        assertNull(IndicatorFreshness.ageInDays("   ", at("2026-10-17T12:00:00Z")))
    }

    @Test
    fun `an unparseable date has no age rather than throwing`() {
        assertNull(IndicatorFreshness.ageInDays("some time last year", at("2026-10-17T12:00:00Z")))
        assertNull(IndicatorFreshness.ageInDays("17/10/2026", at("2026-10-17T12:00:00Z")))
        // A lenient parser would read this as a valid date; the parser is strict on purpose.
        assertNull(IndicatorFreshness.ageInDays("2026-13-45", at("2026-10-17T12:00:00Z")))
    }

    @Test
    fun `a future date does not produce a negative age`() {
        val age = IndicatorFreshness.ageInDays("2027-01-01", at("2026-10-17T12:00:00Z"))

        assertEquals(0L, age)
    }

    @Test
    fun `a set past the threshold is stale`() {
        assertTrue(IndicatorFreshness.isStale("2026-09-01", at("2026-10-17T12:00:00Z")))
    }

    @Test
    fun `a set inside the threshold is not stale`() {
        assertFalse(IndicatorFreshness.isStale("2026-10-10", at("2026-10-17T12:00:00Z")))
    }

    @Test
    fun `the threshold boundary counts as stale`() {
        val now = at("2026-10-31T00:00:00Z")
        val exactly = IndicatorFreshness.ageInDays("2026-10-01", now)

        assertEquals(30L, exactly)
        assertTrue("exactly 30 days must report as stale", IndicatorFreshness.isStale("2026-10-01", now))
    }

    /**
     * The important one: an undated set cannot be shown to be current, so it is reported as stale.
     * Silence here would let an old snapshot present itself as live coverage.
     */
    @Test
    fun `an undated set is treated as stale`() {
        assertTrue(IndicatorFreshness.isStale(null, at("2026-10-17T12:00:00Z")))
        assertTrue(IndicatorFreshness.isStale("", at("2026-10-17T12:00:00Z")))
    }

    @Test
    fun `the compile date is read out of a realistic header`() {
        val header = """
            # AdFection scanner — indicator set
            # Format: type<TAB>value<TAB>category<TAB>severity<TAB>source<TAB>note
            #
            # NOTE ON COVERAGE: this is the published, public indicator set only.
            #
            # Compiled: 2026-10-17
        """.trimIndent()

        assertEquals("2026-10-17", IndicatorFreshness.compiledAtFrom(header))
    }

    @Test
    fun `a header without the marker yields null`() {
        assertNull(IndicatorFreshness.compiledAtFrom("# AdFection scanner\n# no date here\n"))
    }

    /**
     * The scan window is bounded, so a `Compiled:` string appearing inside indicator data (a note
     * field, say) can never be mistaken for the file's own metadata.
     */
    @Test
    fun `the marker is only honoured inside the header window`() {
        val body = (1..40).joinToString("\n") { "# padding line $it" } + "\nCompiled: 2020-01-01"

        assertNull("a marker past the header window must be ignored", IndicatorFreshness.compiledAtFrom(body, scanLines = 25))
    }

    @Test
    fun `the parsed date feeds straight into the age calculation`() {
        val header = "# Compiled: 2026-10-01"
        val compiled = IndicatorFreshness.compiledAtFrom(header)
        val age = IndicatorFreshness.ageInDays(compiled, at("2026-10-17T12:00:00Z"))

        assertEquals(16L, age)
    }

    @Test
    fun `age is computed in whole days regardless of time of day`() {
        // 23:59 on the 16th versus 00:01 on the 17th are less than a day apart.
        val early = IndicatorFreshness.ageInDays("2026-10-16", at("2026-10-16T23:59:00Z"))
        val late = IndicatorFreshness.ageInDays("2026-10-16", at("2026-10-17T00:01:00Z"))

        assertEquals(0L, early)
        // Strictly, 2 minutes later is still under a day; the parser anchors to 00:00 UTC so a same-day
        // compile is 0 and the next calendar day is 1.
        assertEquals(1L, late)
    }

    @Test
    fun `the threshold is the documented thirty days`() {
        assertEquals(30L, IndicatorFreshness.STALE_AFTER_DAYS)
        assertEquals(TimeUnit.DAYS.toMillis(30), TimeUnit.DAYS.toMillis(IndicatorFreshness.STALE_AFTER_DAYS))
    }
}
