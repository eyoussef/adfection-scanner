package dev.adfection.scanner.engine

import dev.adfection.scanner.data.Ioc
import dev.adfection.scanner.data.IocType
import dev.adfection.scanner.data.MatchResult
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.data.ThreatCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class ChainDetectorTest {

    private fun match(category: ThreatCategory, host: String) = MatchResult(
        Ioc(IocType.DOMAIN, host, category, Severity.CRITICAL, "test", ""),
        host,
    )

    @Test
    fun `full ordered chain within the window trips exactly once`() {
        val detector = ChainDetector(windowMs = 60_000)
        val t0 = 1_000_000L

        assertNull(detector.observe(match(ThreatCategory.AD_DELIVERY, "noas.mtrtb.com"), t0))
        assertNull(detector.observe(match(ThreatCategory.CANDIRU_VALIDATOR, "keyadapter.com"), t0 + 5_000))

        val alert = detector.observe(match(ThreatCategory.CANDIRU_C2, "fearevolve.com"), t0 + 9_000)
        assertNotNull(alert)
        assertEquals(3, detector.progress)

        // A second C2 hit must not re-alert for the same incident.
        assertNull(detector.observe(match(ThreatCategory.CANDIRU_C2, "jobmarcher.com"), t0 + 10_000))
    }

    @Test
    fun `chain does not trip when stages arrive out of order`() {
        val detector = ChainDetector(windowMs = 60_000)
        val t0 = 1_000_000L

        // C2 first: a validator/C2 hit with no preceding ad contact is not the documented chain.
        assertNull(detector.observe(match(ThreatCategory.CANDIRU_C2, "fearevolve.com"), t0))
        assertEquals(0, detector.progress)

        assertNull(detector.observe(match(ThreatCategory.CANDIRU_VALIDATOR, "keyadapter.com"), t0 + 1_000))
        assertEquals(0, detector.progress)

        // Now the ad contact, then the remaining stages in order.
        assertNull(detector.observe(match(ThreatCategory.AD_DELIVERY, "mtrtb.com"), t0 + 2_000))
        assertEquals(1, detector.progress)
        assertNull(detector.observe(match(ThreatCategory.CANDIRU_VALIDATOR, "keyadapter.com"), t0 + 3_000))
        assertEquals(2, detector.progress)
        assertNotNull(detector.observe(match(ThreatCategory.CANDIRU_C2, "fearevolve.com"), t0 + 4_000))
    }

    @Test
    fun `chain does not trip when the window expires between stages`() {
        val detector = ChainDetector(windowMs = 60_000)
        val t0 = 1_000_000L

        assertNull(detector.observe(match(ThreatCategory.AD_DELIVERY, "mtrtb.com"), t0))
        // Validator arrives well outside the window: progress must have been discarded.
        assertNull(detector.observe(match(ThreatCategory.CANDIRU_VALIDATOR, "keyadapter.com"), t0 + 120_000))
        assertEquals(0, detector.progress)

        assertNull(detector.observe(match(ThreatCategory.CANDIRU_C2, "fearevolve.com"), t0 + 121_000))
    }

    @Test
    fun `tracking contact counts as the first stage but adint and context do not`() {
        val tracking = ChainDetector(windowMs = 60_000)
        val t0 = 2_000_000L
        assertNull(tracking.observe(match(ThreatCategory.TRACKING, "tracookiepixel.xyz"), t0))
        assertEquals(1, tracking.progress)

        val adint = ChainDetector(windowMs = 60_000)
        assertNull(adint.observe(match(ThreatCategory.ADINT, "intelos.io"), t0))
        assertEquals(0, adint.progress)

        val context = ChainDetector(windowMs = 60_000)
        assertNull(context.observe(match(ThreatCategory.CONTEXT, "bidr.io"), t0))
        assertEquals(0, context.progress)
    }

    @Test
    fun `repeated first-stage hits do not reset the chain start time`() {
        val detector = ChainDetector(windowMs = 60_000)
        val t0 = 3_000_000L

        assertNull(detector.observe(match(ThreatCategory.AD_DELIVERY, "mtrtb.com"), t0))
        assertNull(detector.observe(match(ThreatCategory.AD_DELIVERY, "akedo.gg"), t0 + 10_000))
        assertNull(detector.observe(match(ThreatCategory.CANDIRU_VALIDATOR, "keyadapter.com"), t0 + 20_000))
        // Window is measured from the *first* ad contact, so t0+65s must have expired the chain.
        assertNull(detector.observe(match(ThreatCategory.CANDIRU_C2, "fearevolve.com"), t0 + 65_000))
    }

    @Test
    fun `reset clears progress and allows a fresh incident to be reported`() {
        val detector = ChainDetector(windowMs = 60_000)
        val t0 = 4_000_000L

        detector.observe(match(ThreatCategory.AD_DELIVERY, "mtrtb.com"), t0)
        detector.observe(match(ThreatCategory.CANDIRU_VALIDATOR, "keyadapter.com"), t0 + 1_000)
        assertNotNull(detector.observe(match(ThreatCategory.CANDIRU_C2, "fearevolve.com"), t0 + 2_000))

        detector.reset()
        assertEquals(0, detector.progress)

        detector.observe(match(ThreatCategory.AD_DELIVERY, "mtrtb.com"), t0 + 10_000)
        detector.observe(match(ThreatCategory.CANDIRU_VALIDATOR, "keyadapter.com"), t0 + 11_000)
        assertNotNull(detector.observe(match(ThreatCategory.CANDIRU_C2, "jobmarcher.com"), t0 + 12_000))
    }
}
