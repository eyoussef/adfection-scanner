package dev.adfection.scanner.engine

import dev.adfection.scanner.data.MatchResult
import dev.adfection.scanner.data.ThreatCategory

/**
 * Detects the AdFection kill-chain signature described in Citizen Lab report 195 §2:
 *
 *   1. the device contacts Discover-Tech ad infrastructure (an ad impression),
 *   2. then a Candiru "validator" server (device profiling),
 *   3. then a Candiru command-and-control server.
 *
 * Any single step is only weak evidence — ad domains are contacted by millions of devices, and a
 * CloudFront hostname can be rotated. The *ordered sequence within one device, inside a short
 * window* is the thing that is actually distinctive, and it is what this class tracks.
 *
 * The detector is deliberately conservative:
 *  - all three stages must be observed in order (a later stage never satisfies an earlier one);
 *  - the whole chain must complete within [windowMs];
 *  - each stage is deduplicated so repeated queries do not reset progress.
 */
class ChainDetector(private val windowMs: Long = 10 * 60 * 1000L) {

    private var firstStageAt = 0L
    private var secondStageAt = 0L
    private var firstSubject: String? = null
    private var secondSubject: String? = null

    /** True once a full chain has fired, until [reset]. Prevents repeat alerts for one incident. */
    var tripped: Boolean = false
        private set

    /**
     * Feed one observation.
     * @return a human-readable chain description the first time a complete chain is observed.
     */
    fun observe(match: MatchResult, now: Long): String? {
        if (tripped) return null

        // Expire stale progress: a stage observed outside the window is no longer "preceding".
        if (firstStageAt != 0L && now - firstStageAt > windowMs) reset()

        when (match.ioc.category) {
            ThreatCategory.AD_DELIVERY, ThreatCategory.TRACKING -> {
                if (firstStageAt == 0L) {
                    firstStageAt = now
                    firstSubject = match.matchedHost
                }
            }

            ThreatCategory.CANDIRU_VALIDATOR -> {
                if (firstStageAt == 0L) return null // step 2 without step 1: not the chain
                if (secondStageAt == 0L) {
                    secondStageAt = now
                    secondSubject = match.matchedHost
                }
            }

            ThreatCategory.CANDIRU_C2 -> {
                if (firstStageAt == 0L || secondStageAt == 0L) return null
                tripped = true
                return buildString {
                    append("AdFection kill-chain observed in order: ")
                    append("ad infrastructure '").append(firstSubject).append("'")
                    append(" \u2192 Candiru validator '").append(secondSubject).append("'")
                    append(" \u2192 Candiru C2 '").append(match.matchedHost).append("'")
                    append(" within ").append((now - firstStageAt) / 1000).append("s")
                }
            }

            ThreatCategory.CANDIRU_IMPLANT, ThreatCategory.ADINT, ThreatCategory.CONTEXT -> Unit
        }
        return null
    }

    fun reset() {
        firstStageAt = 0L
        secondStageAt = 0L
        firstSubject = null
        secondSubject = null
        tripped = false
    }

    /** Exposed for the UI: how far along the chain the device currently looks. */
    val progress: Int
        get() = when {
            tripped -> 3
            secondStageAt != 0L -> 2
            firstStageAt != 0L -> 1
            else -> 0
        }
}
