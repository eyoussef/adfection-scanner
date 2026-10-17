package dev.adfection.scanner.ui

import dev.adfection.scanner.data.Action
import dev.adfection.scanner.data.AppFinding
import dev.adfection.scanner.data.EventKind
import dev.adfection.scanner.data.PostureFinding
import dev.adfection.scanner.data.ScanEvent
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.data.ThreatCategory
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the exported device report.
 *
 * The report is what a targeted user hands to a forensic responder. Two properties matter and are
 * asserted here: it must contain the evidence that makes an analyst's job possible, and it must not
 * contain the device's own identifiers.
 */
class ReportBuilderTest {

    private val now = 1_760_000_000_000L // fixed instant so the header is deterministic

    private fun event(
        subject: String,
        severity: Severity = Severity.HIGH,
        category: ThreatCategory? = ThreatCategory.CANDIRU_C2,
        action: Action = Action.BLOCKED,
        detail: String = "CL195 — CANDIRU_C2: Candiru command-and-control",
        kind: EventKind = EventKind.DNS_BLOCKED,
        ts: Long = now - 60_000,
    ) = ScanEvent(
        timestamp = ts,
        kind = kind,
        severity = severity,
        category = category,
        subject = subject,
        detail = detail,
        action = action,
    )

    @Test
    fun `report names the matched host, its category and its provenance`() {
        val report = ReportBuilder.render(
            events = listOf(event("fearevolve.com")),
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        assertTrue(report.contains("fearevolve.com"))
        assertTrue(report.contains("CANDIRU_C2"))
        assertTrue(report.contains("CL195"))
        assertTrue(report.contains("2026-10-17"))
        assertTrue(report.contains("58"))
    }

    @Test
    fun `critical findings are called out ahead of the general list`() {
        val report = ReportBuilder.render(
            events = listOf(
                event("noas.mtrtb.com", Severity.MEDIUM, ThreatCategory.AD_DELIVERY),
                event("fearevolve.com", Severity.CRITICAL, ThreatCategory.CANDIRU_C2, kind = EventKind.CHAIN_DETECTED),
            ),
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        val criticalAt = report.indexOf("CRITICAL FINDINGS")
        val matchedAt = report.indexOf("MATCHED INFRASTRUCTURE")

        assertTrue("critical section must exist", criticalAt >= 0)
        assertTrue("critical section must precede the full list", criticalAt < matchedAt)
    }

    @Test
    fun `summary counts separate blocked from alerted`() {
        val report = ReportBuilder.render(
            events = listOf(
                event("a.example", action = Action.BLOCKED),
                event("b.example", action = Action.BLOCKED),
                event("c.example", action = Action.ALERTED, severity = Severity.LOW, category = ThreatCategory.TRACKING),
            ),
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        assertTrue(report.contains("Observations recorded : 3"))
        assertTrue(report.contains("Blocked               : 2"))
        assertTrue(report.contains("Alerted only          : 1"))
    }

    @Test
    fun `posture findings carry their remediation so a reader can act`() {
        val report = ReportBuilder.render(
            events = emptyList(),
            posture = listOf(
                PostureFinding(
                    id = "private_dns_bypass",
                    title = "Private DNS is bypassing this scanner",
                    detail = "Private DNS mode is 'hostname'.",
                    severity = Severity.CRITICAL,
                    remediation = "Set Private DNS to Off while using this scanner.",
                ),
            ),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        assertTrue(report.contains("Private DNS is bypassing this scanner"))
        assertTrue(report.contains("Set Private DNS to Off"))
        assertTrue(report.contains("[CRITICAL]"))
    }

    @Test
    fun `application findings list their reasons`() {
        val report = ReportBuilder.render(
            events = emptyList(),
            posture = emptyList(),
            apps = listOf(
                AppFinding(
                    packageName = "com.example.spy",
                    label = "Helper",
                    riskPoints = 7,
                    reasons = listOf("sideloaded", "holds camera + microphone + location"),
                    severity = Severity.HIGH,
                    installer = "unknown",
                    versionName = "1.0",
                ),
            ),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        assertTrue(report.contains("com.example.spy"))
        assertTrue(report.contains("risk 7"))
        assertTrue(report.contains("sideloaded"))
        assertTrue(report.contains("installer=unknown"))
    }

    /**
     * The report is a record of *infrastructure contacted*. It must not carry the device's own
     * identifiers, because the report itself is a file the user may send over an untrusted channel.
     */
    @Test
    fun `report does not include device or account identifiers`() {
        val report = ReportBuilder.render(
            events = listOf(event("fearevolve.com")),
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        val forbidden = listOf("android_id", "advertising_id", "ad_id=", "imei", "serial", "account_id")
        forbidden.forEach { term ->
            assertFalse("report must not contain '$term'", report.contains(term, ignoreCase = true))
        }
    }

    @Test
    fun `report states the limits of its own evidence`() {
        val report = ReportBuilder.render(
            events = listOf(event("fearevolve.com")),
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        // A reader must not treat a match as proof of infection, nor a clean log as proof of safety.
        assertTrue(report.contains("not proof of infection", ignoreCase = true))
        assertTrue(report.contains("does not clear the device", ignoreCase = true))
        assertTrue(report.contains("dated snapshot", ignoreCase = true))
    }

    @Test
    fun `an empty log still produces a valid report rather than failing`() {
        val report = ReportBuilder.render(
            events = emptyList(),
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 0,
            compiledAt = null,
            now = now,
        )

        assertTrue(report.contains("AdFection Scanner — device report"))
        assertTrue(report.contains("Observations recorded : 0"))
        assertFalse("no critical section when there is nothing critical", report.contains("CRITICAL FINDINGS"))
    }

    @Test
    fun `a large event list is capped so the report stays sendable`() {
        val many = (1..500).map { event("host-$it.example") }

        val report = ReportBuilder.render(
            events = many,
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        assertTrue("must mention the trimmed remainder", report.contains("more matching observations"))
    }

    @Test
    fun `unmatched observations are counted but not listed as infrastructure matches`() {
        val report = ReportBuilder.render(
            events = listOf(
                event("ordinary.example", category = null, action = Action.LOGGED, detail = "seen"),
                event("fearevolve.com"),
            ),
            posture = emptyList(),
            apps = emptyList(),
            indicatorCount = 58,
            compiledAt = "2026-10-17",
            now = now,
        )

        val matchedStart = report.indexOf("MATCHED INFRASTRUCTURE")
        val matchedBody = report.substring(matchedStart)
        assertTrue("the matched host is listed", matchedBody.contains("fearevolve.com"))
        // The unmatched observation remains part of the summary but is not presented as a match.
        assertTrue(report.contains("Observations recorded : 2"))
        assertFalse(matchedBody.contains("ordinary.example"))
    }
}
