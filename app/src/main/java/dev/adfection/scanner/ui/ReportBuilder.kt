package dev.adfection.scanner.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import dev.adfection.scanner.data.Action
import dev.adfection.scanner.data.AppFinding
import dev.adfection.scanner.data.Ioc
import dev.adfection.scanner.data.PostureFinding
import dev.adfection.scanner.data.ScanEvent
import dev.adfection.scanner.data.Severity
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Builds and shares a human-readable report of what this device observed.
 *
 * ## Why this exists
 * The app tells the user to treat a full chain as a compromise and "seek expert help" — but until now
 * there was nothing to hand that expert. A forensic responder needs the timeline, the exact hosts, the
 * categories and the indicator provenance; asking a targeted user to read rows off a phone screen and
 * retype them is both error-prone and a privacy risk.
 *
 * ## What is deliberately excluded
 * The device's own identifiers are not included: no advertising ID value, no IMEI, no account names.
 * The report names *hosts the device contacted* and *settings that weaken it* — the minimum an analyst
 * needs, and nothing that turns the report itself into a tracking artefact if it is mishandled.
 *
 * The file is shared through [FileProvider] from app-private storage, not written to shared storage, so
 * it exists only where the user sends it.
 */
object ReportBuilder {

    /**
     * Render the report.
     *
     * @param now injected so the header is deterministic in tests.
     */
    fun render(
        events: List<ScanEvent>,
        posture: List<PostureFinding>,
        apps: List<AppFinding>,
        indicatorCount: Int,
        compiledAt: String?,
        now: Long = System.currentTimeMillis(),
    ): String = buildString {
        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(Date(now))

        append("AdFection Scanner — device report\n")
        append("Generated: $stamp\n")
        append("Indicators bundled: ${indicatorCount}")
        append(if (compiledAt != null) " (compiled $compiledAt)\n" else "\n")
        append("\n")

        append("WHAT THIS IS\n")
        append("A log of infrastructure this device contacted while monitoring was running, matched\n")
        append("against published indicators of the AdFection / Discover-Tech / Candiru campaign.\n")
        append("A match is not proof of infection. It is evidence that the device communicated with\n")
        append("infrastructure that has been publicly linked to the campaign.\n")
        append("\n")

        val critical = events.filter { it.severity == Severity.CRITICAL }
        val blocked = events.filter { it.action == Action.BLOCKED }
        val alerted = events.filter { it.action == Action.ALERTED }

        append("SUMMARY\n")
        append("Observations recorded : ${events.size}\n")
        append("Blocked               : ${blocked.size}\n")
        append("Alerted only          : ${alerted.size}\n")
        append("Critical              : ${critical.size}\n")
        append("\n")

        if (critical.isNotEmpty()) {
            append("CRITICAL FINDINGS\n")
            critical.forEach { event ->
                append("  ${formatTime(event.timestamp)}  ${event.kind}  ${event.subject}\n")
                append("      ${event.detail}\n")
            }
            append("\n")
        }

        val matched = events.filter { it.category != null }
        if (matched.isNotEmpty()) {
            append("MATCHED INFRASTRUCTURE (newest first)\n")
            matched.take(MAX_MATCHED).forEach { event ->
                append(
                    "  ${formatTime(event.timestamp)}  ${event.action.name.padEnd(7)}  " +
                        "${event.severity.name.padEnd(8)}  ${event.subject}\n",
                )
                append("      category=${event.category?.name} | ${event.detail}\n")
            }
            if (matched.size > MAX_MATCHED) {
                append("  ... ${matched.size - MAX_MATCHED} more matching observations in the app log\n")
            }
            append("\n")
        }

        if (posture.isNotEmpty()) {
            append("DEVICE POSTURE FINDINGS\n")
            posture.forEach { finding ->
                append("  [${finding.severity.name}] ${finding.title}\n")
                append("      ${finding.detail}\n")
                append("      fix: ${finding.remediation}\n")
            }
            append("\n")
        }

        if (apps.isNotEmpty()) {
            append("APPLICATION AUDIT (highest risk first)\n")
            apps.take(MAX_APPS).forEach { finding ->
                append("  risk ${finding.riskPoints}  ${finding.packageName} (${finding.label})\n")
                if (finding.installer != null) append("      installer=${finding.installer}\n")
                finding.reasons.forEach { append("      - $it\n") }
            }
            append("\n")
        }

        append("INTERPRETATION NOTES FOR AN ANALYST\n")
        append("- Every row is an observation by this device, not a verdict. Corroborate before acting.\n")
        append("- Category CANDIRU_VALIDATOR / CANDIRU_C2 / CANDIRU_IMPLANT rows matter most; the\n")
        append("  validator stage is the attacker checking whether a device is worth infecting.\n")
        append("- AD_DELIVERY and TRACKING rows are ordinary ad-tech traffic and are expected on any\n")
        append("  device; they are context, not evidence.\n")
        append("- The indicator set is a dated snapshot. Infrastructure rotates; absence of matches\n")
        append("  after the compile date above is weak evidence of anything.\n")
        append("- DNS monitoring cannot see DNS-over-HTTPS/TLS to a hardcoded resolver, or traffic to\n")
        append("  IP literals. A negative report does not clear the device.\n")
    }

    /** Write the report to a private file and return a content:// URI to share. */
    fun writeAndShareUri(context: Context, content: String): Intent {
        val dir = File(context.filesDir, "reports").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(Date())
        val file = File(dir, "adfection-report-$stamp.txt")
        file.writeText(content)

        val uri = FileProvider.getUriForFile(context, "${context.packageName}.reports", file)
        return Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "AdFection Scanner report")
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    private fun formatTime(millis: Long): String =
        SimpleDateFormat("MM-dd HH:mm:ss", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(Date(millis))

    private const val MAX_MATCHED = 200
    private const val MAX_APPS = 25
}
