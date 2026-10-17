package dev.adfection.scanner.data

/**
 * Data model for the AdFection scanner.
 *
 * Interfaces in this file are frozen: the IOC engine, VPN service, scanners, UI and tests all
 * depend on them. Add fields with defaults; do not rename or reorder semantics.
 */

/** What kind of infrastructure an indicator describes. */
enum class ThreatCategory {
    /** Ad-buying / ad-serving infrastructure used to deliver the attack (Discover-Tech). */
    AD_DELIVERY,

    /** Tracking / cookie-sync / identity-graph infrastructure. */
    TRACKING,

    /** Candiru device-profiling ("validator") endpoints. */
    CANDIRU_VALIDATOR,

    /** Candiru command-and-control endpoints. */
    CANDIRU_C2,

    /** Recovered Candiru implant artefact. */
    CANDIRU_IMPLANT,

    /** Mercenary advertising-intelligence (ADINT) vendors: Intelos, Tekma, Bindecy. */
    ADINT,

    /** Vendor domains that merely host attacker-linked sub-domains; alert only. */
    CONTEXT,
}

/** Severity drives both UI colour and the default block policy. */
enum class Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO;

    companion object {
        /** Parse from the IOC file; unknown values degrade to INFO rather than throwing. */
        fun parse(raw: String): Severity =
            entries.firstOrNull { it.name.equals(raw.trim(), ignoreCase = true) } ?: INFO
    }
}

/** How a single indicator is compared against an observed host / address. */
enum class IocType {
    /** Matches the apex domain and every sub-domain of it. */
    DOMAIN,

    /** Matches exactly one host name. */
    HOST,

    /** Matches one IPv4/IPv6 literal. */
    IP,

    /** Matches an IPv4 network in CIDR notation. */
    CIDR,

    /** Matches a SHA-256 file hash. */
    SHA256,
}

/**
 * One indicator of compromise, with provenance so every alert can be traced back to a source.
 */
data class Ioc(
    val type: IocType,
    val value: String,
    val category: ThreatCategory,
    val severity: Severity,
    val source: String,
    val note: String = "",
) {
    /** Stable key for de-duplicating alerts and persisting decisions. */
    val key: String get() = "${type.name}:$value"
}

/** What produced an event, for the audit log. */
enum class EventKind {
    DNS_BLOCKED,
    DNS_OBSERVED,
    CHAIN_DETECTED,
    POSTURE_FINDING,
    APP_FINDING,
    SCAN_RUN,
    SERVICE_STATE,
}

/** Action the engine took for an observation. */
enum class Action {
    BLOCKED,
    ALERTED,
    LOGGED,
}

/**
 * A single record in the on-device evidence log.
 *
 * @param subject the host, IP, package name or setting key the event is about.
 * @param detail human-readable explanation, including IOC provenance when known.
 */
data class ScanEvent(
    val id: Long = 0,
    val timestamp: Long,
    val kind: EventKind,
    val severity: Severity,
    val category: ThreatCategory?,
    val subject: String,
    val detail: String,
    val action: Action,
)

/** Result of matching one observed host against the indicator set. */
data class MatchResult(
    val ioc: Ioc,
    val matchedHost: String,
)

/** Outcome of a device posture check. */
data class PostureFinding(
    val id: String,
    val title: String,
    val detail: String,
    val severity: Severity,
    val remediation: String,
)

/** Outcome of the installed-application audit for one package. */
data class AppFinding(
    val packageName: String,
    val label: String,
    val riskPoints: Int,
    val reasons: List<String>,
    val severity: Severity,
    val installer: String?,
    val versionName: String?,
)
