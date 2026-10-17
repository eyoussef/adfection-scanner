package dev.adfection.scanner.engine

import dev.adfection.scanner.data.Ioc
import dev.adfection.scanner.data.IocType
import dev.adfection.scanner.data.MatchResult

/**
 * Matches observed host names and IP addresses against the bundled indicator set.
 *
 * Design:
 *  - [DOMAIN] indicators are stored in a suffix map keyed by the *apex* domain, so a lookup walks
 *    label boundaries only (`a.b.mtrtb.com` -> `b.mtrtb.com` -> `mtrtb.com`). Cost is O(labels),
 *    never O(indicators).
 *  - [HOST] indicators use an exact set.
 *  - [IP]/[CIDR] indicators use an exact set plus a 64-bit prefix map for IPv4.
 *  - [SHA256] indicators are stored verbatim for file-level lookups.
 *
 * All lookups are case-insensitive and tolerant of trailing dots, leading/trailing whitespace and
 * a `www.` prefix only insofar as that is a real label (it is not stripped: `www.x.com` is a
 * different name from `x.com`, and both are covered by a DOMAIN indicator on `x.com`).
 */
class IocMatcher(iocs: List<Ioc>) {

    private val domainsByApex: Map<String, Ioc> =
        iocs.filter { it.type == IocType.DOMAIN }
            .associateBy { normalizeHost(it.value) }

    private val hosts: Map<String, Ioc> =
        iocs.filter { it.type == IocType.HOST }
            .associateBy { normalizeHost(it.value) }

    private val literalIps: Map<String, Ioc> =
        iocs.filter { it.type == IocType.IP }
            .associateBy { it.value.trim().lowercase() }

    private val cidrs: List<Ipv4Cidr.Entry> =
        iocs.filter { it.type == IocType.CIDR }
            .mapNotNull { ioc ->
                Ipv4Cidr.parse(ioc.value)?.let { parsed ->
                    Ipv4Cidr.Entry(network = parsed.networkLength, mask = parsed.mask, ioc = ioc)
                }
            }

    private val hashes: Map<String, Ioc> =
        iocs.filter { it.type == IocType.SHA256 }
            .associateBy { it.value.trim().lowercase() }

    val size: Int get() = domainsByApex.size + hosts.size + literalIps.size + cidrs.size + hashes.size

    /**
     * Match a host name observed in a DNS query.
     *
     * @return the highest-severity match, or null. HOST wins over DOMAIN when both are present,
     *         because an exact indicator is strictly more specific.
     */
    fun matchHost(rawHost: String): MatchResult? {
        val host = normalizeHost(rawHost)
        if (host.isEmpty()) return null

        hosts[host]?.let { return MatchResult(it, host) }

        var remainder = host
        while (true) {
            domainsByApex[remainder]?.let { return MatchResult(it, host) }
            val dot = remainder.indexOf('.')
            if (dot < 0) return null
            remainder = remainder.substring(dot + 1)
            if (remainder.isEmpty()) return null
        }
    }

    /** Match an observed IP literal (used for A/AAAA answers we did not synthesise). */
    fun matchIp(rawIp: String): MatchResult? {
        val ip = rawIp.trim().lowercase()
        literalIps[ip]?.let { return MatchResult(it, ip) }

        val v4 = Ipv4Cidr.toLong(ip) ?: return null
        for (entry in cidrs) {
            if ((v4 and entry.mask) == entry.network) return MatchResult(entry.ioc, ip)
        }
        return null
    }

    /** Match a SHA-256 file hash (lower-case hex or upper-case hex). */
    fun matchHash(rawHash: String): MatchResult? {
        val h = rawHash.trim().lowercase()
        if (h.length != 64) return null
        return hashes[h]?.let { MatchResult(it, h) }
    }

    companion object {
        /** Lower-case, trim, strip a single trailing FQDN dot. Does not do IDN decoding. */
        fun normalizeHost(raw: String): String {
            var h = raw.trim().lowercase()
            if (h.endsWith(".")) h = h.dropLast(1)
            return h
        }
    }
}

/** Minimal, dependency-free IPv4 CIDR helper used by the matcher. */
object Ipv4Cidr {

    /** A parsed range: [network] is the masked address, [mask] the bits to compare under. */
    data class Parsed(val mask: Long, val bits: Int, val networkLength: Long)

    /** A prepared entry: precomputed so matching is one AND plus one compare. */
    data class Entry(val network: Long, val mask: Long, val ioc: Ioc)

    /**
     * Parse `a.b.c.d/nn` into a masked network value plus mask.
     * Returns null for malformed input (including IPv6 ranges, which are not yet supported).
     */
    fun parse(raw: String): Parsed? {
        val s = raw.trim()
        val slash = s.indexOf('/')
        if (slash <= 0) return null
        val address = s.substring(0, slash)
        val bits = s.substring(slash + 1).toIntOrNull() ?: return null
        if (bits !in 0..32) return null

        val value = toLong(address) ?: return null
        val mask = if (bits == 0) 0L else (0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL
        return Parsed(mask, bits, value and mask)
    }

    /** Parse a dotted-quad IPv4 literal into an unsigned 32-bit value held in a Long. */
    fun toLong(address: String): Long? {
        val parts = address.trim().split('.')
        if (parts.size != 4) return null
        var value = 0L
        for (part in parts) {
            if (part.isEmpty() || part.length > 3) return null
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            value = (value shl 8) or octet.toLong()
        }
        return value and 0xFFFFFFFFL
    }
}
