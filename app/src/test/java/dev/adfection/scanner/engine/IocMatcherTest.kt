package dev.adfection.scanner.engine

import dev.adfection.scanner.data.Ioc
import dev.adfection.scanner.data.IocType
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.data.ThreatCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IocMatcherTest {

    private fun ioc(
        type: IocType,
        value: String,
        category: ThreatCategory = ThreatCategory.AD_DELIVERY,
        severity: Severity = Severity.HIGH,
    ) = Ioc(type, value, category, severity, "test", "")

    @Test
    fun `domain indicator matches apex and all sub-domains`() {
        val matcher = IocMatcher(listOf(ioc(IocType.DOMAIN, "mtrtb.com")))

        assertNotNull(matcher.matchHost("mtrtb.com"))
        assertNotNull(matcher.matchHost("noas.mtrtb.com"))
        assertNotNull(matcher.matchHost("ppv2.mtrtb.com"))
        assertNotNull(matcher.matchHost("a.b.c.mtrtb.com"))
    }

    @Test
    fun `domain indicator does not match a look-alike suffix`() {
        val matcher = IocMatcher(listOf(ioc(IocType.DOMAIN, "mtrtb.com")))

        // The classic false positive: attacker registers the indicator as a *label*, not a suffix.
        assertNull(matcher.matchHost("mtrtb.com.evil.example"))
        assertNull(matcher.matchHost("notmtrtb.com"))
        assertNull(matcher.matchHost("xmtrtb.com"))
    }

    @Test
    fun `host indicator matches exactly one name and nothing else`() {
        val matcher = IocMatcher(listOf(ioc(IocType.HOST, "d23625plpxg1yn.cloudfront.net")))

        assertNotNull(matcher.matchHost("d23625plpxg1yn.cloudfront.net"))
        assertNull(matcher.matchHost("other.cloudfront.net"))
        assertNull(matcher.matchHost("sub.d23625plpxg1yn.cloudfront.net"))
    }

    @Test
    fun `exact host wins over a broader domain indicator`() {
        val matcher = IocMatcher(
            listOf(
                ioc(IocType.DOMAIN, "cloudfront.net", severity = Severity.LOW),
                ioc(IocType.HOST, "d23625plpxg1yn.cloudfront.net", severity = Severity.CRITICAL),
            )
        )

        val match = matcher.matchHost("d23625plpxg1yn.cloudfront.net")
        assertNotNull(match)
        assertEquals(Severity.CRITICAL, match!!.ioc.severity)
    }

    @Test
    fun `lookups normalise case, trailing dot and whitespace`() {
        val matcher = IocMatcher(listOf(ioc(IocType.DOMAIN, "Mtrtb.COM")))

        assertNotNull(matcher.matchHost("NOAS.MTRTB.COM"))
        assertNotNull(matcher.matchHost("noas.mtrtb.com."))
        assertNotNull(matcher.matchHost("  noas.mtrtb.com  "))
    }

    @Test
    fun `empty and malformed hosts never match`() {
        val matcher = IocMatcher(listOf(ioc(IocType.DOMAIN, "mtrtb.com")))

        assertNull(matcher.matchHost(""))
        assertNull(matcher.matchHost("."))
        assertNull(matcher.matchHost("   "))
    }

    @Test
    fun `ip literal and cidr indicators match the right addresses only`() {
        val matcher = IocMatcher(
            listOf(
                ioc(IocType.IP, "203.0.113.9", category = ThreatCategory.CANDIRU_C2, severity = Severity.CRITICAL),
                ioc(IocType.CIDR, "198.51.100.0/24", category = ThreatCategory.ADINT),
            )
        )

        assertNotNull(matcher.matchIp("203.0.113.9"))
        assertNull(matcher.matchIp("203.0.113.10"))

        assertNotNull(matcher.matchIp("198.51.100.1"))
        assertNotNull(matcher.matchIp("198.51.100.255"))
        assertNull(matcher.matchIp("198.51.101.1"))
        assertNull(matcher.matchIp("198.51.99.255"))
    }

    @Test
    fun `cidr boundaries are exact for a slash-32 and a slash-0`() {
        val host = IocMatcher(listOf(ioc(IocType.CIDR, "192.0.2.7/32")))
        assertNotNull(host.matchIp("192.0.2.7"))
        assertNull(host.matchIp("192.0.2.8"))
        assertNull(host.matchIp("192.0.2.6"))

        val everything = IocMatcher(listOf(ioc(IocType.CIDR, "0.0.0.0/0")))
        assertNotNull(everything.matchIp("1.2.3.4"))
        assertNotNull(everything.matchIp("255.255.255.255"))
    }

    @Test
    fun `sha256 indicators require exact length and value`() {
        val hash = "255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8"
        val matcher = IocMatcher(listOf(ioc(IocType.SHA256, hash, category = ThreatCategory.CANDIRU_IMPLANT)))

        assertNotNull(matcher.matchHash(hash))
        assertNotNull(matcher.matchHash(hash.uppercase()))
        assertNull(matcher.matchHash(hash.dropLast(1)))
        assertNull(matcher.matchHash("not-a-hash"))
    }

    @Test
    fun `ipv4 parser rejects out-of-range and malformed input`() {
        assertNull(Ipv4Cidr.toLong("256.1.1.1"))
        assertNull(Ipv4Cidr.toLong("1.1.1"))
        assertNull(Ipv4Cidr.toLong("1.1.1.1.1"))
        assertNull(Ipv4Cidr.toLong("a.b.c.d"))
        assertNull(Ipv4Cidr.parse("1.1.1.1/33"))
        assertNull(Ipv4Cidr.parse("1.1.1.1"))
        assertNotNull(Ipv4Cidr.parse("10.0.0.0/8"))
    }

    @Test
    fun `matcher reports the number of distinct indicators it holds`() {
        val matcher = IocMatcher(
            listOf(
                ioc(IocType.DOMAIN, "a.com"),
                ioc(IocType.DOMAIN, "b.com"),
                ioc(IocType.HOST, "c.com"),
                ioc(IocType.IP, "1.2.3.4"),
                ioc(IocType.CIDR, "10.0.0.0/8"),
            )
        )
        assertEquals(5, matcher.size)
    }

    @Test
    fun `every indicator in the bundled asset parses and is reachable`() {
        // Guards against a hand-edit breaking the shipped file.
        val asset = java.io.File("src/main/assets/iocs.tsv")
        assertTrue("iocs.tsv must exist", asset.exists())

        val parsed = TsvIocLoader.parse(asset.readText())
        assertTrue("bundled set must not be empty", parsed.iocs.size > 20)
        assertEquals("bundled set must parse cleanly: ${parsed.problems}", emptyList<String>(), parsed.problems)
    }
}
