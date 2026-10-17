package dev.adfection.scanner.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Codec tests. These run on the JVM with no Android dependency, which is why [Dns] and [Packets]
 * deliberately use `java.net.InetAddress` only (no `android.util`).
 */
class DnsCodecTest {

    /** Build a minimal DNS query for `name`/`type` with the given transaction id. */
    private fun buildQuery(id: Int, name: String, type: Int = Dns.TYPE_A): ByteArray {
        val labels = name.trim('.').split('.')
        val qname = ByteArray(labels.sumOf { it.length + 1 } + 1)
        var i = 0
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            qname[i] = bytes.size.toByte(); i++
            bytes.copyInto(qname, i); i += bytes.size
        }
        qname[i] = 0

        val out = ByteArray(12 + qname.size + 4)
        out[0] = ((id shr 8) and 0xFF).toByte()
        out[1] = (id and 0xFF).toByte()
        out[2] = 0x01 // RD
        out[3] = 0x00
        out[5] = 0x01 // QDCOUNT = 1
        qname.copyInto(out, 12)
        val at = 12 + qname.size
        out[at] = ((type shr 8) and 0xFF).toByte()
        out[at + 1] = (type and 0xFF).toByte()
        out[at + 3] = 0x01 // class IN
        return out
    }

    @Test
    fun `parse a well-formed query`() {
        val packet = buildQuery(0x1234, "noas.mtrtb.com")
        val query = Dns.parseQuery(packet, packet.size)

        assertNotNull(query)
        assertEquals(0x1234, query!!.id)
        assertEquals("noas.mtrtb.com", query.question.name)
        assertEquals(Dns.TYPE_A, query.question.type)
        assertEquals(Dns.CLASS_IN, query.question.clazz)
    }

    @Test
    fun `parse trims and lower-cases the queried name`() {
        val packet = buildQuery(1, "NoAs.MTRTB.CoM")
        assertEquals("noas.mtrtb.com", Dns.parseQuery(packet, packet.size)!!.question.name)
    }

    @Test
    fun `malformed and truncated packets return null instead of throwing`() {
        assertNull(Dns.parseQuery(ByteArray(0), 0))
        assertNull(Dns.parseQuery(ByteArray(4), 4))

        val packet = buildQuery(7, "example.com")
        // Every truncation point must be survivable.
        for (cut in 0 until packet.size) {
            Dns.parseQuery(packet, cut)
        }
        assertNull(Dns.parseQuery(packet, 12)) // header only, no question
    }

    @Test
    fun `compression pointer cycles are rejected rather than looping`() {
        // Craft a name whose first two bytes are a pointer back to itself.
        val packet = ByteArray(12 + 6)
        packet[5] = 0x01 // QDCOUNT = 1
        packet[12] = 0xC0.toByte()
        packet[13] = 0x0C // pointer to offset 12 == itself
        packet[14] = 0x00; packet[15] = 0x01 // type A
        packet[16] = 0x00; packet[17] = 0x01 // class IN

        assertNull(Dns.parseQuery(packet, packet.size))
    }

    @Test
    fun `sinkhole response echoes the question and answers with the sinkhole address`() {
        val query = buildQuery(0xBEEF, "noas.mtrtb.com").let { Dns.parseQuery(it, it.size) }!!
        val response = Dns.buildSinkholeResponse(query, "0.0.0.0")

        assertEquals(0xBEEF, ((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF))
        assertEquals(0x8180, ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF))
        assertEquals(1, ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)) // QDCOUNT
        assertEquals(1, ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)) // ANCOUNT

        // The trailing 4 bytes are the A record RDLENGTH + address.
        val tail = response.takeLast(4)
        assertEquals(listOf(0, 0, 0, 0), tail.map { it.toInt() and 0xFF })
    }

    @Test
    fun `nxdomain response sets rcode 3 and carries no answers`() {
        val query = buildQuery(0x0101, "fearevolve.com").let { Dns.parseQuery(it, it.size) }!!
        val response = Dns.buildNxDomain(query)

        assertEquals(0x8183, ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF))
        assertEquals(0, ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)) // ANCOUNT
    }

    @Test
    fun `formerr response preserves the transaction id and sets rcode 1`() {
        val response = Dns.buildFormErr(byteArrayOf(0xAB.toByte(), 0xCD.toByte()), 2)
        assertNotNull(response)
        assertEquals(0xABCD, ((response!![0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF))
        assertEquals(0x8181, ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF))
    }

    @Test
    fun `rewriteId patches only the transaction id`() {
        val original = buildQuery(0x1111, "example.com")
        val rewritten = Dns.rewriteId(original, original.size, 0x2222)

        assertNotNull(rewritten)
        assertEquals(0x2222, ((rewritten!![0].toInt() and 0xFF) shl 8) or (rewritten[1].toInt() and 0xFF))
        // Everything after the id is untouched.
        assertTrue(original.copyOfRange(2, original.size).contentEquals(rewritten.copyOfRange(2, rewritten.size)))
    }

    @Test
    fun `rewriteId rejects a datagram too short to be a DNS message`() {
        assertNull(Dns.rewriteId(ByteArray(6), 6, 1))
    }

    @Test
    fun `extractAnswerAddresses reads an A record out of a response`() {
        val query = buildQuery(9, "noas.mtrtb.com").let { Dns.parseQuery(it, it.size) }!!
        val response = Dns.buildSinkholeResponse(query, "203.0.113.77")

        val addresses = Dns.extractAnswerAddresses(response, response.size)
        assertEquals(listOf("203.0.113.77"), addresses)
    }

    @Test
    fun `extractAnswerAddresses returns empty for a response with no answers`() {
        val query = buildQuery(9, "noas.mtrtb.com").let { Dns.parseQuery(it, it.size) }!!
        val response = Dns.buildNxDomain(query)
        assertEquals(emptyList<String>(), Dns.extractAnswerAddresses(response, response.size))
    }

    /**
     * The SERVFAIL reply is what stops a dead upstream from turning into a silent hang. If this
     * response is malformed, the stub resolver ignores it and the user waits out a full timeout —
     * which is the symptom this code exists to prevent.
     */
    @Test
    fun `buildServFail echoes the query and sets RCODE 2`() {
        val query = buildQuery(0x4242, "example.com").let { Dns.parseQuery(it, it.size) }!!
        val response = Dns.buildServFail(query)

        // Same transaction id, QR set, RCODE 2.
        assertEquals(0x4242, ((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF))
        val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
        assertEquals(0x8000, flags and 0x8000)
        assertEquals(2, flags and 0x000F)
        // No answer records, and the question is present so the client can match it.
        assertEquals(0, ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF))
        assertEquals(1, ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF))
        assertNotNull(Dns.parseQuery(response, response.size))
    }

    @Test
    fun `buildServFail from raw bytes parses the query itself`() {
        val raw = buildQuery(0x7777, "www.example.org")
        val response = Dns.buildServFail(raw, raw.size)

        assertNotNull(response)
        assertEquals(0x7777, ((response!![0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF))
    }

    @Test
    fun `buildServFail from raw bytes rejects a non-query`() {
        assertNull(Dns.buildServFail(ByteArray(4), 4))
    }
}
