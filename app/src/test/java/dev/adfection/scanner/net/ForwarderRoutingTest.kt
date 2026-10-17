package dev.adfection.scanner.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Forwarder-level tests. These exercise the *routing contract* of the sinkhole — that a reply
 * reaches the client that asked, with the transaction ID that client used — without needing a tun
 * device or a live socket.
 *
 * The logic under test mirrors [AdfectionVpnService.forward]/[AdfectionVpnService.deliverUpstream]:
 * the service owns a private ID space so two clients using the same ID cannot be confused.
 */
class ForwarderRoutingTest {

    /** Minimal stand-in for the service's pending-query map and ID allocator. */
    private class Router {
        data class Awaiting(val clientId: Int, val clientPort: Int)

        val pending = HashMap<Int, Awaiting>()
        private var counter = 1

        fun nextId(): Int {
            repeat(1024) {
                val candidate = counter++ and 0xFFFF
                if (!pending.containsKey(candidate)) return candidate
            }
            return counter and 0xFFFF
        }

        /** Mirrors forward(): rewrite the client's ID to one we own, remember the mapping. */
        fun forward(clientId: Int, clientPort: Int, payload: ByteArray): ByteArray? {
            val ownId = nextId()
            val outbound = Dns.rewriteId(payload, payload.size, ownId) ?: return null
            pending[ownId] = Awaiting(clientId, clientPort)
            return outbound
        }

        /** Mirrors deliverUpstream(): look up by our ID, restore the client's ID. */
        fun deliver(reply: ByteArray): Pair<ByteArray, Awaiting>? {
            val ownId = ((reply[0].toInt() and 0xFF) shl 8) or (reply[1].toInt() and 0xFF)
            val awaiting = pending.remove(ownId) ?: return null
            val restored = Dns.rewriteId(reply, reply.size, awaiting.clientId) ?: return null
            return restored to awaiting
        }
    }

    private fun query(id: Int, name: String): ByteArray {
        val labels = name.split('.')
        val qname = ByteArray(labels.sumOf { it.length + 1 } + 1)
        var i = 0
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            qname[i] = bytes.size.toByte(); i++
            bytes.copyInto(qname, i); i += bytes.size
        }
        qname[i] = 0

        val out = ByteArray(12 + qname.size + 4)
        out[0] = ((id shr 8) and 0xFF).toByte(); out[1] = (id and 0xFF).toByte()
        out[5] = 0x01 // QDCOUNT = 1
        qname.copyInto(out, 12)

        // QTYPE = A(1), QCLASS = IN(1). Without these the question is untyped and the sinkhole
        // correctly declines to synthesise an A record for it.
        val at = 12 + qname.size
        out[at] = 0x00; out[at + 1] = 0x01
        out[at + 2] = 0x00; out[at + 3] = 0x01
        return out
    }

    /**
     * Build an upstream reply for [question].
     *
     * @param wireId the ID the *service* sent upstream; this is what the upstream server echoes
     *               back, and therefore what `deliver` must look the pending query up by.
     */
    private fun replyFor(question: ByteArray, answer: String, wireId: Int): ByteArray {
        val parsed = Dns.parseQuery(question, question.size)!!
        val response = Dns.buildSinkholeResponse(parsed, answer)
        return Dns.rewriteId(response, response.size, wireId)!!
    }

    private fun wireIdOf(packet: ByteArray): Int =
        ((packet[0].toInt() and 0xFF) shl 8) or (packet[1].toInt() and 0xFF)

    @Test
    fun `two clients using the same transaction id both get their own answer`() {
        val router = Router()

        // Both devices coincidentally pick ID 0x4242 (perfectly legal and common on a LAN with
        // many clients behind one resolver).
        val q1 = query(0x4242, "one.example")
        val q2 = query(0x4242, "two.example")

        val out1 = router.forward(0x4242, 1111, q1)
        val out2 = router.forward(0x4242, 2222, q2)
        assertNotNull(out1); assertNotNull(out2)

        val wireId1 = wireIdOf(out1!!)
        val wireId2 = wireIdOf(out2!!)
        // The wire IDs must differ, or the two pendings would collide on the same key.
        assertTrue("outbound IDs must be distinct", wireId1 != wireId2)

        // Reply to the first query arrives first, carrying our wire ID.
        val r1 = router.deliver(replyFor(q1, "203.0.113.1", wireId1))
        assertNotNull(r1)
        assertEquals(1111, r1!!.second.clientPort)
        assertEquals(0x4242, wireIdOf(r1.first)) // client's own ID restored

        // Then the second — it must still be routed, and to the right client.
        val r2 = router.deliver(replyFor(q2, "203.0.113.2", wireId2))
        assertNotNull(r2)
        assertEquals(2222, r2!!.second.clientPort)
        assertEquals(0x4242, wireIdOf(r2.first))

        // Both pendings are consumed; a duplicate reply must be dropped, not misrouted.
        assertNull(router.deliver(replyFor(q1, "203.0.113.1", wireId1)))
    }

    @Test
    fun `a reply for an unknown transaction id is dropped`() {
        val router = Router()
        router.forward(7, 3333, query(7, "x.example"))

        val stranger = replyFor(query(999, "unknown.example"), "198.51.100.1", 0x7FFF)
        assertNull(router.deliver(stranger))
    }

    @Test
    fun `allocator does not hand out an id that is still in flight`() {
        val router = Router()

        val used = HashSet<Int>()
        repeat(500) {
            val out = router.forward(it, 1000 + it, query(it, "host$it.example"))!!
            assertTrue("id issued while still in flight", used.add(wireIdOf(out)))
        }
    }

    @Test
    fun `the client's answer is restored byte-for-byte apart from the id it asked with`() {
        val router = Router()
        val q = query(0x0A0B, "restore.example")
        val out = router.forward(0x0A0B, 4444, q)!!

        val delivered = router.deliver(replyFor(q, "203.0.113.9", wireIdOf(out)))!!
        assertEquals(0x0A0B, wireIdOf(delivered.first))
        // The answer record survives the round trip.
        assertEquals(listOf("203.0.113.9"), Dns.extractAnswerAddresses(delivered.first, delivered.first.size))
    }
}
