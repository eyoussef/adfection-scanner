package dev.adfection.scanner.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketsTest {

    /** Build a raw IPv4/UDP DNS query packet as the tun device would deliver it. */
    private fun ipv4UdpQuery(
        src: String = "10.111.222.5",
        dst: String = "10.111.222.1",
        srcPort: Int = 44321,
        dstPort: Int = 53,
        payload: ByteArray = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0),
    ): ByteArray {
        val srcBytes = Packets.addressFromString(src)!!
        val dstBytes = Packets.addressFromString(dst)!!

        val udp = ByteArray(8 + payload.size)
        udp[0] = ((srcPort shr 8) and 0xFF).toByte(); udp[1] = (srcPort and 0xFF).toByte()
        udp[2] = ((dstPort shr 8) and 0xFF).toByte(); udp[3] = (dstPort and 0xFF).toByte()
        val udpLen = 8 + payload.size
        udp[4] = ((udpLen shr 8) and 0xFF).toByte(); udp[5] = (udpLen and 0xFF).toByte()
        payload.copyInto(udp, 8)

        val ip = ByteArray(20 + udp.size)
        ip[0] = 0x45
        val total = 20 + udp.size
        ip[2] = ((total shr 8) and 0xFF).toByte(); ip[3] = (total and 0xFF).toByte()
        ip[8] = 64
        ip[9] = Packets.PROTO_UDP.toByte()
        srcBytes.copyInto(ip, 12); dstBytes.copyInto(ip, 16)
        udp.copyInto(ip, 20)
        return ip
    }

    @Test
    fun `parse an IPv4 UDP DNS query`() {
        val raw = ipv4UdpQuery()
        val parsed = Packets.parse(raw, raw.size)

        assertNotNull(parsed)
        assertEquals(4, parsed!!.version)
        assertEquals(Packets.PROTO_UDP, parsed.protocol)
        assertEquals(44321, parsed.srcPort)
        assertEquals(53, parsed.dstPort)
        assertTrue(parsed.isDnsQuery)
        assertEquals(12, parsed.payload.size)
    }

    @Test
    fun `parse rejects truncated and malformed packets`() {
        val raw = ipv4UdpQuery()
        for (cut in 0 until raw.size) {
            Packets.parse(raw, cut) // must never throw
        }
        assertNull(Packets.parse(ByteArray(0), 0))
        assertNull(Packets.parse(ByteArray(10), 10))
    }

    @Test
    fun `parse ignores a transport protocol we do not handle`() {
        val raw = ipv4UdpQuery()
        raw[9] = 47 // GRE
        assertNull(Packets.parse(raw, raw.size))
    }

    @Test
    fun `parse ignores non-first fragments`() {
        val raw = ipv4UdpQuery()
        raw[6] = 0x00; raw[7] = 0x10 // fragment offset = 2
        assertNull(Packets.parse(raw, raw.size))
    }

    @Test
    fun `parse rejects an IPv4 header with an impossible IHL`() {
        val raw = ipv4UdpQuery()
        raw[0] = 0x43 // IHL = 3 -> 12 bytes, below the 20-byte minimum
        assertNull(Packets.parse(raw, raw.size))
    }

    @Test
    fun `parse an IPv6 UDP query`() {
        val src = Packets.addressFromString("fd00:adfe:c710::5")!!
        val dst = Packets.addressFromString("fd00:adfe:c710::1")!!
        val payload = ByteArray(12)

        val udp = ByteArray(8 + payload.size)
        udp[0] = 0xD4.toByte(); udp[1] = 0x31.toByte() // 54321
        udp[2] = 0x00; udp[3] = 0x35 // 53
        val udpLen = 8 + payload.size
        udp[4] = ((udpLen shr 8) and 0xFF).toByte(); udp[5] = (udpLen and 0xFF).toByte()

        val ip = ByteArray(40 + udp.size)
        ip[0] = 0x60
        ip[4] = 0; ip[5] = udp.size.toByte()
        ip[6] = Packets.PROTO_UDP.toByte()
        ip[7] = 64
        src.copyInto(ip, 8); dst.copyInto(ip, 24)
        udp.copyInto(ip, 40)

        val parsed = Packets.parse(ip, ip.size)
        assertNotNull(parsed)
        assertEquals(6, parsed!!.version)
        assertEquals(54321, parsed.srcPort)
        assertTrue(parsed.isDnsQuery)
    }

    @Test
    fun `buildUdp produces a packet that parses back with matching ports and payload`() {
        val payload = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
        val src = Packets.addressFromString("10.111.222.1")!!
        val dst = Packets.addressFromString("10.111.222.5")!!

        val packet = Packets.buildUdp(4, src, 53, dst, 44321, payload)
        assertNotNull(packet)

        val parsed = Packets.parse(packet!!, packet.size)!!
        assertEquals(Packets.PROTO_UDP, parsed.protocol)
        assertEquals(53, parsed.srcPort)
        assertEquals(44321, parsed.dstPort)
        assertTrue(payload.contentEquals(parsed.payload))
    }

    @Test
    fun `buildUdp computes a UDP checksum that verifies to zero`() {
        val payload = "hello-dns".toByteArray()
        val src = Packets.addressFromString("10.111.222.1")!!
        val dst = Packets.addressFromString("10.111.222.5")!!

        val packet = Packets.buildUdp(4, src, 53, dst, 40000, payload)!!
        // UDP header starts at byte 20 for IPv4.
        val udpChecksum = ((packet[26].toInt() and 0xFF) shl 8) or (packet[27].toInt() and 0xFF)
        assertTrue("expected a non-zero checksum", udpChecksum != 0)

        // Recompute over the emitted bytes: a correct checksum sums (with the field included) to
        // 0xFFFF in ones-complement arithmetic.
        var sum = 0L
        sum += (packet[12].toInt() and 0xFF) shl 8; sum += packet[13].toInt() and 0xFF
        sum += (packet[14].toInt() and 0xFF) shl 8; sum += packet[15].toInt() and 0xFF
        sum += (packet[16].toInt() and 0xFF) shl 8; sum += packet[17].toInt() and 0xFF
        sum += (packet[18].toInt() and 0xFF) shl 8; sum += packet[19].toInt() and 0xFF
        sum += Packets.PROTO_UDP.toLong()
        sum += (payload.size + 8).toLong()
        var i = 20
        while (i + 1 < packet.size) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < packet.size) sum += (packet[i].toInt() and 0xFF) shl 8
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFFL, sum)
    }

    @Test
    fun `buildUdp for IPv6 produces a parseable packet`() {
        val payload = ByteArray(12)
        val src = Packets.addressFromString("fd00:adfe:c710::1")!!
        val dst = Packets.addressFromString("fd00:adfe:c710::5")!!

        val packet = Packets.buildUdp(6, src, 53, dst, 40000, payload)
        assertNotNull(packet)
        val parsed = Packets.parse(packet!!, packet.size)!!
        assertEquals(6, parsed.version)
        assertEquals(53, parsed.srcPort)
        assertEquals(40000, parsed.dstPort)
    }

    @Test
    fun `buildUdp refuses a mismatched address family`() {
        val v4 = Packets.addressFromString("10.0.0.1")!!
        val v6 = Packets.addressFromString("fd00::1")!!
        assertNull(Packets.buildUdp(4, v4, 53, v6, 40000, ByteArray(4)))
    }

    @Test
    fun `address helpers never throw on garbage`() {
        assertNull(Packets.addressFromString("not-an-address"))
        assertEquals("<invalid>", Packets.addressToString(byteArrayOf(1, 2, 3)))
    }
}
