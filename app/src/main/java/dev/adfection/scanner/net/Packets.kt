package dev.adfection.scanner.net

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * IPv4/IPv6 + UDP/TCP packet parsing and construction for the DNS sinkhole.
 *
 * Why hand-rolled: the VPN service receives raw IP packets and must synthesise replies that the
 * kernel's stub resolver accepts. Using a socket per query would be simpler but cannot answer a
 * query that arrived on the tun from the tun's own address range without NAT hacks.
 *
 * Correctness rules enforced here:
 *  - every parser returns null instead of throwing on truncated/malformed input;
 *  - IPv6 is handled natively (modern Android devices prefer IPv6 DNS, and a v4-only sinkhole
 *    silently fails open on those networks);
 *  - UDP checksums are computed for both families (mandatory for IPv6, verified in practice for v4);
 *  - a checksum that computes to zero is emitted as 0xFFFF, per RFC 768 for UDP.
 */
object Packets {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val PORT_DNS = 53

    /** A parsed transport packet, restricted to what the sinkhole needs. */
    data class Parsed(
        val version: Int,
        val protocol: Int,
        val srcAddress: ByteArray,
        val dstAddress: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val payload: ByteArray,
        /** TCP sequence number; 0 for UDP. */
        val tcpSeq: Long = 0,
        val tcpFlags: Int = 0,
    ) {
        val isUdp: Boolean get() = protocol == PROTO_UDP
        val isDnsQuery: Boolean get() = isUdp && dstPort == PORT_DNS && payload.isNotEmpty()
        val isTcpSyn: Boolean get() = protocol == PROTO_TCP && (tcpFlags and FLAG_SYN) != 0 && (tcpFlags and FLAG_ACK) == 0

        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = System.identityHashCode(this)
    }

    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    /**
     * Parse an IP packet captured from the tun device.
     * @return null when the packet is not IPv4/IPv6, is truncated, or uses a transport we ignore.
     */
    fun parse(data: ByteArray, length: Int): Parsed? {
        if (length < 20) return null
        return when ((data[0].toInt() and 0xF0) shr 4) {
            4 -> parseV4(data, length)
            6 -> parseV6(data, length)
            else -> null
        }
    }

    private fun parseV4(data: ByteArray, length: Int): Parsed? {
        val ihl = (data[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > length) return null

        val totalLength = readShort(data, 2)
        if (totalLength < ihl || totalLength > length) return null

        val protocol = data[9].toInt() and 0xFF
        if (protocol != PROTO_UDP && protocol != PROTO_TCP) return null

        val fragmentField = readShort(data, 6)
        // Drop non-first fragments: without reassembly their payload is meaningless.
        if ((fragmentField and 0x1FFF) != 0) return null

        // Header checksum is intentionally not verified: the kernel already validated it before
        // delivering to the tun, and verifying costs cycles on every packet.
        val src = data.copyOfRange(12, 16)
        val dst = data.copyOfRange(16, 20)

        return parseTransport(data, length, totalLength, ihl, 4, protocol, src, dst)
    }

    private fun parseV6(data: ByteArray, length: Int): Parsed? {
        if (length < 40) return null
        val payloadLength = readShort(data, 4)
        val nextHeader = data[6].toInt() and 0xFF
        // Extension headers are not expected from a stub resolver; anything but UDP/TCP is ignored.
        if (nextHeader != PROTO_UDP && nextHeader != PROTO_TCP) return null
        if (40 + payloadLength > length) return null

        val src = data.copyOfRange(8, 24)
        val dst = data.copyOfRange(24, 40)

        return parseTransport(data, length, 40 + payloadLength, 40, 6, nextHeader, src, dst)
    }

    private fun parseTransport(
        data: ByteArray,
        length: Int,
        declaredEnd: Int,
        transportOffset: Int,
        version: Int,
        protocol: Int,
        src: ByteArray,
        dst: ByteArray,
    ): Parsed? {
        val end = minOf(declaredEnd, length)
        if (transportOffset + 8 > end) return null

        val srcPort = readShort(data, transportOffset)
        val dstPort = readShort(data, transportOffset + 2)

        return when (protocol) {
            PROTO_UDP -> {
                val udpLength = readShort(data, transportOffset + 4)
                if (udpLength < 8 || transportOffset + udpLength > end) return null
                Parsed(
                    version = version,
                    protocol = protocol,
                    srcAddress = src,
                    dstAddress = dst,
                    srcPort = srcPort,
                    dstPort = dstPort,
                    payload = data.copyOfRange(transportOffset + 8, transportOffset + udpLength),
                )
            }

            PROTO_TCP -> {
                val dataOffset = ((data[transportOffset + 12].toInt() and 0xF0) shr 4) * 4
                if (dataOffset < 20 || transportOffset + dataOffset > end) return null
                val seq = readInt(data, transportOffset + 4).toLong() and 0xFFFFFFFFL
                val flags = data[transportOffset + 13].toInt() and 0xFF
                Parsed(
                    version = version,
                    protocol = protocol,
                    srcAddress = src,
                    dstAddress = dst,
                    srcPort = srcPort,
                    dstPort = dstPort,
                    payload = data.copyOfRange(transportOffset + dataOffset, end),
                    tcpSeq = seq,
                    tcpFlags = flags,
                )
            }

            else -> null
        }
    }

    /**
     * Build a complete IPv4/IPv6 UDP packet carrying [payload].
     *
     * @param version 4 or 6, matching the packet this reply is answering.
     */
    fun buildUdp(
        version: Int,
        srcAddress: ByteArray,
        srcPort: Int,
        dstAddress: ByteArray,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray? {
        val udpLength = 8 + payload.size
        val udp = ByteArray(udpLength)
        writeShort(udp, 0, srcPort)
        writeShort(udp, 2, dstPort)
        writeShort(udp, 4, udpLength)
        writeShort(udp, 6, 0)
        payload.copyInto(udp, 8)
        val udpChecksum = udpChecksum(version, srcAddress, dstAddress, udp)
        writeShort(udp, 6, udpChecksum)

        return when (version) {
            4 -> buildV4Header(srcAddress, dstAddress, PROTO_UDP, udp.size)?.let { it + udp }
            6 -> buildV6Header(srcAddress, dstAddress, PROTO_UDP, udp.size)?.let { it + udp }
            else -> null
        }
    }

    /** Build a TCP RST+ACK to close a connection the sinkhole will not proxy (DNS over TCP). */
    fun buildTcpReset(parsed: Parsed, srcAddress: ByteArray, dstAddress: ByteArray): ByteArray? {
        val header = ByteArray(20)
        writeShort(header, 0, parsed.dstPort)
        writeShort(header, 2, parsed.srcPort)
        writeInt(header, 4, 0) // seq
        writeInt(header, 8, (parsed.tcpSeq + 1).toInt()) // ack
        header[12] = (5 shl 4).toByte() // data offset 20 bytes, no options
        header[13] = (FLAG_RST or FLAG_ACK).toByte()
        writeShort(header, 14, 0) // window
        writeShort(header, 16, 0) // checksum placeholder
        writeShort(header, 18, 0) // urgent pointer

        val checksum = tcpChecksum(parsed.version, srcAddress, dstAddress, header)
        writeShort(header, 16, checksum)

        return when (parsed.version) {
            4 -> buildV4Header(srcAddress, dstAddress, PROTO_TCP, header.size)?.let { it + header }
            6 -> buildV6Header(srcAddress, dstAddress, PROTO_TCP, header.size)?.let { it + header }
            else -> null
        }
    }

    private fun buildV4Header(src: ByteArray, dst: ByteArray, protocol: Int, payloadLength: Int): ByteArray? {
        if (src.size != 4 || dst.size != 4) return null
        val header = ByteArray(20)
        header[0] = 0x45 // version 4, IHL 5
        header[1] = 0 // DSCP/ECN
        writeShort(header, 2, 20 + payloadLength)
        writeShort(header, 4, 0) // identification
        writeShort(header, 6, 0x4000) // don't fragment
        header[8] = 64 // TTL
        header[9] = protocol.toByte()
        src.copyInto(header, 12)
        dst.copyInto(header, 16)
        writeShort(header, 10, internetChecksum(header, 0, 20))
        return header
    }

    private fun buildV6Header(src: ByteArray, dst: ByteArray, nextHeader: Int, payloadLength: Int): ByteArray? {
        if (src.size != 16 || dst.size != 16) return null
        val header = ByteArray(40)
        header[0] = 0x60
        writeShort(header, 4, payloadLength)
        header[6] = nextHeader.toByte()
        header[7] = 64 // hop limit
        src.copyInto(header, 8)
        dst.copyInto(header, 24)
        return header
    }

    private fun udpChecksum(version: Int, src: ByteArray, dst: ByteArray, udp: ByteArray): Int {
        val sum = pseudoHeaderSum(version, src, dst, PROTO_UDP, udp.size) + onesComplementSum(udp, 0, udp.size)
        val folded = fold(sum)
        return if (folded == 0) 0xFFFF else folded
    }

    private fun tcpChecksum(version: Int, src: ByteArray, dst: ByteArray, tcp: ByteArray): Int {
        val sum = pseudoHeaderSum(version, src, dst, PROTO_TCP, tcp.size) + onesComplementSum(tcp, 0, tcp.size)
        return fold(sum)
    }

    private fun pseudoHeaderSum(version: Int, src: ByteArray, dst: ByteArray, protocol: Int, length: Int): Long {
        var sum = 0L
        sum += onesComplementSum(src, 0, src.size)
        sum += onesComplementSum(dst, 0, dst.size)
        sum += (length.toLong() and 0xFFFF)
        sum += (protocol.toLong() and 0xFF)
        return sum
    }

    private fun onesComplementSum(data: ByteArray, offset: Int, length: Int): Long {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        return sum
    }

    private fun fold(sum: Long): Int {
        var s = sum
        while ((s shr 16) != 0L) s = (s and 0xFFFF) + (s shr 16)
        return (s.inv() and 0xFFFF).toInt()
    }

    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int = fold(onesComplementSum(data, offset, length))

    private fun readShort(data: ByteArray, at: Int): Int =
        ((data[at].toInt() and 0xFF) shl 8) or (data[at + 1].toInt() and 0xFF)

    private fun readInt(data: ByteArray, at: Int): Int =
        ((data[at].toInt() and 0xFF) shl 24) or
            ((data[at + 1].toInt() and 0xFF) shl 16) or
            ((data[at + 2].toInt() and 0xFF) shl 8) or
            (data[at + 3].toInt() and 0xFF)

    private fun writeShort(dst: ByteArray, at: Int, value: Int) {
        dst[at] = ((value shr 8) and 0xFF).toByte()
        dst[at + 1] = (value and 0xFF).toByte()
    }

    private fun writeInt(dst: ByteArray, at: Int, value: Int) {
        dst[at] = ((value shr 24) and 0xFF).toByte()
        dst[at + 1] = ((value shr 16) and 0xFF).toByte()
        dst[at + 2] = ((value shr 8) and 0xFF).toByte()
        dst[at + 3] = (value and 0xFF).toByte()
    }

    /** Render an address for logging. Never throws for a wrong-length array. */
    fun addressToString(address: ByteArray): String = runCatching { InetAddress.getByAddress(address).hostAddress }.getOrNull() ?: "<invalid>"

    /** Address bytes for a literal, or null when unparseable. */
    fun addressFromString(literal: String): ByteArray? =
        runCatching { InetAddress.getByName(literal.trim()).address }.getOrNull()

    /** Little helper for tests and debugging: decode a built packet back into fields. */
    fun describe(packet: ByteArray): String {
        val buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
        return when ((packet[0].toInt() and 0xF0) shr 4) {
            4 -> {
                val ihl = (packet[0].toInt() and 0x0F) * 4
                val proto = packet[9].toInt() and 0xFF
                buf.position(ihl)
                val sp = buf.short.toInt() and 0xFFFF
                val dp = buf.short.toInt() and 0xFFFF
                "IPv4 $proto $sp->$dp"
            }

            6 -> {
                val proto = packet[6].toInt() and 0xFF
                buf.position(40)
                val sp = buf.short.toInt() and 0xFFFF
                val dp = buf.short.toInt() and 0xFFFF
                "IPv6 $proto $sp->$dp"
            }

            else -> "unknown"
        }
    }
}
