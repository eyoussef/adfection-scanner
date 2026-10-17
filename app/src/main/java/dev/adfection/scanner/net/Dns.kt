package dev.adfection.scanner.net

import java.net.InetAddress

/**
 * Minimal DNS message codec: parses a query, builds a synthesised response, and rewrites an
 * upstream response's transaction ID so the on-device stub resolver accepts it.
 *
 * Scope is deliberately narrow — this is a sinkhole resolver, not a full DNS server:
 *  - the question section is parsed; additional records (EDNS0 OPT) are ignored on parse and
 *    never emitted in synthesised responses;
 *  - name decompression pointers are followed with both a hop budget and a strict
 *    backwards-only rule, because a packet that points at itself would otherwise spin forever;
 *  - every entry point validates its `length` argument against the array it was handed and
 *    returns null/empty rather than throwing.
 *
 * All multi-byte fields are network byte order (big endian).
 */
object Dns {

    const val MAX_NAME_LENGTH = 255
    const val TYPE_A = 1
    const val TYPE_CNAME = 5
    const val TYPE_AAAA = 28
    const val CLASS_IN = 1
    const val RCODE_NXDOMAIN = 3
    const val RCODE_FORMERR = 1

    private const val HEADER_SIZE = 12
    private const val MAX_HOPS = 16
    private const val MAX_LABELS = 128

    /** A parsed question. */
    data class Question(val name: String, val type: Int, val clazz: Int)

    /** A parsed DNS query header + question. */
    data class Query(
        val id: Int,
        val flags: Int,
        val question: Question,
    ) {
        val isResponse: Boolean get() = (flags and 0x8000) != 0
    }

    /** A decoded name plus the offset immediately after it in the original byte stream. */
    private data class NameResult(val name: String, val end: Int)

    /**
     * Parse a DNS query datagram.
     * @return null when the packet is truncated, malformed, or not a single-question query.
     */
    fun parseQuery(data: ByteArray, length: Int): Query? {
        if (length < HEADER_SIZE || length > data.size) return null

        val id = u16(data, 0)
        val flags = u16(data, 2)
        val qdCount = u16(data, 4)
        if (qdCount < 1) return null

        val name = readName(data, length, HEADER_SIZE) ?: return null
        val at = name.end
        if (at + 4 > length) return null

        return Query(
            id = id,
            flags = flags,
            question = Question(
                name = name.name,
                type = u16(data, at),
                clazz = u16(data, at + 2),
            ),
        )
    }

    /**
     * Decode a (possibly compressed) domain name starting at [startPos].
     *
     * A compression pointer must point strictly backwards. That is what RFC 1035 permits, and
     * enforcing it makes pointer cycles impossible rather than merely bounded — a self-referential
     * or forward pointer is rejected outright.
     *
     * @return the lower-cased name and the offset after the name as it appeared in the stream, or
     *         null if the name is malformed, over-long, or runs past [limit].
     */
    private fun readName(data: ByteArray, limit: Int, startPos: Int): NameResult? {
        val labels = ArrayList<String>(4)
        var pos = startPos
        var hops = 0
        var end = -1

        while (true) {
            if (pos >= limit) return null
            val len = data[pos].toInt() and 0xFF

            when {
                len == 0 -> {
                    if (end < 0) end = pos + 1
                    break
                }

                (len and 0xC0) == 0xC0 -> {
                    if (pos + 1 >= limit) return null
                    val pointer = ((len and 0x3F) shl 8) or (data[pos + 1].toInt() and 0xFF)
                    if (end < 0) end = pos + 2
                    // Strictly backwards: rejects self-references and forward loops.
                    if (pointer >= pos) return null
                    if (++hops > MAX_HOPS) return null
                    pos = pointer
                }

                (len and 0xC0) != 0 -> return null // reserved label type

                else -> {
                    if (pos + 1 + len > limit) return null
                    labels.add(String(data, pos + 1, len, Charsets.US_ASCII))
                    if (labels.size > MAX_LABELS) return null
                    pos += 1 + len
                }
            }
        }

        val name = labels.joinToString(".")
        if (name.length > MAX_NAME_LENGTH) return null
        return NameResult(name.lowercase(), end)
    }

    /**
     * Build a sinkhole response: same question, and an A record pointing at [sinkholeAddress] when
     * the query was for A. AAAA queries get an empty NOERROR answer so the client does not fall
     * back to IPv6 and bypass the sinkhole.
     */
    fun buildSinkholeResponse(query: Query, sinkholeAddress: String, ttlSeconds: Int = 60): ByteArray {
        val wantA = query.question.type == TYPE_A
        return build(
            id = query.id,
            flags = 0x8180, // QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
            answerCount = if (wantA) 1 else 0,
            question = query.question,
            answerBytes = if (wantA) encodeA(query.question.name, sinkholeAddress, ttlSeconds) else ByteArray(0),
        )
    }

    /** Build an NXDOMAIN response for a blocked name (no answer records). */
    fun buildNxDomain(query: Query): ByteArray = build(
        id = query.id,
        flags = 0x8183, // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        answerCount = 0,
        question = query.question,
        answerBytes = ByteArray(0),
    )

    /** Build a FORMERR response for a packet we could not parse far enough to use. */
    fun buildFormErr(data: ByteArray, length: Int): ByteArray? {
        if (length < 2 || length > data.size) return null
        val out = ByteArray(HEADER_SIZE)
        writeShort(out, 0, u16(data, 0))
        writeShort(out, 2, 0x8181) // QR=1, RD=1, RA=1, RCODE=1 (FORMERR)
        // All section counts stay zero.
        return out
    }

    /**
     * Build a SERVFAIL response from a query we forwarded but could not get an answer for.
     *
     * Better than dropping the query: the stub resolver fails immediately instead of retrying for
     * seconds, and a browser shows an error rather than hanging. The question is echoed back so the
     * response still matches what the client asked.
     */
    fun buildServFail(query: Query): ByteArray = build(
        id = query.id,
        flags = 0x8182, // QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
        answerCount = 0,
        question = query.question,
        answerBytes = ByteArray(0),
    )

    /** Build a SERVFAIL when only the raw datagram is available (used on the forward-failure path). */
    fun buildServFail(data: ByteArray, length: Int): ByteArray? {
        val query = parseQuery(data, length) ?: return null
        return buildServFail(query)
    }

    /**
     * Rewrite the transaction ID of an upstream response so the stub resolver matches it to the
     * pending query. Returns null when the datagram is too short to contain a header.
     */
    fun rewriteId(data: ByteArray, length: Int, newId: Int): ByteArray? {
        if (length < HEADER_SIZE || length > data.size) return null
        val copy = data.copyOf(length)
        copy[0] = ((newId shr 8) and 0xFF).toByte()
        copy[1] = (newId and 0xFF).toByte()
        return copy
    }

    /** Extract every A/AAAA answer address from a response, for logging and IP-side matching. */
    fun extractAnswerAddresses(data: ByteArray, length: Int): List<String> {
        if (length < HEADER_SIZE || length > data.size) return emptyList()

        val questionCount = u16(data, 4)
        val answerCount = u16(data, 6)
        var pos = HEADER_SIZE

        repeat(questionCount) {
            val name = readName(data, length, pos) ?: return emptyList()
            pos = name.end
            if (pos + 4 > length) return emptyList()
            pos += 4
        }

        val out = ArrayList<String>(4)
        repeat(answerCount) {
            val name = readName(data, length, pos) ?: return out
            pos = name.end
            if (pos + 10 > length) return out

            val type = u16(data, pos)
            val rdLength = u16(data, pos + 8)
            pos += 10
            if (pos + rdLength > length) return out

            when {
                type == TYPE_A && rdLength == 4 ->
                    out.add("${u8(data, pos)}.${u8(data, pos + 1)}.${u8(data, pos + 2)}.${u8(data, pos + 3)}")

                type == TYPE_AAAA && rdLength == 16 -> {
                    val bytes = data.copyOfRange(pos, pos + 16)
                    runCatching { InetAddress.getByAddress(bytes).hostAddress }.getOrNull()?.let { out.add(it) }
                }
            }
            pos += rdLength
        }
        return out
    }

    private fun encodeA(name: String, address: String, ttl: Int): ByteArray {
        val octets = address.split('.').mapNotNull { it.toIntOrNull()?.takeIf { o -> o in 0..255 }?.toByte() }
        if (octets.size != 4) return ByteArray(0)

        val nameBytes = encodeName(name)
        val out = ByteArray(nameBytes.size + 10 + 4)
        var i = 0
        nameBytes.copyInto(out, 0); i += nameBytes.size
        writeShort(out, i, TYPE_A); i += 2
        writeShort(out, i, CLASS_IN); i += 2
        writeInt(out, i, ttl); i += 4
        writeShort(out, i, 4); i += 2
        for (octet in octets) { out[i] = octet; i += 1 }
        return out
    }

    private fun encodeName(name: String): ByteArray {
        val labels = name.trim('.').split('.').filter { it.isNotEmpty() }
        val out = ByteArray(labels.sumOf { it.length + 1 } + 1)
        var i = 0
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out[i] = bytes.size.toByte(); i += 1
            bytes.copyInto(out, i); i += bytes.size
        }
        out[i] = 0
        return out
    }

    private fun build(
        id: Int,
        flags: Int,
        answerCount: Int,
        question: Question,
        answerBytes: ByteArray,
    ): ByteArray {
        val qName = encodeName(question.name)
        val out = ByteArray(HEADER_SIZE + qName.size + 4 + answerBytes.size)

        writeShort(out, 0, id)
        writeShort(out, 2, flags)
        writeShort(out, 4, 1) // QDCOUNT
        writeShort(out, 6, answerCount) // ANCOUNT
        // NSCOUNT and ARCOUNT remain zero.

        var i = HEADER_SIZE
        qName.copyInto(out, i); i += qName.size
        writeShort(out, i, question.type); i += 2
        writeShort(out, i, question.clazz); i += 2
        answerBytes.copyInto(out, i)
        return out
    }

    private fun u8(data: ByteArray, at: Int): Int = data[at].toInt() and 0xFF

    private fun u16(data: ByteArray, at: Int): Int = (u8(data, at) shl 8) or u8(data, at + 1)

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
}
