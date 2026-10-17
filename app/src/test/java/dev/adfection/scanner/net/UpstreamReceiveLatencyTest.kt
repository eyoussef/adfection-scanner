package dev.adfection.scanner.net

import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Regression test for the upstream receive path.
 *
 * ## The defect this pins down
 * The service originally received from every upstream socket inside one loop:
 *
 * ```
 * for (socket in sockets) { socket.receive(response) }   // blocking, 4 s timeout
 * ```
 *
 * A device asks its first IPv6 question seconds after protection starts, so a second socket appears
 * almost immediately. From then on, a reply waiting on the *first* socket could not be read until the
 * *second* socket timed out — up to four seconds added to every lookup, repeated indefinitely. The
 * user-visible symptom was "the internet dies": browsers could not resolve, while apps holding
 * long-lived connections kept working.
 *
 * These tests demonstrate the difference in shape between the two designs using real sockets on the
 * loopback interface, so the serialisation is measured rather than asserted in the abstract.
 */
class UpstreamReceiveLatencyTest {

    /**
     * The buggy shape: one loop, blocking receives in sequence. With two sockets where only the
     * second has traffic, the first socket's timeout dominates the time to deliver.
     */
    @Test
    fun `serial receives pay a full timeout per idle socket`() {
        val timeoutMs = 400
        val idle = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        val busy = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        idle.soTimeout = timeoutMs
        busy.soTimeout = timeoutMs

        try {
            val sender = DatagramSocket()
            // Put a datagram in busy's queue so the serial loop will find it on its second pass.
            val payload = "reply".toByteArray()
            sender.send(DatagramPacket(payload, payload.size, InetSocketAddress(InetAddress.getByName("127.0.0.1"), busy.localPort)))

            val started = System.nanoTime()
            for (socket in listOf(idle, busy)) {
                val buffer = ByteArray(512)
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (t: Throwable) {
                    // Idle socket times out first: this is the delay the bug introduced.
                }
            }
            val elapsedMs = (System.nanoTime() - started) / 1_000_000

            // The reply was already queued, so an efficient design would deliver it in milliseconds.
            // The serial design cannot: it must absorb the idle socket's timeout first.
            assertTrue(
                "serial loop should be dominated by the idle socket's timeout (took ${elapsedMs}ms)",
                elapsedMs >= timeoutMs * 0.5,
            )
        } finally {
            runCatching { idle.close() }
            runCatching { busy.close() }
        }
    }

    /**
     * The fixed shape: one receive loop per socket. A datagram queued on either socket is delivered
     * immediately, because no loop ever waits on a socket that has nothing to say.
     */
    @Test
    fun `parallel receivers deliver without waiting on the idle socket`() {
        val timeoutMs = 400
        val idle = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        val busy = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        idle.soTimeout = timeoutMs
        busy.soTimeout = timeoutMs

        try {
            val delivered = CountDownLatch(1)
            val started = System.nanoTime()

            // Mirror of ensureReceiver(): one loop per socket.
            val idleThread = Thread {
                runCatching {
                    val packet = DatagramPacket(ByteArray(512), 512)
                    idle.receive(packet)
                }
            }
            val busyThread = Thread {
                runCatching {
                    val packet = DatagramPacket(ByteArray(512), 512)
                    busy.receive(packet)
                    delivered.countDown()
                }
            }
            idleThread.isDaemon = true
            busyThread.isDaemon = true
            idleThread.start()
            busyThread.start()

            val sender = DatagramSocket()
            val payload = "reply".toByteArray()
            sender.send(DatagramPacket(payload, payload.size, InetSocketAddress(InetAddress.getByName("127.0.0.1"), busy.localPort)))

            val ok = delivered.await(timeoutMs / 2L, TimeUnit.MILLISECONDS)
            val elapsedMs = (System.nanoTime() - started) / 1_000_000

            assertTrue("reply must be delivered promptly, took ${elapsedMs}ms", ok)
            assertTrue(
                "delivery should not be gated by the idle socket's timeout (took ${elapsedMs}ms)",
                elapsedMs < timeoutMs,
            )
        } finally {
            runCatching { idle.close() }
            runCatching { busy.close() }
        }
    }
}

/**
 * Reproduction of the orphaned-socket defect.
 *
 * ## The defect
 * The socket was published with `putIfAbsent`, but the receiver was only started when the caller's
 * socket was the one that ended up in the map:
 *
 * ```
 * val existing = upstreamSocket.putIfAbsent(key, fresh)
 * if (existing != null && !existing.isClosed) { fresh.close(); return existing }
 * if (upstreamSocket[key] === fresh) ensureReceiver(fresh)
 * return fresh                       // <- when `existing` was CLOSED the map still holds it,
 *                                    //    so this is false: no receiver is ever started
 * ```
 *
 * A closed socket can be left in that map by the send-failure path, which fires immediately on
 * networks without IPv6 because the v6 send fails. From then on every reply arriving for those
 * queries was delivered into a socket nobody was reading, while `send` kept succeeding. DNS answers
 * were silently discarded — intermittently, depending on which family a query arrived on — and the
 * client reported `ERR_NAME_NOT_RESOLVED`.
 *
 * These tests pin the invariant that matters: a socket handed to a caller must be the one the map
 * contains AND must have a receiver. A socket that is simply closed must be replaced, never reused.
 */
class UpstreamSocketRegistrationTest {

    @Test
    fun `a closed socket is never handed back to a caller`() {
        val map = java.util.concurrent.ConcurrentHashMap<String, DatagramSocket>()
        val dead = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        map["v4"] = dead
        dead.close()

        // The lookup the code performs: a closed entry must not satisfy it.
        val reusable = map["v4"]?.takeIf { !it.isClosed }

        assertNull("a closed socket must not be reused", reusable)
    }

    /**
     * The orphan, reproduced directly: publish with putIfAbsent while a closed entry is present, and
     * the caller's socket is returned without ever being the map's value.
     */
    @Test
    fun `putIfAbsent over a closed entry orphans the new socket`() {
        val map = java.util.concurrent.ConcurrentHashMap<String, DatagramSocket>()
        val dead = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        map["v4"] = dead
        dead.close()

        val fresh = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        val existing = map.putIfAbsent("v4", fresh)

        assertNotNull("putIfAbsent reports the old entry", existing)
        assertTrue("the stale entry is closed", existing!!.isClosed)
        // This is the bug: the guard below is what the old code used to decide whether to start a
        // receiver, and it is false even though `fresh` is the socket being returned. `existing` is
        // smart-cast to non-null by the assertion above, so only `isClosed` matters.
        assertFalse(
            "old guard is false, so no receiver was ever started for the returned socket",
            !existing.isClosed,
        )
        // And the map does NOT contain the socket that was returned.
        assertTrue("map still holds the closed socket, not the returned one", map["v4"] === existing)
        assertFalse("the returned socket is not in the map", map["v4"] === fresh)

        runCatching { fresh.close() }
    }

    @Test
    fun `remove then publish guarantees the returned socket is the registered one`() {
        val map = java.util.concurrent.ConcurrentHashMap<String, DatagramSocket>()
        val dead = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        map["v4"] = dead
        dead.close()

        // The fixed registration.
        val candidate = map["v4"]?.takeIf { !it.isClosed }
        if (candidate != null) {
            println("reusing live socket")
        } else {
            map.remove("v4") // drop the closed entry first
            val fresh = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
            val raced = map.putIfAbsent("v4", fresh)
            val registered = raced ?: fresh
            assertTrue("the socket we will return is the one in the map", map["v4"] === registered)
            assertFalse("it is open and therefore readable", registered.isClosed)
            runCatching { fresh.close() }
        }
    }

    private fun assertNull(message: String, value: Any?) =
        org.junit.Assert.assertNull(message, value)

    private fun assertNotNull(message: String, value: Any?) =
        org.junit.Assert.assertNotNull(message, value)

    private fun assertTrue(message: String, value: Boolean) =
        org.junit.Assert.assertTrue(message, value)

    private fun assertFalse(message: String, value: Boolean) =
        org.junit.Assert.assertFalse(message, value)
}
