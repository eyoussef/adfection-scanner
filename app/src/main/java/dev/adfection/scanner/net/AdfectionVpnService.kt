package dev.adfection.scanner.net

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.adfection.scanner.R
import dev.adfection.scanner.data.Action
import dev.adfection.scanner.data.EventKind
import dev.adfection.scanner.data.EventStore
import dev.adfection.scanner.data.IocDatabase
import dev.adfection.scanner.data.ScanEvent
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.data.Settings
import dev.adfection.scanner.data.ThreatCategory
import dev.adfection.scanner.engine.ChainDetector
import dev.adfection.scanner.engine.IocMatcher
import dev.adfection.scanner.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * DNS-sinkhole [VpnService].
 *
 * ## Why a VPN service
 * Android gives no supported API to observe another app's DNS queries. A `VpnService` that
 * negotiates capture of exactly two /32 (and /128) routes — the virtual DNS addresses it
 * advertises — is the narrowest privileged surface that still sees every system-resolver lookup.
 * No default route is requested, so ordinary traffic never enters the tunnel and there is no
 * throughput cost and no traffic inspection beyond DNS.
 *
 * ## Data flow
 * ```
 * app -> tun (10.111.222.1:53) -> parse -> IOC match
 *        |-- BLOCKED  -> synthesise sinkhole/NXDOMAIN reply, write back to tun
 *        `-- else     -> forward over a protected socket to upstream, write reply back to tun
 * ```
 * The upstream socket is `protect()`ed so its own packets do not re-enter the tunnel (which would
 * cause an infinite loop).
 *
 * ## Limits (documented, not hidden)
 *  - DNS-over-HTTPS/TLS to a hardcoded resolver, and IP-literal connections, are invisible here.
 *  - Only the first fragment of a fragmented datagram is inspected.
 *  - This is *detection*, not remediation: it cannot remove an implant already on the device.
 */
class AdfectionVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)

    private var tun: ParcelFileDescriptor? = null
    private var readJob: Job? = null

    /** Single writer for the tunnel, shared by the read loop and the reply pump. */
    @Volatile
    private var tunOutput: FileOutputStream? = null

    /**
     * Serialises writes to the tun.
     *
     * Three threads can write to the same descriptor: the read loop (sinkhole/NXDOMAIN replies and
     * TCP resets), the forwarder's SERVFAIL path, and every upstream reply pump. Writes to a
     * character device are not atomic with respect to each other, so two concurrent writes can
     * interleave and corrupt a packet — which the kernel then drops, leaving the client to time out
     * with no error anywhere. A short critical section per reply is cheap next to that.
     */
    private val tunWriteLock = Any()

    private lateinit var matcher: IocMatcher
    private lateinit var settings: Settings
    private lateinit var store: EventStore
    private val chain = ChainDetector()

    /** Posts an OS notification when a finding clears the high-severity gate. */
    private val notifier by lazy { AlertNotifier(applicationContext) }

    private val upstreamSocket = ConcurrentHashMap<String, DatagramSocket>() // key: v4/v6 family

    /** One receive loop per upstream socket; see [ensureReceiver] for why. */
    private val receivers = ConcurrentHashMap<DatagramSocket, Job>()

    private val pending = ConcurrentHashMap<Int, PendingQuery>()
    private val lastLogged = ConcurrentHashMap<String, Long>()

    private val totalQueries = AtomicLong()
    private val totalBlocked = AtomicLong()
    private val totalAlerted = AtomicLong()

    /** Allocator for outbound transaction IDs; see [nextTransactionId]. */
    private val idSource = java.util.concurrent.atomic.AtomicInteger(1)

    private data class PendingQuery(
        /** The transaction ID the client used; restored on the way back. */
        val clientId: Int,
        val srcAddress: ByteArray,
        val srcPort: Int,
        val dstAddress: ByteArray,
        val version: Int,
        val askedAt: Long,
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopScanner()
                return START_NOT_STICKY
            }
        }

        if (running.get()) return START_STICKY
        startForegroundInternal()
        startScanner()
        return START_STICKY
    }

    private fun startScanner() {
        val db = IocDatabase(this)
        val loaded = db.loadBlocking()
        matcher = loaded.matcher
        settings = Settings(this)
        store = EventStore(this)

        Log.i(TAG, "indicator set loaded: ${loaded.indicatorCount} indicators from ${loaded.sourceCount} sources, ${loaded.problems.size} parse problems")

        tun = try {
            establish()
        } catch (t: Throwable) {
            Log.e(TAG, "establish() failed", t)
            null
        }

        if (tun == null) {
            Log.e(TAG, "VPN could not be established; stopping")
            publishState(active = false)
            stopSelf()
            return
        }

        running.set(true)
        publishState(active = true)
        logEvent(
            ScanEvent(
                timestamp = System.currentTimeMillis(),
                kind = EventKind.SERVICE_STATE,
                severity = Severity.INFO,
                category = null,
                subject = "vpn",
                detail = "DNS sinkhole started; ${loaded.indicatorCount} indicators active",
                action = Action.LOGGED,
            )
        )

        // Receive loops are started per socket, on creation: a device emits IPv6 queries within
        // seconds of starting, so a single shared loop would serialise the two families and add a
        // timeout of latency to every lookup. See ensureReceiver().
        readJob = scope.launch { readLoop() }
    }

    /** Configure the tunnel: two virtual DNS addresses and routes for nothing else. */
    private fun establish(): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("AdFection Scanner")
            .setMtu(MTU)
            .addAddress(VIRTUAL_DNS_V4, 32)
            .addAddress(VIRTUAL_DNS_V6, 128)
            .addDnsServer(VIRTUAL_DNS_V4)
            .addDnsServer(VIRTUAL_DNS_V6)
            .addRoute(VIRTUAL_DNS_V4, 32)
            .addRoute(VIRTUAL_DNS_V6, 128)

        // Keep our own traffic (the upstream forwarder) out of the tunnel as a second line of
        // defence beyond Socket.protect().
        runCatching { builder.addDisallowedApplication(packageName) }
            .onFailure { Log.w(TAG, "could not exclude self from VPN", it) }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        return builder.establish()
    }

    private suspend fun readLoop() {
        val descriptor = tun ?: return
        val input = FileInputStream(descriptor.fileDescriptor)
        // One output stream for the life of the tunnel. Allocating a FileOutputStream per packet
        // would churn an object per datagram on the hot path.
        val output = FileOutputStream(descriptor.fileDescriptor)
        tunOutput = output
        val buffer = ByteArray(MAX_PACKET)

        try {
            while (running.get()) {
                val length = try {
                    input.read(buffer)
                } catch (t: Throwable) {
                    if (running.get()) Log.w(TAG, "tun read failed", t)
                    break
                }
                if (length <= 0) continue

                val packet = Packets.parse(buffer, length) ?: continue
                if (packet.isDnsQuery) {
                    handleDnsQuery(packet, output)
                } else if (packet.protocol == Packets.PROTO_TCP && packet.dstPort == Packets.PORT_DNS && packet.isTcpSyn) {
                    // DNS over TCP: we do not proxy streams, so refuse cleanly. The stub resolver
                    // then falls back to UDP, which we do handle.
                    Packets.buildTcpReset(packet, packet.dstAddress, packet.srcAddress)?.let { writeToTun(output, it) }
                }
            }
        } finally {
            tunOutput = null
        }
    }

    private fun handleDnsQuery(packet: Packets.Parsed, output: FileOutputStream) {
        val query = Dns.parseQuery(packet.payload, packet.payload.size)
        if (query == null) return

        totalQueries.incrementAndGet()
        val host = query.question.name
        val match = matcher.matchHost(host)
        val now = System.currentTimeMillis()

        val action = match?.let { settings.state.value.actionFor(it.ioc.category, it.ioc.severity) }
            ?: Action.LOGGED

        if (match == null) {
            forward(packet, query)
            return
        }

        if (action == Action.BLOCKED) {
            val response = if (match.ioc.category == ThreatCategory.TRACKING) {
                Dns.buildSinkholeResponse(query, SINKHOLE_V4)
            } else {
                Dns.buildNxDomain(query)
            }
            Packets.buildUdp(
                version = packet.version,
                srcAddress = packet.dstAddress,
                srcPort = Packets.PORT_DNS,
                dstAddress = packet.srcAddress,
                dstPort = packet.srcPort,
                payload = response,
            )?.let { writeToTun(output, it) }

            totalBlocked.incrementAndGet()
            record(match, host, Action.BLOCKED, now)
            return
        }

        if (action == Action.ALERTED) totalAlerted.incrementAndGet()
        record(match, host, action, now)
        forward(packet, query)
    }

    /** Log a matched observation and run kill-chain detection. */
    private fun record(
        match: dev.adfection.scanner.data.MatchResult,
        host: String,
        action: Action,
        now: Long,
    ) {
        val ioc = match.ioc

        val chainAlert = chain.observe(match, now)
        if (chainAlert != null) {
            logEvent(
                ScanEvent(
                    timestamp = now,
                    kind = EventKind.CHAIN_DETECTED,
                    severity = Severity.CRITICAL,
                    category = ThreatCategory.CANDIRU_C2,
                    subject = host,
                    detail = chainAlert,
                    action = Action.BLOCKED,
                )
            )
            // The full chain is the one finding that warrants interrupting the user wherever they are.
            notifier.alert(host, chainAlert, Severity.CRITICAL)
        }

        val throttleMs = settings.state.value.logThrottleSeconds * 1000L
        val last = lastLogged[host]
        if (last != null && now - last < throttleMs) return
        lastLogged[host] = now

        val provenance = buildString {
            append(ioc.source).append(" — ").append(ioc.category.name)
            if (ioc.note.isNotEmpty()) append(": ").append(ioc.note)
        }
        logEvent(
            ScanEvent(
                timestamp = now,
                kind = if (action == Action.BLOCKED) EventKind.DNS_BLOCKED else EventKind.DNS_OBSERVED,
                severity = ioc.severity,
                category = ioc.category,
                subject = host,
                detail = provenance,
                action = action,
            )
        )

        // Raises its own severity gate: ad-delivery and tracking domains are routine traffic and must
        // not produce notifications, or the alerts that matter get dismissed with the rest.
        notifier.alert(host, provenance, ioc.severity)
    }

    /**
     * Send the query upstream on a protected socket and remember it so the reply can be routed home.
     *
     * The transaction ID is rewritten to an ID this service owns. Two clients (or one client and
     * its own retry) can legitimately use the same ID at the same moment; forwarding them unmodified
     * would make the first reply satisfy both pendings and hand a caller another client's answer.
     * Rewriting gives every in-flight query a unique key, and the original ID is restored on the
     * way back.
     */
    private fun forward(packet: Packets.Parsed, query: Dns.Query) {
        val upstream = settings.state.value.upstreamDns
        val ownId = nextTransactionId()
        val outbound = Dns.rewriteId(packet.payload, packet.payload.size, ownId) ?: return

        // Both families are attempted regardless of which one the query arrived on. A v6 query on a
        // v4-only uplink is common on Android, and answering it over v4 is correct: the reply only
        // has to travel back over the tunnel, so the upstream transport is free to differ from the
        // client's addressing.
        //
        // v4 is tried first even for a v6 query. Almost every mobile network is v4-only, so leading
        // with v6 would make the first attempt fail on every query, and each failure costs a socket
        // close and rebuild. Ordering by likelihood keeps the common case to one attempt.
        if (sendUpstream(4, packet, query, outbound, upstream)) return
        if (sendUpstream(6, packet, query, outbound, upstream)) return

        Log.w(TAG, "no usable upstream socket for '$upstream'; answering SERVFAIL")
        logUpstreamFailure(upstream, packet, query, outbound)
    }

    /** Send over an already-resolved family. @return true when the datagram was handed to the socket. */
    private fun sendUpstream(
        family: Int,
        packet: Packets.Parsed,
        query: Dns.Query,
        outbound: ByteArray,
        upstream: String,
    ): Boolean {
        val socket = ensureUpstreamSocket(family) ?: return false
        val target = resolveUpstream(upstream, family) ?: return false

        val ownId = ((outbound[0].toInt() and 0xFF) shl 8) or (outbound[1].toInt() and 0xFF)
        pending[ownId] = PendingQuery(
            clientId = query.id,
            srcAddress = packet.srcAddress,
            srcPort = packet.srcPort,
            dstAddress = packet.dstAddress,
            version = packet.version,
            askedAt = System.currentTimeMillis(),
        )

        return try {
            socket.send(DatagramPacket(outbound, outbound.size, InetSocketAddress(target, Packets.PORT_DNS)))
            true
        } catch (t: Throwable) {
            // Wrong family for this network, or the socket died: drop the pending entry and let the
            // caller try the other family before giving up. Without the SERVFAIL the stub resolver
            // would wait out its own timeout on a query we already know we cannot answer.
            Log.w(TAG, "upstream send failed on v$family", t)
            pending.remove(ownId)
            runCatching { socket.close() }
            false
        }
    }

    /** Resolve the configured upstream name to an address of [family], or null when it has none. */
    private fun resolveUpstream(upstream: String, family: Int): InetAddress? = try {
        InetAddress.getAllByName(upstream).firstOrNull { (it.address.size == 16) == (family == 6) }
    } catch (t: Throwable) {
        null
    }

    /**
     * Answer SERVFAIL so the client fails fast and visibly.
     *
     * Silence is the worst outcome: the stub resolver retries for seconds, the user sees a spinner,
     * and nothing in the evidence log explains why. SERVFAIL plus an event makes it diagnosable.
     */
    private fun logUpstreamFailure(upstream: String, packet: Packets.Parsed, query: Dns.Query, outbound: ByteArray) {
        Dns.buildServFail(outbound.copyOf(outbound.size), outbound.size)
            ?.let { reply ->
                Packets.buildUdp(
                    version = packet.version,
                    srcAddress = packet.dstAddress,
                    srcPort = Packets.PORT_DNS,
                    dstAddress = packet.srcAddress,
                    dstPort = packet.srcPort,
                    payload = reply,
                )?.let { writeToTun(tunOutput, it) }
            }

        val now = System.currentTimeMillis()
        val last = lastLogged["!upstream"]
        if (last != null && now - last < UPSTREAM_FAILURE_LOG_THROTTLE_MS) return
        lastLogged["!upstream"] = now

        logEvent(
            ScanEvent(
                timestamp = now,
                kind = EventKind.SERVICE_STATE,
                severity = Severity.HIGH,
                category = null,
                subject = query.question.name,
                detail = "Upstream resolver '$upstream' is unreachable from this network; " +
                    "set a different one in settings. Query answered with SERVFAIL.",
                action = Action.LOGGED,
            )
        )
    }

    /** Allocate an unused transaction ID. The 16-bit space is ample for a device's DNS concurrency. */
    private fun nextTransactionId(): Int {
        repeat(1024) {
            val candidate = idSource.getAndIncrement() and 0xFFFF
            if (!pending.containsKey(candidate)) return candidate
        }
        // Pathological: every ID is in flight. Reuse the round-robin value; a collision here can
        // only misroute a reply if the colliding query is for the same name, which is far rarer
        // than the exhaustion itself.
        return idSource.get() and 0xFFFF
    }

    /**
     * @return null when none of the candidates could open, so the caller logs instead of silently
     *         black-holing the query. Returning an explicit null (rather than NPE-ing on a null map
     *         value, which would abort the whole read loop) is what keeps a blocked upstream from
     *         killing DNS for the device.
     */
    private fun ensureUpstreamSocket(version: Int): DatagramSocket? {
        val key = if (version == 6) "v6" else "v4"
        upstreamSocket[key]?.takeIf { !it.isClosed }?.let { return it }

        // The stale-or-closed entry must go before publishing a replacement. Leaving it in place
        // makes putIfAbsent hand back a closed socket, and a caller that receives one has a socket
        // nobody is reading: replies are delivered into it and discarded while send keeps
        // succeeding. That failure is silent and intermittent, which is the worst combination.
        upstreamSocket.remove(key, upstreamSocket[key])

        val fresh = newProtectedSocket(version) ?: return null
        val raced = upstreamSocket.putIfAbsent(key, fresh)

        val registered = if (raced != null && !raced.isClosed) {
            // Another thread won with a live socket; use theirs and discard ours.
            runCatching { fresh.close() }
            raced
        } else {
            if (raced != null) upstreamSocket.remove(key, raced)
            upstreamSocket.putIfAbsent(key, fresh) ?: fresh
        }

        // Invariant: whoever is returned is the socket in the map, and has a receiver. Starting the
        // loop here — rather than only on the branch where this thread won — is what makes that true.
        ensureReceiver(registered)
        return registered
    }

    private fun newProtectedSocket(version: Int): DatagramSocket? = try {
        val socket = DatagramSocket(null)
        socket.reuseAddress = true

        // No connect() is performed to prepare the socket. Connecting a v6 socket to a v6 address to
        // "check reachability" also pins its default destination, and a connected datagram socket
        // refuses datagrams from any other peer — which would silently discard every upstream reply.
        // The family decision belongs in forward(), which falls back on a real send failure.
        when (version) {
            6 -> socket.bind(InetSocketAddress(IPV6_ANY, 0))
            else -> socket.bind(InetSocketAddress(IPV4_ANY, 0))
        }

        // protect() is what keeps our own upstream packets out of the tunnel. protect() itself
        // throws on an unconnected socket to a different address family on some ROMs, so it is
        // guarded: a socket we cannot protect is closed rather than left to loop traffic back.
        val protectedOk = runCatching { protect(socket) }.getOrDefault(false)
        if (!protectedOk) {
            Log.w(TAG, "protect() returned false for upstream socket; closing to avoid a loop")
            socket.close()
            null
        } else {
            socket.soTimeout = UPSTREAM_TIMEOUT_MS
            socket
        }
    } catch (t: Throwable) {
        Log.w(TAG, "could not open upstream socket", t)
        null
    }

    /**
     * Start one blocking receive loop per upstream socket.
     *
     * ## Why this is per-socket and not one shared loop
     * The first version of this service received from every socket inside a single loop:
     *
     * ```
     * for (socket in sockets) { socket.receive(response) }   // blocking, 4 s timeout
     * ```
     *
     * That is a latency bug with a severe symptom. A device asks its first IPv6 question early, so
     * within seconds there are two sockets (v4 and v6). From then on a reply arriving on the *first*
     * socket cannot be read until the *second* socket has timed out — up to 4 seconds — and the
     * pattern repeats on the next pass. Every lookup took ~4 s, browsers gave up, and apps with
     * long-lived connections (WhatsApp) kept working, which makes it look like "the internet dies".
     *
     * Dedicated blocking receives in parallel remove the coupling: a reply is delivered as soon as
     * its own socket receives it, while the timeout still acts as the pending-entry sweep that stops
     * [pending] growing without bound.
     */
    private fun ensureReceiver(socket: DatagramSocket) {
        if (receivers.containsKey(socket)) return
        val job = scope.launch { receiveFrom(socket) }
        // Close the race where the socket was reaped between the check and the launch.
        if (receivers.putIfAbsent(socket, job) != null) job.cancel()
    }

    private fun receiveFrom(socket: DatagramSocket) {
        val buffer = ByteArray(MAX_PACKET)
        while (running.get() && !socket.isClosed) {
            val response = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(response)
            } catch (t: Throwable) {
                if (!running.get() || socket.isClosed) return
                // A timeout is expected and is the only thing that sweeps stale entries.
                expirePending()
                continue
            }
            deliverUpstream(response.data, response.length)
        }
    }

    private fun deliverUpstream(data: ByteArray, length: Int) {
        if (length < 12) return
        val ownId = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        val awaiting = pending.remove(ownId) ?: return

        // Restore the ID the client actually asked with.
        val rewritten = Dns.rewriteId(data, length, awaiting.clientId) ?: return
        val packet = Packets.buildUdp(
            version = awaiting.version,
            srcAddress = awaiting.dstAddress,
            srcPort = Packets.PORT_DNS,
            dstAddress = awaiting.srcAddress,
            dstPort = awaiting.srcPort,
            payload = rewritten,
        ) ?: return

        writeToTun(tunOutput, packet)
    }


    /**
     * Write one packet to the tun, serialised against the other writers.
     *
     * @return false when the tunnel is gone or the write failed; callers treat that as "stop".
     */
    private fun writeToTun(sink: FileOutputStream?, packet: ByteArray): Boolean {
        if (sink == null) return false
        return try {
            synchronized(tunWriteLock) { sink.write(packet) }
            true
        } catch (t: Throwable) {
            Log.w(TAG, "tun write failed", t)
            false
        }
    }

    private fun expirePending() {
        val now = System.currentTimeMillis()
        pending.entries.removeIf { now - it.value.askedAt > UPSTREAM_TIMEOUT_MS * 2 }
    }

    private fun logEvent(event: ScanEvent) {
        if (!::store.isInitialized) return
        scope.launch {
            runCatching { store.append(event) }
                .onFailure { Log.w(TAG, "event write failed", it) }
        }
    }

    private fun publishState(active: Boolean) {
        ScannerState.update(
            active = active,
            queries = totalQueries.get(),
            blocked = totalBlocked.get(),
            alerted = totalAlerted.get(),
            chainProgress = chain.progress,
        )
    }

    private fun startForegroundInternal() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = getString(R.string.channel_description) }
            manager?.createNotificationChannel(channel)
        }

        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, AdfectionVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, getString(R.string.action_stop), stop)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun stopScanner() {
        running.set(false)
        readJob?.cancel()
        readJob = null
        receivers.values.forEach { it.cancel() }
        receivers.clear()
        upstreamSocket.values.forEach { runCatching { it.close() } }
        upstreamSocket.clear()
        pending.clear()
        runCatching { tun?.close() }
        tun = null
        publishState(active = false)
        if (::store.isInitialized) {
            logEvent(
                ScanEvent(
                    timestamp = System.currentTimeMillis(),
                    kind = EventKind.SERVICE_STATE,
                    severity = Severity.INFO,
                    category = null,
                    subject = "vpn",
                    detail = "DNS sinkhole stopped",
                    action = Action.LOGGED,
                )
            )
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN consent revoked by user or another VPN")
        stopScanner()
        super.onRevoke()
    }

    override fun onDestroy() {
        running.set(false)
        scope.cancel()
        runCatching { tun?.close() }
        tun = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AdfectionVpn"
        private const val CHANNEL_ID = "adfection_scanner"
        private const val NOTIFICATION_ID = 4711
        private const val MTU = 1500
        private const val MAX_PACKET = 32767
        private const val UPSTREAM_TIMEOUT_MS = 4000

        /** Backstop throttle for "upstream unreachable" events, so a dead resolver cannot flood the log. */
        private const val UPSTREAM_FAILURE_LOG_THROTTLE_MS = 60_000L

        const val ACTION_STOP = "dev.adfection.scanner.STOP"

        private const val VIRTUAL_DNS_V4 = "10.111.222.1"
        private const val VIRTUAL_DNS_V6 = "fd00:adfe:c710::1"
        private const val SINKHOLE_V4 = "0.0.0.0"
        private const val IPV4_ANY = "0.0.0.0"
        private const val IPV6_ANY = "::"

        /** Start the service in monitor mode. */
        fun start(context: android.content.Context) {
            val intent = Intent(context, AdfectionVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: android.content.Context) {
            context.startService(
                Intent(context, AdfectionVpnService::class.java).setAction(ACTION_STOP)
            )
        }
    }
}
