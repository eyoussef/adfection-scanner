package dev.adfection.scanner.net

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Live scanner status shared between the VPN service (writer) and the UI (reader).
 *
 * A process-wide singleton is correct here: exactly one VPN service instance exists per process,
 * and the UI has no other way to observe counters updated on the service's IO threads.
 */
object ScannerState {

    data class Snapshot(
        val active: Boolean = false,
        val queriesSeen: Long = 0,
        val blocked: Long = 0,
        val alerted: Long = 0,
        /** 0 = no chain stages seen, 3 = full AdFection chain observed. */
        val chainProgress: Int = 0,
    )

    private val _state = MutableStateFlow(Snapshot())
    val state: StateFlow<Snapshot> = _state.asStateFlow()

    fun update(
        active: Boolean? = null,
        queries: Long? = null,
        blocked: Long? = null,
        alerted: Long? = null,
        chainProgress: Int? = null,
    ) {
        val current = _state.value
        _state.value = current.copy(
            active = active ?: current.active,
            queriesSeen = queries ?: current.queriesSeen,
            blocked = blocked ?: current.blocked,
            alerted = alerted ?: current.alerted,
            chainProgress = chainProgress ?: current.chainProgress,
        )
    }
}
