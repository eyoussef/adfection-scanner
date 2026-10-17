package dev.adfection.scanner.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.adfection.scanner.R
import dev.adfection.scanner.data.AppFinding
import dev.adfection.scanner.data.EventStore
import dev.adfection.scanner.data.IndicatorFreshness
import dev.adfection.scanner.data.IocDatabase
import dev.adfection.scanner.data.PostureFinding
import dev.adfection.scanner.data.ScanEvent
import dev.adfection.scanner.data.Settings
import dev.adfection.scanner.scan.PackageScanner
import dev.adfection.scanner.scan.PostureScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * View-model backing [MainActivity]: owns the evidence log stream, the two audit reports, and the
 * settings snapshot. All heavy work runs off the main thread.
 */
class ScannerViewModel(application: Application) : AndroidViewModel(application) {

    private val store = EventStore(application)
    private val settings = Settings(application)
    private val iocDatabase = IocDatabase(application)
    private val postureScanner = PostureScanner(application)
    private val packageScanner = PackageScanner(application)

    private val _events = MutableStateFlow<List<ScanEvent>>(emptyList())
    val events: StateFlow<List<ScanEvent>> = _events.asStateFlow()

    private val _posture = MutableStateFlow<List<PostureFinding>>(emptyList())
    val posture: StateFlow<List<PostureFinding>> = _posture.asStateFlow()

    private val _appFindings = MutableStateFlow<List<AppFinding>>(emptyList())
    val appFindings: StateFlow<List<AppFinding>> = _appFindings.asStateFlow()

    private val _indicatorSummary = MutableStateFlow("")
    val indicatorSummary: StateFlow<String> = _indicatorSummary.asStateFlow()

    /** Indicator counts plus compile date, kept for the exported report. */
    private var indicatorCount: Int = 0
    private var indicatorCompiledAt: String? = null

    private val _config = MutableStateFlow(settings.state.value)
    val config: StateFlow<Settings.Config> = _config.asStateFlow()

    fun bootstrap() {
        viewModelScope.launch {
            runCatching { iocDatabase.load() }
                .onSuccess { loaded ->
                    indicatorCount = loaded.indicatorCount
                    indicatorCompiledAt = loaded.compiledAt

                    val problems = if (loaded.problems.isNotEmpty()) {
                        getApplication<Application>().getString(R.string.indicators_problems, loaded.problems.size)
                    } else {
                        ""
                    }
                    val compiled = loaded.compiledAt
                    val ageDays = IndicatorFreshness.ageInDays(compiled, System.currentTimeMillis())
                    _indicatorSummary.value = when {
                        // An undated set cannot be reported as current, so it is not.
                        compiled == null || ageDays == null ->
                            getApplication<Application>().getString(
                                R.string.indicators_format, loaded.indicatorCount, loaded.sourceCount,
                            ) + problems

                        IndicatorFreshness.isStale(compiled, System.currentTimeMillis()) ->
                            getApplication<Application>().getString(
                                R.string.indicators_stale, loaded.indicatorCount, loaded.sourceCount, compiled, ageDays,
                            ) + problems

                        else ->
                            getApplication<Application>().getString(
                                R.string.indicators_compiled, loaded.indicatorCount, loaded.sourceCount, compiled,
                            ) + problems
                    }
                }
                .onFailure {
                    _indicatorSummary.value =
                        getApplication<Application>().getString(R.string.indicators_failed, it.message ?: "unknown")
                }
        }
        runAudits()
        refreshLog()
    }

    /**
     * Shareable report of everything observed.
     *
     * Runs on [Dispatchers.IO] because it reads the event log and writes a file; the caller gets a
     * share intent through the callback rather than a return value.
     */
    fun buildReport(onResult: (Result<android.content.Intent>) -> Unit) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val context = getApplication<Application>()
                    val content = ReportBuilder.render(
                        events = store.recent(500),
                        posture = _posture.value,
                        apps = _appFindings.value,
                        indicatorCount = indicatorCount,
                        compiledAt = indicatorCompiledAt,
                    )
                    ReportBuilder.writeAndShareUri(context, content)
                }
            }
            onResult(result)
        }
    }

    fun runAudits() {
        viewModelScope.launch {
            val postureFindings = withContext(Dispatchers.Default) { postureScanner.scan() }
            _posture.value = postureFindings
            val apps = packageScanner.scan()
            _appFindings.value = apps

            postureFindings.forEach { finding ->
                store.append(
                    ScanEvent(
                        timestamp = System.currentTimeMillis(),
                        kind = dev.adfection.scanner.data.EventKind.POSTURE_FINDING,
                        severity = finding.severity,
                        category = null,
                        subject = finding.id,
                        detail = "${finding.title} — ${finding.remediation}",
                        action = dev.adfection.scanner.data.Action.LOGGED,
                    )
                )
            }
            apps.take(10).forEach { finding ->
                store.append(
                    ScanEvent(
                        timestamp = System.currentTimeMillis(),
                        kind = dev.adfection.scanner.data.EventKind.APP_FINDING,
                        severity = finding.severity,
                        category = null,
                        subject = finding.packageName,
                        detail = "risk ${finding.riskPoints}: ${finding.reasons.joinToString("; ")}",
                        action = dev.adfection.scanner.data.Action.LOGGED,
                    )
                )
            }
            refreshLog()
        }
    }

    fun refreshLog() {
        viewModelScope.launch { _events.value = store.recent(300) }
    }

    fun clearLog() {
        viewModelScope.launch {
            store.clear()
            refreshLog()
        }
    }

    fun setBlockAds(value: Boolean) {
        settings.setBlockAds(value)
        _config.value = settings.state.value
    }

    fun setAlertTracking(value: Boolean) {
        settings.setAlertTracking(value)
        _config.value = settings.state.value
    }

    fun setBlockAdint(value: Boolean) {
        settings.setBlockAdint(value)
        _config.value = settings.state.value
    }

    override fun onCleared() {
        store.close()
        super.onCleared()
    }

}
