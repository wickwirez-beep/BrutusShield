package com.hughmongus.brutusshield

import android.content.Context
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hughmongus.brutusshield.model.ApkAnalysis
import com.hughmongus.brutusshield.model.AppFinding
import com.hughmongus.brutusshield.model.FileFinding
import com.hughmongus.brutusshield.model.HistoryEntry
import com.hughmongus.brutusshield.model.LinkAnalysis
import com.hughmongus.brutusshield.model.RiskLevel
import com.hughmongus.brutusshield.model.ScanState
import com.hughmongus.brutusshield.model.ScanSummary
import com.hughmongus.brutusshield.model.Screen
import com.hughmongus.brutusshield.security.ApkAnalyzerEngine
import com.hughmongus.brutusshield.security.AppAuditEngine
import com.hughmongus.brutusshield.security.FileSecurityEngine
import com.hughmongus.brutusshield.security.LinkAnalyzerEngine
import com.hughmongus.brutusshield.security.MalwareScanEngine
import com.hughmongus.brutusshield.security.QuarantineResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class BrutusViewModel : ViewModel() {
    var screen by mutableStateOf(Screen.HOME)
        private set

    var scanState by mutableStateOf<ScanState>(ScanState.Idle)
        private set

    var appFindings by mutableStateOf<List<AppFinding>>(emptyList())
        private set

    var appAuditRunning by mutableStateOf(false)
        private set

    var apkAnalysis by mutableStateOf<ApkAnalysis?>(null)
        private set

    var apkAnalysisRunning by mutableStateOf(false)
        private set

    var linkAnalysis by mutableStateOf<LinkAnalysis?>(null)
        private set

    var history by mutableStateOf<List<HistoryEntry>>(emptyList())
        private set

    var bannerMessage by mutableStateOf<String?>(null)
        private set

    private var scanJob: Job? = null

    fun navigate(destination: Screen) {
        screen = destination
        bannerMessage = null
    }

    fun goHome() {
        screen = Screen.HOME
        bannerMessage = null
    }

    fun showMessage(message: String) {
        bannerMessage = message
    }

    fun clearMessage() {
        bannerMessage = null
    }

    fun runFileScan(context: Context, treeUri: Uri, deep: Boolean) {
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            val started = System.currentTimeMillis()
            scanState = ScanState.Running(0, "Preparing folder scanner", false)
            screen = Screen.FILE_RESULTS

            try {
                val (count, findings) = FileSecurityEngine.scanTree(
                    context = context,
                    treeUri = treeUri,
                    deep = deep,
                    onProgress = { scanned, name ->
                        scanState = ScanState.Running(scanned, name, false)
                    }
                )
                val summary = ScanSummary(
                    scannedCount = count,
                    flaggedCount = findings.size,
                    dangerousCount = findings.count { it.riskLevel == RiskLevel.DANGEROUS },
                    elapsedMillis = System.currentTimeMillis() - started
                )
                scanState = ScanState.Finished(summary, findings)
                addHistory(
                    title = if (deep) "Recursive folder scan" else "Quick folder scan",
                    detail = "$count files checked, ${findings.size} flagged",
                    risk = when {
                        summary.dangerousCount > 0 -> RiskLevel.DANGEROUS
                        summary.flaggedCount > 0 -> RiskLevel.CAUTION
                        else -> RiskLevel.CLEAR
                    }
                )
            } catch (_: CancellationException) {
                scanState = ScanState.Idle
                bannerMessage = "Scan stopped."
            } catch (error: Throwable) {
                scanState = ScanState.Failed(error.message ?: "The scan could not be completed.")
            }
        }
    }


    fun runMalwareScan(context: Context) {
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            val started = System.currentTimeMillis()
            scanState = ScanState.Running(0, "Loading offline malware signatures", true)
            screen = Screen.MALWARE_RESULTS

            try {
                val (count, findings) = MalwareScanEngine.scanDevice(
                    context = context,
                    onProgress = { scanned, name ->
                        scanState = ScanState.Running(scanned, name, true)
                    }
                )
                val summary = ScanSummary(
                    scannedCount = count,
                    flaggedCount = findings.size,
                    dangerousCount = findings.count { it.riskLevel == RiskLevel.DANGEROUS },
                    elapsedMillis = System.currentTimeMillis() - started
                )
                scanState = ScanState.Finished(summary, findings)
                addHistory(
                    title = "Malware scan",
                    detail = "$count files and installed apps checked, ${findings.size} findings",
                    risk = when {
                        summary.dangerousCount > 0 -> RiskLevel.DANGEROUS
                        summary.flaggedCount > 0 -> RiskLevel.CAUTION
                        else -> RiskLevel.CLEAR
                    }
                )
            } catch (_: CancellationException) {
                scanState = ScanState.Idle
                bannerMessage = "Malware scan stopped."
            } catch (error: Throwable) {
                scanState = ScanState.Failed(error.message ?: "The malware scan could not be completed.")
            }
        }
    }

    fun runDeepScan(context: Context) {
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            val started = System.currentTimeMillis()
            scanState = ScanState.Running(0, "Preparing full shared-storage scan", true)
            screen = Screen.FILE_RESULTS

            try {
                val (count, findings) = FileSecurityEngine.scanDevice(
                    context = context,
                    onProgress = { scanned, name ->
                        scanState = ScanState.Running(scanned, name, true)
                    }
                )
                val summary = ScanSummary(
                    scannedCount = count,
                    flaggedCount = findings.size,
                    dangerousCount = findings.count { it.riskLevel == RiskLevel.DANGEROUS },
                    elapsedMillis = System.currentTimeMillis() - started
                )
                scanState = ScanState.Finished(summary, findings)
                addHistory(
                    title = "Full deep scan",
                    detail = "$count files checked across shared storage, ${findings.size} flagged",
                    risk = when {
                        summary.dangerousCount > 0 -> RiskLevel.DANGEROUS
                        summary.flaggedCount > 0 -> RiskLevel.CAUTION
                        else -> RiskLevel.CLEAR
                    }
                )
            } catch (_: CancellationException) {
                scanState = ScanState.Idle
                bannerMessage = "Deep scan stopped."
            } catch (error: Throwable) {
                scanState = ScanState.Failed(error.message ?: "The deep scan could not be completed.")
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        scanJob = null
    }

    fun runAppAudit(context: Context) {
        if (appAuditRunning) return
        appAuditRunning = true
        appFindings = emptyList()
        screen = Screen.APP_AUDIT
        viewModelScope.launch {
            try {
                appFindings = AppAuditEngine.auditInstalledApps(context)
                addHistory(
                    title = "Installed-app audit",
                    detail = "${appFindings.size} apps have reviewable risk indicators",
                    risk = when {
                        appFindings.any { it.riskLevel == RiskLevel.DANGEROUS } -> RiskLevel.DANGEROUS
                        appFindings.isNotEmpty() -> RiskLevel.CAUTION
                        else -> RiskLevel.CLEAR
                    }
                )
            } catch (error: Throwable) {
                bannerMessage = error.message ?: "App audit failed."
            } finally {
                appAuditRunning = false
            }
        }
    }

    fun analyzeApk(context: Context, uri: Uri) {
        apkAnalysisRunning = true
        apkAnalysis = null
        screen = Screen.APK_ANALYZER
        viewModelScope.launch {
            try {
                apkAnalysis = ApkAnalyzerEngine.analyze(context, uri)
                val analysis = apkAnalysis
                if (analysis != null) {
                    addHistory(
                        title = "APK analyzed",
                        detail = "${analysis.appName}: ${analysis.riskLevel.displayName}",
                        risk = analysis.riskLevel
                    )
                }
            } catch (error: Throwable) {
                bannerMessage = error.message ?: "APK analysis failed."
            } finally {
                apkAnalysisRunning = false
            }
        }
    }

    fun analyzeLink(rawLink: String) {
        try {
            linkAnalysis = LinkAnalyzerEngine.analyze(rawLink)
            val result = linkAnalysis
            if (result != null) {
                addHistory(
                    title = "Link checked",
                    detail = "${result.host}: ${result.riskLevel.displayName}",
                    risk = result.riskLevel
                )
            }
        } catch (error: Throwable) {
            bannerMessage = error.message ?: "Link analysis failed."
        }
    }

    fun quarantine(context: Context, finding: FileFinding, onComplete: (QuarantineResult?) -> Unit) {
        if (!finding.canQuarantine) {
            bannerMessage = "Installed apps cannot be quarantined as files. Open app settings to uninstall or disable them."
            onComplete(null)
            return
        }
        viewModelScope.launch {
            try {
                val result = FileSecurityEngine.quarantine(context, finding)
                val current = scanState
                if (current is ScanState.Finished) {
                    scanState = current.copy(
                        findings = current.findings.filterNot { it.uri == finding.uri },
                        summary = current.summary.copy(
                            flaggedCount = (current.summary.flaggedCount - 1).coerceAtLeast(0),
                            dangerousCount = if (finding.riskLevel == RiskLevel.DANGEROUS) {
                                (current.summary.dangerousCount - 1).coerceAtLeast(0)
                            } else current.summary.dangerousCount
                        )
                    )
                }
                addHistory(
                    title = "File quarantined",
                    detail = finding.name,
                    risk = finding.riskLevel
                )
                onComplete(result)
            } catch (error: Throwable) {
                bannerMessage = error.message ?: "Quarantine failed."
                onComplete(null)
            }
        }
    }

    fun statusReport(): String {
        val scan = scanState
        return when {
            scan is ScanState.Running -> "Scan in progress. ${scan.scannedCount} files checked so far."
            scan is ScanState.Finished && scan.summary.dangerousCount > 0 ->
                "Security alert. ${scan.summary.dangerousCount} dangerous malware or file warnings require review."
            scan is ScanState.Finished && scan.summary.flaggedCount > 0 ->
                "Scan complete. ${scan.summary.flaggedCount} items need your review."
            appFindings.any { it.riskLevel == RiskLevel.DANGEROUS } ->
                "App audit found high risk permission combinations. Review suspicious apps."
            else -> "Brutus Shield is ready. No confirmed active threat has been identified."
        }
    }

    private fun addHistory(title: String, detail: String, risk: RiskLevel) {
        history = listOf(
            HistoryEntry(
                timestamp = System.currentTimeMillis(),
                title = title,
                detail = detail,
                riskLevel = risk
            )
        ) + history.take(24)
    }
}
