package com.hughmongus.brutusshield.model

import android.net.Uri

enum class Screen {
    HOME,
    FILE_RESULTS,
    APP_AUDIT,
    APK_ANALYZER,
    LINK_SCANNER,
    HISTORY,
    ABOUT
}

enum class RiskLevel(val displayName: String) {
    CLEAR("All clear"),
    LOW("Low risk"),
    CAUTION("Caution"),
    DANGEROUS("Dangerous")
}

data class FileFinding(
    val name: String,
    val uri: Uri,
    val sizeBytes: Long,
    val riskLevel: RiskLevel,
    val reasons: List<String>,
    val sha256: String? = null
)

data class AppFinding(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val riskLevel: RiskLevel,
    val score: Int,
    val reasons: List<String>,
    val isSystemApp: Boolean
)

data class ApkAnalysis(
    val fileName: String,
    val appName: String,
    val packageName: String,
    val versionName: String,
    val sha256: String,
    val riskLevel: RiskLevel,
    val score: Int,
    val reasons: List<String>,
    val requestedPermissions: List<String>
)

data class LinkAnalysis(
    val normalizedUrl: String,
    val host: String,
    val riskLevel: RiskLevel,
    val score: Int,
    val reasons: List<String>
)

data class ScanSummary(
    val scannedCount: Int = 0,
    val flaggedCount: Int = 0,
    val dangerousCount: Int = 0,
    val elapsedMillis: Long = 0L
)

sealed interface ScanState {
    data object Idle : ScanState
    data class Running(
        val scannedCount: Int,
        val currentName: String,
        val deep: Boolean
    ) : ScanState
    data class Finished(
        val summary: ScanSummary,
        val findings: List<FileFinding>
    ) : ScanState
    data class Failed(val message: String) : ScanState
}

data class HistoryEntry(
    val timestamp: Long,
    val title: String,
    val detail: String,
    val riskLevel: RiskLevel
)
