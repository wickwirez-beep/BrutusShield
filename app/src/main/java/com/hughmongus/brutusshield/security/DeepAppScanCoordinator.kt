package com.hughmongus.brutusshield.security

import android.content.Context

/**
 * Minimal bridge for BrutusViewModel.
 *
 * Pass the existing threat database's SHA-256 sets into this class. Keep the
 * database local until a signed rule-update channel is added.
 */
class DeepAppScanCoordinator(
    context: Context,
    knownBadApkHashes: Set<String>,
    knownGoodApkHashes: Set<String> = emptySet(),
    trustedSignerHashes: Set<String> = emptySet(),
) {
    private val scanner = InstalledAppDeepScanner(
        context = context,
        knownBadApkHashes = knownBadApkHashes,
        knownGoodApkHashes = knownGoodApkHashes,
        trustedSignerHashes = trustedSignerHashes,
    )

    suspend fun run(
        includeSystemApps: Boolean = false,
        onProgress: (DeepAppScanProgress) -> Unit = {},
    ): List<DeepAppScanResult> =
        scanner.scanInstalledApps(
            includeSystemApps = includeSystemApps,
            onProgress = onProgress,
        )
}
