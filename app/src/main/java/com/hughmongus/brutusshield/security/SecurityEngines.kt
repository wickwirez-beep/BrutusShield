package com.hughmongus.brutusshield.security

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.documentfile.provider.DocumentFile
import com.hughmongus.brutusshield.model.ApkAnalysis
import com.hughmongus.brutusshield.model.AppFinding
import com.hughmongus.brutusshield.model.FileFinding
import com.hughmongus.brutusshield.model.LinkAnalysis
import com.hughmongus.brutusshield.model.RiskLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.net.IDN
import java.net.URI
import java.security.MessageDigest
import kotlin.coroutines.coroutineContext

object FileSecurityEngine {
    private val executableExtensions = setOf(
        "apk", "xapk", "apks", "aab", "dex", "jar", "sh", "bat", "cmd", "exe", "msi"
    )

    private val lureWords = setOf(
        "crack", "cracked", "hack", "modmenu", "mod_menu", "keygen", "patcher",
        "unlocked", "premium_free", "security_update", "urgent_update"
    )

    suspend fun scanTree(
        context: Context,
        treeUri: Uri,
        deep: Boolean,
        onProgress: suspend (count: Int, currentName: String) -> Unit
    ): Pair<Int, List<FileFinding>> = withContext(Dispatchers.IO) {
        val root = DocumentFile.fromTreeUri(context, treeUri)
            ?: error("Android could not open the selected folder.")

        var scanned = 0
        val findings = mutableListOf<FileFinding>()

        suspend fun visit(document: DocumentFile, depth: Int) {
            coroutineContext.ensureActive()

            if (document.isDirectory) {
                if (!deep && depth > 0) return
                document.listFiles().forEach { child ->
                    visit(child, depth + 1)
                }
                return
            }

            if (!document.isFile) return
            scanned += 1
            val name = document.name ?: "Unnamed file"
            if (scanned == 1 || scanned % 20 == 0) {
                onProgress(scanned, name)
            }

            inspectFile(document)?.let(findings::add)
        }

        visit(root, 0)
        onProgress(scanned, "Scan complete")
        scanned to findings.sortedWith(
            compareByDescending<FileFinding> { it.riskLevel.ordinal }
                .thenByDescending { it.sizeBytes }
        )
    }

    private fun inspectFile(document: DocumentFile): FileFinding? {
        val name = document.name ?: return null
        val lower = name.lowercase()
        val extension = lower.substringAfterLast('.', "")
        val reasons = mutableListOf<String>()
        var score = 0

        if (extension in executableExtensions) {
            score += if (extension in setOf("apk", "xapk", "apks", "aab")) 2 else 4
            reasons += if (extension in setOf("apk", "xapk", "apks", "aab")) {
                "Installable Android package—review its source before opening."
            } else {
                "Executable or script file detected in user storage."
            }
        }

        val extensionParts = lower.split('.')
        if (extensionParts.size >= 3 && extension in executableExtensions) {
            val disguisedType = extensionParts[extensionParts.lastIndex - 1]
            if (disguisedType in setOf("jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "mp3", "mp4")) {
                score += 5
                reasons += "Double extension may disguise an executable as $disguisedType."
            }
        }

        if (lureWords.any(lower::contains)) {
            score += 2
            reasons += "Filename contains wording commonly used by modified or deceptive downloads."
        }

        val size = document.length()
        if (size == 0L) {
            score += 1
            reasons += "File is empty or could not be read correctly."
        }
        if (extension == "apk" && size > 800L * 1024L * 1024L) {
            score += 2
            reasons += "APK is unusually large."
        }

        if (score == 0) return null
        val risk = riskFromScore(score)
        return FileFinding(
            name = name,
            uri = document.uri,
            sizeBytes = size,
            riskLevel = risk,
            reasons = reasons.distinct()
        )
    }

    suspend fun quarantine(context: Context, finding: FileFinding): QuarantineResult =
        withContext(Dispatchers.IO) {
            val resolver = context.contentResolver
            val source = DocumentFile.fromSingleUri(context, finding.uri)
            val safeName = finding.name.replace(Regex("[^A-Za-z0-9._-]"), "_")
            val quarantineDir = File(context.filesDir, "quarantine").apply { mkdirs() }
            val destination = File(quarantineDir, "${System.currentTimeMillis()}_$safeName.quarantined")

            resolver.openInputStream(finding.uri).use { input ->
                requireNotNull(input) { "The selected file could not be opened." }
                FileOutputStream(destination).use { output -> input.copyTo(output) }
            }

            val deleted = source?.delete() == true
            QuarantineResult(destination.absolutePath, deleted)
        }
}

data class QuarantineResult(
    val privateCopyPath: String,
    val originalDeleted: Boolean
)

object AppAuditEngine {
    private val permissionWeights = linkedMapOf(
        Manifest.permission.REQUEST_INSTALL_PACKAGES to Pair(5, "Can request installation of other apps."),
        Manifest.permission.SYSTEM_ALERT_WINDOW to Pair(4, "Can draw over other apps."),
        Manifest.permission.SEND_SMS to Pair(5, "Can send SMS messages."),
        Manifest.permission.READ_SMS to Pair(3, "Can read SMS messages."),
        Manifest.permission.RECEIVE_SMS to Pair(3, "Can receive SMS messages."),
        Manifest.permission.READ_CALL_LOG to Pair(3, "Can read call history."),
        Manifest.permission.WRITE_CALL_LOG to Pair(4, "Can modify call history."),
        Manifest.permission.RECORD_AUDIO to Pair(2, "Can access the microphone."),
        Manifest.permission.CAMERA to Pair(1, "Can access the camera."),
        Manifest.permission.READ_CONTACTS to Pair(2, "Can read contacts."),
        Manifest.permission.ACCESS_FINE_LOCATION to Pair(1, "Can access precise location."),
        Manifest.permission.RECEIVE_BOOT_COMPLETED to Pair(1, "Can start after the phone boots.")
    )

    suspend fun auditInstalledApps(context: Context): List<AppFinding> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }

        packages.mapNotNull { packageInfo -> analyzePackage(pm, packageInfo) }
            .sortedWith(
                compareByDescending<AppFinding> { it.score }
                    .thenBy { it.appName.lowercase() }
            )
    }

    private fun analyzePackage(pm: PackageManager, packageInfo: PackageInfo): AppFinding? {
        val appInfo = packageInfo.applicationInfo ?: return null
        val isSystem = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
        if (isSystem) return null

        var score = 0
        val reasons = mutableListOf<String>()
        val requested = packageInfo.requestedPermissions?.toSet().orEmpty()

        permissionWeights.forEach { (permission, weightedReason) ->
            if (permission in requested) {
                score += weightedReason.first
                reasons += weightedReason.second
            }
        }

        val accessibilityService = packageInfo.services.orEmpty().any {
            it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE
        }
        if (accessibilityService) {
            score += 5
            reasons += "Declares an accessibility service, which can observe and control screen interactions when enabled."
        }

        val hasLauncher = pm.getLaunchIntentForPackage(packageInfo.packageName) != null
        if (!hasLauncher) {
            score += 1
            reasons += "No normal launcher icon was found."
        }

        val installer = runCatching {
            if (Build.VERSION.SDK_INT >= 30) {
                pm.getInstallSourceInfo(packageInfo.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageInfo.packageName)
            }
        }.getOrNull()

        val recognizedStores = setOf(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.amazon.venezia"
        )
        if (installer == null || installer !in recognizedStores) {
            score += 2
            reasons += "Not installed by a recognized app store or installer identity is unavailable."
        }

        if (score < 3) return null
        val label = runCatching { appInfo.loadLabel(pm).toString() }
            .getOrElse { packageInfo.packageName }

        return AppFinding(
            packageName = packageInfo.packageName,
            appName = label,
            versionName = packageInfo.versionName ?: "Unknown",
            riskLevel = riskFromScore(score),
            score = score,
            reasons = reasons.distinct(),
            isSystemApp = false
        )
    }
}

object ApkAnalyzerEngine {
    suspend fun analyze(context: Context, uri: Uri): ApkAnalysis = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver
        val displayName = DocumentFile.fromSingleUri(context, uri)?.name ?: "selected.apk"
        val cacheFile = File(context.cacheDir, "analysis_${System.currentTimeMillis()}.apk")

        resolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "APK could not be opened." }
            FileOutputStream(cacheFile).use { output -> input.copyTo(output) }
        }

        try {
            val pm = context.packageManager
            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or if (Build.VERSION.SDK_INT >= 28) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }

            val packageInfo = if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageArchiveInfo(
                    cacheFile.absolutePath,
                    PackageManager.PackageInfoFlags.of(flags.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageArchiveInfo(cacheFile.absolutePath, flags)
            } ?: error("Android could not read this APK. It may be damaged or use an unsupported format.")

            val appInfo = packageInfo.applicationInfo
            if (appInfo != null) {
                appInfo.sourceDir = cacheFile.absolutePath
                appInfo.publicSourceDir = cacheFile.absolutePath
            }

            val appName = runCatching { appInfo?.loadLabel(pm)?.toString() }
                .getOrNull()
                ?: packageInfo.packageName
            val requested = packageInfo.requestedPermissions?.sorted().orEmpty()

            var score = 0
            val reasons = mutableListOf<String>()
            val sensitivePermissions = mapOf(
                Manifest.permission.REQUEST_INSTALL_PACKAGES to Pair(5, "Can request installation of other apps."),
                Manifest.permission.SYSTEM_ALERT_WINDOW to Pair(4, "Can draw over other apps."),
                Manifest.permission.SEND_SMS to Pair(5, "Can send SMS messages."),
                Manifest.permission.READ_SMS to Pair(3, "Can read SMS messages."),
                Manifest.permission.RECORD_AUDIO to Pair(2, "Can access the microphone."),
                Manifest.permission.READ_CONTACTS to Pair(2, "Can read contacts."),
                Manifest.permission.ACCESS_FINE_LOCATION to Pair(1, "Can access precise location."),
                Manifest.permission.RECEIVE_BOOT_COMPLETED to Pair(1, "Can start after device boot.")
            )
            sensitivePermissions.forEach { (permission, detail) ->
                if (permission in requested) {
                    score += detail.first
                    reasons += detail.second
                }
            }

            val accessibilityService = packageInfo.services.orEmpty().any {
                it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE
            }
            if (accessibilityService) {
                score += 5
                reasons += "Declares an accessibility service."
            }

            if (appInfo?.flags?.and(ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                score += 2
                reasons += "APK is marked debuggable."
            }

            if (reasons.isEmpty()) {
                reasons += "No high-risk permission combination was detected by the local analyzer."
            }

            ApkAnalysis(
                fileName = displayName,
                appName = appName,
                packageName = packageInfo.packageName,
                versionName = packageInfo.versionName ?: "Unknown",
                sha256 = sha256(cacheFile),
                riskLevel = riskFromScore(score),
                score = score,
                reasons = reasons.distinct(),
                requestedPermissions = requested
            )
        } finally {
            cacheFile.delete()
        }
    }
}

object LinkAnalyzerEngine {
    private val shorteners = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "cutt.ly", "rb.gy"
    )

    fun analyze(rawInput: String): LinkAnalysis {
        val trimmed = rawInput.trim()
        require(trimmed.isNotBlank()) { "Enter a link first." }
        val normalized = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val uri = runCatching { URI(normalized) }
            .getOrElse { error("That link is not formatted correctly.") }
        val host = uri.host?.lowercase() ?: error("The link does not contain a valid host name.")

        var score = 0
        val reasons = mutableListOf<String>()
        if (uri.scheme?.lowercase() != "https") {
            score += 3
            reasons += "Connection is not protected by HTTPS."
        }
        if (host in shorteners) {
            score += 2
            reasons += "Shortened link hides the final destination."
        }
        if (host.contains("xn--")) {
            score += 4
            reasons += "Internationalized/punycode host can imitate familiar domain names."
        }
        if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
            score += 3
            reasons += "Link uses a raw IP address instead of a normal domain."
        }
        if (normalized.contains('@')) {
            score += 3
            reasons += "The @ symbol can conceal the true destination."
        }
        if (host.count { it == '.' } >= 4) {
            score += 1
            reasons += "Host contains an unusually deep chain of subdomains."
        }
        val lureText = (host + (uri.path ?: "")).lowercase()
        if (setOf("verify", "urgent", "account", "password", "wallet", "security-update").any(lureText::contains)) {
            score += 2
            reasons += "Link contains urgency or account-verification wording."
        }
        val port = uri.port
        if (port != -1 && port !in setOf(80, 443)) {
            score += 1
            reasons += "Link uses a non-standard network port."
        }

        val unicodeHost = runCatching { IDN.toUnicode(host) }.getOrDefault(host)
        if (reasons.isEmpty()) {
            reasons += "No obvious local warning signs were detected. This is not a guarantee that the site is safe."
        }

        return LinkAnalysis(
            normalizedUrl = normalized,
            host = unicodeHost,
            riskLevel = riskFromScore(score),
            score = score,
            reasons = reasons
        )
    }
}

private fun riskFromScore(score: Int): RiskLevel = when {
    score >= 9 -> RiskLevel.DANGEROUS
    score >= 4 -> RiskLevel.CAUTION
    score >= 1 -> RiskLevel.LOW
    else -> RiskLevel.CLEAR
}

private fun sha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
