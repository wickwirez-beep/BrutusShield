package com.hughmongus.brutusshield.security

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
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
        "apk", "xapk", "apks", "aab", "dex", "jar", "sh", "bat", "cmd", "exe", "msi", "dll", "so"
    )

    private val androidPackageExtensions = setOf("apk", "xapk", "apks", "aab")

    private val lureWords = setOf(
        "crack", "cracked", "hack", "modmenu", "mod_menu", "keygen", "patcher",
        "unlocked", "premium_free", "security_update", "urgent_update", "bypass", "injector"
    )

    private val benignLookingExtensions = setOf(
        "jpg", "jpeg", "png", "gif", "webp", "pdf", "doc", "docx", "xls", "xlsx",
        "mp3", "wav", "mp4", "mkv", "txt"
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
                document.listFiles().forEach { child -> visit(child, depth + 1) }
                return
            }

            if (!document.isFile) return
            scanned += 1
            val name = document.name ?: "Unnamed file"
            if (scanned == 1 || scanned % 20 == 0) onProgress(scanned, name)
            inspectDocumentFile(document)?.let(findings::add)
        }

        visit(root, 0)
        onProgress(scanned, "Folder scan complete")
        scanned to sortFindings(findings)
    }

    suspend fun scanDevice(
        context: Context,
        onProgress: suspend (count: Int, currentName: String) -> Unit
    ): Pair<Int, List<FileFinding>> = withContext(Dispatchers.IO) {
        check(StorageAccessManager.hasFullStorageAccess(context)) {
            "All Files Access is required for a full shared-storage scan."
        }

        val roots = externalStorageRoots(context)
        if (roots.isEmpty()) error("No readable shared-storage volume was found.")

        val stack = java.util.ArrayDeque<File>()
        roots.forEach(stack::addLast)
        val visitedDirectories = HashSet<String>()
        val findings = mutableListOf<FileFinding>()
        var scanned = 0

        while (stack.isNotEmpty()) {
            coroutineContext.ensureActive()
            val current = stack.removeLast()

            if (current.isDirectory) {
                val canonical = runCatching { current.canonicalPath }.getOrDefault(current.absolutePath)
                if (!visitedDirectories.add(canonical) || shouldSkipDirectory(canonical, context)) continue
                runCatching { current.listFiles() }
                    .getOrNull()
                    ?.forEach(stack::addLast)
                continue
            }

            if (!current.isFile || !current.canRead()) continue
            scanned += 1
            if (scanned == 1 || scanned % 25 == 0) {
                onProgress(scanned, current.absolutePath)
            }
            inspectRawFile(context, current)?.let(findings::add)
        }

        onProgress(scanned, "Full shared-storage scan complete")
        scanned to sortFindings(findings)
    }

    private fun externalStorageRoots(context: Context): List<File> {
        val candidates = linkedSetOf<File>()
        @Suppress("DEPRECATION")
        candidates += Environment.getExternalStorageDirectory()

        context.getExternalFilesDirs(null).forEach { appDirectory ->
            if (appDirectory == null) return@forEach
            val marker = "/Android/data/${context.packageName}/files"
            val path = appDirectory.absolutePath
            val rootPath = path.substringBefore(marker, missingDelimiterValue = path)
            candidates += File(rootPath)
        }

        return candidates
            .filter { it.exists() && it.isDirectory && it.canRead() }
            .distinctBy { runCatching { it.canonicalPath }.getOrDefault(it.absolutePath) }
    }

    private fun shouldSkipDirectory(path: String, context: Context): Boolean {
        val normalized = path.replace('\\', '/')
        if (normalized.contains("/Android/data/") || normalized.endsWith("/Android/data")) return true
        if (normalized.contains("/Android/obb/") || normalized.endsWith("/Android/obb")) return true
        val quarantine = File(context.filesDir, "quarantine").absolutePath.replace('\\', '/')
        return normalized.startsWith(quarantine)
    }

    private fun inspectDocumentFile(document: DocumentFile): FileFinding? {
        val name = document.name ?: return null
        val assessment = assessNameAndSize(name, document.length())
        if (assessment.score == 0) return null
        return FileFinding(
            name = name,
            uri = document.uri,
            sizeBytes = document.length(),
            riskLevel = riskFromScore(assessment.score),
            reasons = assessment.reasons.distinct()
        )
    }

    private fun inspectRawFile(context: Context, file: File): FileFinding? {
        val name = file.name
        val extension = name.lowercase().substringAfterLast('.', "")
        val assessment = assessNameAndSize(name, file.length())
        var score = assessment.score
        val reasons = assessment.reasons.toMutableList()
        val header = readHeader(file, 4096)

        val isZip = header.startsWithBytes(0x50, 0x4B)
        val isWindowsExecutable = header.startsWithBytes(0x4D, 0x5A)
        val isElf = header.startsWithBytes(0x7F, 0x45, 0x4C, 0x46)
        val isDex = header.startsWithBytes(0x64, 0x65, 0x78, 0x0A)
        val executableMagic = isWindowsExecutable || isElf || isDex
        val headerText = header.toString(Charsets.ISO_8859_1)

        if ("X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" in headerText) {
            score += 10
            reasons += "EICAR antivirus test signature detected."
        }

        if (extension in androidPackageExtensions && !isZip) {
            score += 6
            reasons += "Android-package extension does not contain a valid ZIP/APK header."
        }

        if (extension in benignLookingExtensions && executableMagic) {
            score += 9
            reasons += "File content is executable even though the filename looks like a document or media file."
        } else if (extension.isBlank() && executableMagic) {
            score += 6
            reasons += "Executable content has no filename extension."
        }

        if (extension in setOf("exe", "dll", "msi") && !isWindowsExecutable) {
            score += 3
            reasons += "Windows-executable extension does not match the file signature."
        }

        if (extension == "apk" && isZip) {
            val apkAssessment = assessApkAtPath(context, file)
            score += apkAssessment.score
            reasons += apkAssessment.reasons
        }

        if (score == 0) return null
        val digest = if (extension in executableExtensions || score >= 4) {
            runCatching { sha256(file) }.getOrNull()
        } else null

        return FileFinding(
            name = name,
            uri = Uri.fromFile(file),
            sizeBytes = file.length(),
            riskLevel = riskFromScore(score),
            reasons = reasons.distinct(),
            sha256 = digest
        )
    }

    private fun assessNameAndSize(name: String, size: Long): FileAssessment {
        val lower = name.lowercase()
        val extension = lower.substringAfterLast('.', "")
        val reasons = mutableListOf<String>()
        var score = 0

        if (extension in executableExtensions) {
            score += if (extension in androidPackageExtensions) 2 else 4
            reasons += if (extension in androidPackageExtensions) {
                "Installable Android package—review its source before opening."
            } else {
                "Executable, native library, or script file detected in shared storage."
            }
        }

        val extensionParts = lower.split('.')
        if (extensionParts.size >= 3 && extension in executableExtensions) {
            val disguisedType = extensionParts[extensionParts.lastIndex - 1]
            if (disguisedType in benignLookingExtensions) {
                score += 5
                reasons += "Double extension may disguise an executable as $disguisedType."
            }
        }

        if (lureWords.any(lower::contains)) {
            score += 2
            reasons += "Filename contains wording commonly used by modified or deceptive downloads."
        }

        if (size == 0L) {
            score += 1
            reasons += "File is empty or could not be read correctly."
        }
        if (extension == "apk" && size > 800L * 1024L * 1024L) {
            score += 2
            reasons += "APK is unusually large."
        }

        return FileAssessment(score, reasons)
    }

    private fun assessApkAtPath(context: Context, file: File): FileAssessment {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
        val packageInfo = if (Build.VERSION.SDK_INT >= 33) {
            context.packageManager.getPackageArchiveInfo(
                file.absolutePath,
                PackageManager.PackageInfoFlags.of(flags.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageArchiveInfo(file.absolutePath, flags)
        }

        if (packageInfo == null) {
            return FileAssessment(5, mutableListOf("APK manifest could not be parsed; the package may be damaged or deceptive."))
        }

        var score = 0
        val reasons = mutableListOf<String>()
        val permissions = packageInfo.requestedPermissions?.toSet().orEmpty()
        val highRisk = mapOf(
            Manifest.permission.REQUEST_INSTALL_PACKAGES to Pair(4, "APK can request installation of other apps."),
            Manifest.permission.SYSTEM_ALERT_WINDOW to Pair(3, "APK can request drawing over other apps."),
            Manifest.permission.SEND_SMS to Pair(4, "APK requests permission to send SMS messages."),
            Manifest.permission.READ_SMS to Pair(3, "APK requests permission to read SMS messages."),
            Manifest.permission.WRITE_CALL_LOG to Pair(4, "APK requests permission to modify call history.")
        )
        highRisk.forEach { (permission, detail) ->
            if (permission in permissions) {
                score += detail.first
                reasons += detail.second
            }
        }

        if (packageInfo.services.orEmpty().any { it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE }) {
            score += 5
            reasons += "APK declares an accessibility service capable of observing or controlling screen interactions when enabled."
        }

        val appInfo = packageInfo.applicationInfo
        if (appInfo != null && appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            score += 2
            reasons += "APK is marked debuggable."
        }

        return FileAssessment(score, reasons)
    }

    private fun readHeader(file: File, count: Int): ByteArray {
        if (file.length() <= 0L) return byteArrayOf()
        return runCatching {
            file.inputStream().buffered().use { input ->
                val buffer = ByteArray(count)
                val read = input.read(buffer)
                if (read <= 0) byteArrayOf() else buffer.copyOf(read)
            }
        }.getOrDefault(byteArrayOf())
    }

    private fun ByteArray.startsWithBytes(vararg expected: Int): Boolean {
        if (size < expected.size) return false
        return expected.indices.all { index -> this[index].toInt() and 0xFF == expected[index] }
    }

    private fun sortFindings(findings: List<FileFinding>): List<FileFinding> = findings.sortedWith(
        compareByDescending<FileFinding> { it.riskLevel.ordinal }
            .thenByDescending { it.sizeBytes }
    )

    suspend fun quarantine(context: Context, finding: FileFinding): QuarantineResult =
        withContext(Dispatchers.IO) {
            val safeName = finding.name.replace(Regex("[^A-Za-z0-9._-]"), "_")
            val quarantineDir = File(context.filesDir, "quarantine").apply { mkdirs() }
            val destination = File(quarantineDir, "${System.currentTimeMillis()}_$safeName.quarantined")

            val deleted = if (finding.uri.scheme == "file") {
                val source = File(requireNotNull(finding.uri.path) { "The file path is unavailable." })
                source.inputStream().use { input ->
                    FileOutputStream(destination).use { output -> input.copyTo(output) }
                }
                source.delete()
            } else {
                val resolver = context.contentResolver
                resolver.openInputStream(finding.uri).use { input ->
                    requireNotNull(input) { "The selected file could not be opened." }
                    FileOutputStream(destination).use { output -> input.copyTo(output) }
                }
                DocumentFile.fromSingleUri(context, finding.uri)?.delete() == true
            }

            QuarantineResult(destination.absolutePath, deleted)
        }

    private data class FileAssessment(
        val score: Int,
        val reasons: MutableList<String>
    )
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
            ApkMalwareAnalyzer.analyze(context, cacheFile, displayName)
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
