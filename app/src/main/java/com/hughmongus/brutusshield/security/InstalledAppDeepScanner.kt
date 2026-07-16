package com.hughmongus.brutusshield.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipFile
import kotlin.coroutines.coroutineContext
import kotlin.math.min

/**
 * Brutus Shield v0.4 deep installed-app scanner.
 *
 * All analysis is local. No APK, package list, hash, certificate, or finding
 * is uploaded.
 *
 * Android does not allow a normal app to inspect another app's private
 * /data/data directory. This scanner goes as deep as Android allows without
 * root: installed APKs, split APKs, package metadata, permissions, components,
 * signing certificates, embedded files, and selected DEX behavior indicators.
 */
class InstalledAppDeepScanner(
    context: Context,
    knownBadApkHashes: Set<String> = emptySet(),
    knownGoodApkHashes: Set<String> = emptySet(),
    trustedSignerHashes: Set<String> = emptySet(),
) {
    private val appContext = context.applicationContext
    private val packageManager = appContext.packageManager
    private val badHashes = knownBadApkHashes.mapTo(hashSetOf(), ::normalizeHash)
    private val goodHashes = knownGoodApkHashes.mapTo(hashSetOf(), ::normalizeHash)
    private val trustedSigners = trustedSignerHashes.mapTo(hashSetOf(), ::normalizeHash)

    suspend fun scanInstalledApps(
        includeSystemApps: Boolean = false,
        onProgress: (DeepAppScanProgress) -> Unit = {},
    ): List<DeepAppScanResult> = withContext(Dispatchers.IO) {
        val packages = installedPackages()
            .filter { includeSystemApps || !it.isSystemApp() }
            .sortedBy { it.packageName.lowercase(Locale.US) }

        val results = ArrayList<DeepAppScanResult>(packages.size)

        packages.forEachIndexed { index, packageInfo ->
            coroutineContext.ensureActive()

            val label = runCatching {
                packageManager.getApplicationLabel(
                    requireNotNull(packageInfo.applicationInfo)
                ).toString()
            }.getOrDefault(packageInfo.packageName)

            onProgress(
                DeepAppScanProgress(
                    current = index + 1,
                    total = packages.size,
                    appLabel = label,
                    packageName = packageInfo.packageName,
                    stage = "Inspecting installed application",
                )
            )

            results += scanPackage(packageInfo, label)
        }

        results.sortedWith(
            compareByDescending<DeepAppScanResult> { it.riskScore }
                .thenBy { it.appLabel.lowercase(Locale.US) }
        )
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags =
            PackageManager.GET_PERMISSIONS or
                PackageManager.GET_SIGNING_CERTIFICATES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_META_DATA

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(flags.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledPackages(flags)
        }
    }

    private fun scanPackage(
        packageInfo: PackageInfo,
        appLabel: String,
    ): DeepAppScanResult {
        val applicationInfo = packageInfo.applicationInfo
        val packageName = packageInfo.packageName
        val findings = mutableListOf<DeepAppFinding>()

        val apkPaths = buildList {
            val base = applicationInfo?.publicSourceDir ?: applicationInfo?.sourceDir
            if (!base.isNullOrBlank()) add(base)

            val splits =
                applicationInfo?.splitPublicSourceDirs
                    ?: applicationInfo?.splitSourceDirs
                    ?: emptyArray()

            addAll(splits.filterNotNull().filter { it.isNotBlank() })
        }.distinct()

        val apkHashes = apkPaths.mapNotNull { path ->
            runCatching {
                val file = File(path)
                DeepApkHash(
                    path = path,
                    sha256 = sha256(file),
                    sizeBytes = file.length(),
                )
            }.onFailure {
                findings += DeepAppFinding(
                    code = "APK_READ_FAILED",
                    title = "APK segment could not be read",
                    detail = "${File(path).name}: ${it.message ?: "unknown error"}",
                    points = 0,
                    confidence = DeepFindingConfidence.INFO,
                )
            }.getOrNull()
        }

        val exactBad = apkHashes.filter { normalizeHash(it.sha256) in badHashes }
        val exactGood = apkHashes.filter { normalizeHash(it.sha256) in goodHashes }

        exactBad.forEach {
            findings += DeepAppFinding(
                code = "KNOWN_BAD_HASH",
                title = "Known malicious APK hash",
                detail = "${File(it.path).name}: ${it.sha256}",
                points = 100,
                confidence = DeepFindingConfidence.EXACT,
            )
        }

        exactGood.forEach {
            findings += DeepAppFinding(
                code = "KNOWN_GOOD_HASH",
                title = "Known clean APK hash",
                detail = "${File(it.path).name}: ${it.sha256}",
                points = 0,
                confidence = DeepFindingConfidence.EXACT,
            )
        }

        val signerHashes = signerCertificateHashes(packageInfo)
        val trustedSigner = signerHashes.any {
            normalizeHash(it) in trustedSigners
        }

        if (trustedSigner) {
            findings += DeepAppFinding(
                code = "TRUSTED_SIGNER",
                title = "Trusted developer signature",
                detail = "The app is signed by a certificate in the local trusted list.",
                points = 0,
                confidence = DeepFindingConfidence.EXACT,
            )
        }

        val permissions = packageInfo.requestedPermissions?.toSet().orEmpty()
        val bindings = sensitiveBindings(packageInfo)
        val installer = installerPackage(packageName)
        val isSystemApp = packageInfo.isSystemApp()
        val isSideloaded =
            installer.isNullOrBlank() || installer !in TRUSTED_INSTALLERS
        val isDebuggable =
            applicationInfo?.flags?.and(ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val targetSdk = applicationInfo?.targetSdkVersion ?: 0
        val cleartextAllowed =
            applicationInfo?.flags?.and(ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0

        addMetadataFindings(
            findings = findings,
            packageInfo = packageInfo,
            permissions = permissions,
            bindings = bindings,
            installer = installer,
            isSideloaded = isSideloaded,
            isDebuggable = isDebuggable,
            isSystemApp = isSystemApp,
            targetSdk = targetSdk,
            cleartextAllowed = cleartextAllowed,
        )

        apkPaths.forEach { path ->
            runCatching {
                inspectApkArchive(File(path), findings)
            }.onFailure {
                findings += DeepAppFinding(
                    code = "APK_ARCHIVE_SCAN_INCOMPLETE",
                    title = "APK archive inspection incomplete",
                    detail = "${File(path).name}: ${it.message ?: "unknown error"}",
                    points = 0,
                    confidence = DeepFindingConfidence.INFO,
                )
            }
        }

        val hasExactBadHash = exactBad.isNotEmpty()
        var score = findings.sumOf { it.points }.coerceIn(0, 100)

        // Trusted homemade/developer apps should not be condemned for being
        // sideloaded or debuggable. An exact malicious hash still overrides.
        if (trustedSigner && !hasExactBadHash) {
            score = min(score, 10)
        }

        // Brutus Shield needs broad visibility and storage-related capabilities
        // to do its job. Do not flag the scanner itself merely for those traits.
        if (packageName == appContext.packageName && !hasExactBadHash) {
            score = 0
        }

        val highConfidenceCount = findings.count {
            it.confidence == DeepFindingConfidence.HIGH ||
                it.confidence == DeepFindingConfidence.EXACT
        }

        val riskLevel = when {
            hasExactBadHash -> DeepAppRiskLevel.DANGEROUS
            score >= 75 && highConfidenceCount >= 2 -> DeepAppRiskLevel.DANGEROUS
            score >= 45 -> DeepAppRiskLevel.SUSPICIOUS
            score >= 20 -> DeepAppRiskLevel.CAUTION
            score >= 8 -> DeepAppRiskLevel.LOW
            else -> DeepAppRiskLevel.SAFE
        }

        return DeepAppScanResult(
            packageName = packageName,
            appLabel = appLabel,
            versionName = packageInfo.versionName ?: "Unknown",
            versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            },
            installerPackage = installer,
            targetSdk = targetSdk,
            isSystemApp = isSystemApp,
            isDebuggable = isDebuggable,
            isSideloaded = isSideloaded,
            apkHashes = apkHashes,
            signerSha256 = signerHashes,
            requestedPermissions = permissions.sorted(),
            sensitiveBindings = bindings.sorted(),
            findings = findings
                .distinctBy { "${it.code}|${it.detail}" }
                .sortedWith(
                    compareByDescending<DeepAppFinding> { it.points }
                        .thenBy { it.title }
                ),
            riskScore = score,
            riskLevel = riskLevel,
        )
    }

    private fun addMetadataFindings(
        findings: MutableList<DeepAppFinding>,
        packageInfo: PackageInfo,
        permissions: Set<String>,
        bindings: Set<String>,
        installer: String?,
        isSideloaded: Boolean,
        isDebuggable: Boolean,
        isSystemApp: Boolean,
        targetSdk: Int,
        cleartextAllowed: Boolean,
    ) {
        fun permission(name: String) = name in permissions
        fun binding(name: String) = name in bindings

        val hasInternet = permission("android.permission.INTERNET")
        val hasOverlay = permission("android.permission.SYSTEM_ALERT_WINDOW")
        val canInstall = permission("android.permission.REQUEST_INSTALL_PACKAGES")
        val readSms = permission("android.permission.READ_SMS")
        val sendSms = permission("android.permission.SEND_SMS")
        val receiveSms = permission("android.permission.RECEIVE_SMS")
        val readContacts = permission("android.permission.READ_CONTACTS")
        val readCallLog = permission("android.permission.READ_CALL_LOG")
        val mic = permission("android.permission.RECORD_AUDIO")
        val camera = permission("android.permission.CAMERA")
        val fineLocation = permission("android.permission.ACCESS_FINE_LOCATION")
        val backgroundLocation =
            permission("android.permission.ACCESS_BACKGROUND_LOCATION")
        val boot = permission("android.permission.RECEIVE_BOOT_COMPLETED")

        val accessibility =
            binding("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val deviceAdmin =
            binding("android.permission.BIND_DEVICE_ADMIN")
        val notificationListener =
            binding("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE")

        if (accessibility && hasOverlay && canInstall) {
            findings += finding(
                "ACCESSIBILITY_OVERLAY_INSTALL_COMBO",
                "Powerful control combination",
                "Accessibility service + screen overlay + app installation capability.",
                38,
                DeepFindingConfidence.HIGH,
            )
        } else {
            if (accessibility) {
                findings += finding(
                    "ACCESSIBILITY_SERVICE",
                    "Accessibility service",
                    "Can observe or interact with screen content after the user enables it.",
                    8,
                    DeepFindingConfidence.MEDIUM,
                )
            }
            if (hasOverlay) {
                findings += finding(
                    "SCREEN_OVERLAY",
                    "Can draw over other apps",
                    "Overlay access can be legitimate but is also used for phishing.",
                    5,
                    DeepFindingConfidence.LOW,
                )
            }
            if (canInstall) {
                findings += finding(
                    "PACKAGE_INSTALLER",
                    "Can request APK installation",
                    "Can ask Android to install packages from outside an app store.",
                    7,
                    DeepFindingConfidence.MEDIUM,
                )
            }
        }

        if (deviceAdmin && accessibility) {
            findings += finding(
                "DEVICE_ADMIN_ACCESSIBILITY_COMBO",
                "Device administration plus accessibility",
                "This combination can make malicious software harder to remove.",
                28,
                DeepFindingConfidence.HIGH,
            )
        } else if (deviceAdmin) {
            findings += finding(
                "DEVICE_ADMIN",
                "Device administrator component",
                "Can receive elevated administration capabilities after approval.",
                8,
                DeepFindingConfidence.MEDIUM,
            )
        }

        if ((readSms || receiveSms) && sendSms && readContacts && hasInternet) {
            findings += finding(
                "SMS_CONTACTS_NETWORK_COMBO",
                "SMS, contacts, and network access",
                "Could read verification codes, message contacts, and transmit data.",
                24,
                DeepFindingConfidence.HIGH,
            )
        } else if ((readSms || receiveSms || sendSms) && hasInternet) {
            findings += finding(
                "SMS_NETWORK",
                "SMS and network access",
                "Review whether messaging access matches the app's stated purpose.",
                9,
                DeepFindingConfidence.MEDIUM,
            )
        }

        if (readCallLog && readContacts && hasInternet) {
            findings += finding(
                "CALLLOG_CONTACTS_NETWORK",
                "Call log, contacts, and network access",
                "Could expose sensitive communication metadata.",
                16,
                DeepFindingConfidence.HIGH,
            )
        }

        if (mic && camera && backgroundLocation && hasInternet) {
            findings += finding(
                "SENSOR_SURVEILLANCE_COMBO",
                "Camera, microphone, background location, and network",
                "A broad sensor combination that deserves close review.",
                18,
                DeepFindingConfidence.HIGH,
            )
        } else if (mic && camera && fineLocation && hasInternet) {
            findings += finding(
                "SENSOR_ACCESS_COMBO",
                "Camera, microphone, location, and network",
                "Powerful access, but common in social and communication apps.",
                8,
                DeepFindingConfidence.MEDIUM,
            )
        }

        if (notificationListener && readSms && hasInternet) {
            findings += finding(
                "NOTIFICATION_SMS_NETWORK_COMBO",
                "Notification, SMS, and network access",
                "Could expose one-time codes and private notifications.",
                18,
                DeepFindingConfidence.HIGH,
            )
        } else if (notificationListener) {
            findings += finding(
                "NOTIFICATION_LISTENER",
                "Notification listener",
                "Can read notifications only after special access is granted.",
                6,
                DeepFindingConfidence.MEDIUM,
            )
        }

        if (boot && (accessibility || canInstall || deviceAdmin)) {
            findings += finding(
                "PERSISTENCE_COMBO",
                "Starts at boot with elevated capabilities",
                "May maintain persistent control after the phone restarts.",
                12,
                DeepFindingConfidence.HIGH,
            )
        }

        if (isDebuggable && !isSystemApp) {
            findings += finding(
                "DEBUGGABLE_BUILD",
                "Debuggable build",
                "Development builds are easier to inspect. This is not malware by itself.",
                4,
                DeepFindingConfidence.LOW,
            )
        }

        if (isSideloaded && !isSystemApp) {
            findings += finding(
                "SIDELOADED",
                "Installed outside a recognized store",
                "Installer: ${installer ?: "unknown, ADB, or manual install"}. Sideloading alone is not a threat.",
                3,
                DeepFindingConfidence.LOW,
            )
        }

        if (targetSdk in 1..25 && !isSystemApp) {
            findings += finding(
                "VERY_OLD_TARGET_SDK",
                "Targets an old Android security model",
                "Target SDK $targetSdk may lack modern platform protections.",
                9,
                DeepFindingConfidence.MEDIUM,
            )
        } else if (targetSdk in 26..30 && !isSystemApp) {
            findings += finding(
                "OLD_TARGET_SDK",
                "Older Android target",
                "Target SDK $targetSdk. Review abandoned or rarely updated apps.",
                3,
                DeepFindingConfidence.LOW,
            )
        }

        if (cleartextAllowed && hasInternet) {
            findings += finding(
                "CLEARTEXT_NETWORK",
                "Cleartext network traffic allowed",
                "The app may permit unencrypted HTTP traffic.",
                4,
                DeepFindingConfidence.LOW,
            )
        }

        val exportedCount =
            packageInfo.activities.orEmpty().count { it.exported } +
                packageInfo.services.orEmpty().count { it.exported } +
                packageInfo.receivers.orEmpty().count { it.exported } +
                packageInfo.providers.orEmpty().count { it.exported }

        if (exportedCount >= 15) {
            findings += finding(
                "MANY_EXPORTED_COMPONENTS",
                "Many externally reachable components",
                "$exportedCount exported activities, services, receivers, or providers.",
                4,
                DeepFindingConfidence.LOW,
            )
        }
    }

    private fun inspectApkArchive(
        apkFile: File,
        findings: MutableList<DeepAppFinding>,
    ) {
        if (!apkFile.isFile) return

        ZipFile(apkFile).use { zip ->
            val entries = zip.entries().asList()
            val names = entries.map { it.name.lowercase(Locale.US) }

            val dexEntries = entries.filter {
                it.name.matches(
                    Regex("""classes(\d*)\.dex""", RegexOption.IGNORE_CASE)
                )
            }

            if (dexEntries.size >= 5) {
                findings += finding(
                    "MANY_DEX_FILES",
                    "Many DEX code files",
                    "${apkFile.name} contains ${dexEntries.size} DEX files. Common in large apps.",
                    2,
                    DeepFindingConfidence.LOW,
                )
            }

            val embeddedPayloads = names.filter { name ->
                name.startsWith("assets/") &&
                    EMBEDDED_PAYLOAD_EXTENSIONS.any(name::endsWith)
            }

            if (embeddedPayloads.isNotEmpty()) {
                val suspicious = embeddedPayloads.filter { name ->
                    SUSPICIOUS_NAME_TOKENS.any(name::contains)
                }

                findings += finding(
                    "EMBEDDED_EXECUTABLE_PAYLOAD",
                    "Embedded executable or archive payload",
                    embeddedPayloads.take(8).joinToString(),
                    if (suspicious.isNotEmpty()) 10 else 3,
                    if (suspicious.isNotEmpty()) {
                        DeepFindingConfidence.MEDIUM
                    } else {
                        DeepFindingConfidence.LOW
                    },
                )
            }

            val suspiciousNames = names.filter { name ->
                SUSPICIOUS_NAME_TOKENS.any(name::contains)
            }.take(12)

            if (suspiciousNames.size >= 2) {
                findings += finding(
                    "SUSPICIOUS_ARCHIVE_NAMES",
                    "Suspicious names inside APK",
                    suspiciousNames.joinToString(),
                    min(10, suspiciousNames.size * 2),
                    DeepFindingConfidence.MEDIUM,
                )
            }

            val nativeLibraries = names.count {
                it.startsWith("lib/") && it.endsWith(".so")
            }

            if (nativeLibraries >= 50) {
                findings += finding(
                    "LARGE_NATIVE_CODE_SURFACE",
                    "Large native-code surface",
                    "$nativeLibraries native libraries are present.",
                    3,
                    DeepFindingConfidence.LOW,
                )
            }

            val dexMatches = linkedSetOf<String>()
            dexEntries.take(MAX_DEX_FILES_TO_SCAN).forEach { entry ->
                dexMatches += scanEntryForTokens(
                    zip = zip,
                    entryName = entry.name,
                    tokens = DEX_INDICATORS,
                    byteLimit = MAX_BYTES_PER_DEX,
                )
            }

            addDexFindings(dexMatches, findings)
        }
    }

    private fun addDexFindings(
        matches: Set<String>,
        findings: MutableList<DeepAppFinding>,
    ) {
        fun has(value: String) = value.lowercase(Locale.US) in matches

        if (
            has("dexclassloader") &&
            (has("runtime.exec") || has("/system/bin/su") || has("pm install"))
        ) {
            findings += finding(
                "DYNAMIC_CODE_EXECUTION_COMBO",
                "Dynamic code loading plus command execution",
                "Indicators for loading code dynamically and executing system commands.",
                28,
                DeepFindingConfidence.HIGH,
            )
        } else if (has("dexclassloader")) {
            findings += finding(
                "DYNAMIC_CODE_LOADING",
                "Dynamic code loading",
                "Legitimate plugin frameworks can also load code dynamically.",
                7,
                DeepFindingConfidence.MEDIUM,
            )
        }

        if (has("/system/bin/su") || has("magisk") || has("chmod 777")) {
            findings += finding(
                "ROOT_TOOLING_INDICATORS",
                "Root or privilege tooling indicators",
                matches.filter {
                    it in setOf("/system/bin/su", "magisk", "chmod 777")
                }.joinToString(),
                12,
                DeepFindingConfidence.MEDIUM,
            )
        }

        if (has("xmrig") || has("stratum+tcp") || has("cryptonight")) {
            findings += finding(
                "CRYPTOMINER_INDICATORS",
                "Cryptocurrency miner indicators",
                matches.filter {
                    it in setOf("xmrig", "stratum+tcp", "cryptonight")
                }.joinToString(),
                30,
                DeepFindingConfidence.HIGH,
            )
        }

        if (has("keylog") && has("accessibilityservice")) {
            findings += finding(
                "KEYLOGGER_INDICATORS",
                "Possible keylogging behavior",
                "Both keylogging and accessibility indicators were found.",
                30,
                DeepFindingConfidence.HIGH,
            )
        }

        if (has("mediaprojectionmanager") && has("accessibilityservice")) {
            findings += finding(
                "SCREEN_CAPTURE_ACCESSIBILITY",
                "Screen capture plus accessibility indicators",
                "Could observe and interact with screen content after permission grants.",
                14,
                DeepFindingConfidence.MEDIUM,
            )
        }
    }

    private fun scanEntryForTokens(
        zip: ZipFile,
        entryName: String,
        tokens: Set<String>,
        byteLimit: Long,
    ): Set<String> {
        val entry = zip.getEntry(entryName) ?: return emptySet()
        val normalized = tokens.associateBy { it.lowercase(Locale.US) }
        val found = linkedSetOf<String>()

        zip.getInputStream(entry).buffered().use { input ->
            val buffer = ByteArray(128 * 1024)
            var carry = ""
            var total = 0L

            while (total < byteLimit) {
                val readLimit =
                    min(buffer.size.toLong(), byteLimit - total).toInt()
                val count = input.read(buffer, 0, readLimit)
                if (count <= 0) break
                total += count

                val chunk =
                    carry + String(buffer, 0, count, Charsets.ISO_8859_1)
                val lower = chunk.lowercase(Locale.US)

                normalized.forEach { (needle, original) ->
                    if (needle in lower) {
                        found += original.lowercase(Locale.US)
                    }
                }

                if (found.size == normalized.size) break
                carry = chunk.takeLast(512)
            }
        }

        return found
    }

    private fun sensitiveBindings(packageInfo: PackageInfo): Set<String> =
        buildSet {
            packageInfo.services.orEmpty().mapNotNullTo(this) { it.permission }
            packageInfo.receivers.orEmpty().mapNotNullTo(this) { it.permission }
            packageInfo.providers.orEmpty().mapNotNullTo(this) { it.readPermission }
            packageInfo.providers.orEmpty().mapNotNullTo(this) { it.writePermission }
        }.filterTo(linkedSetOf()) { it in SENSITIVE_BINDINGS }

    private fun signerCertificateHashes(
        packageInfo: PackageInfo,
    ): List<String> = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = packageInfo.signingInfo ?: return@runCatching emptyList()
            val signatures = if (info.hasMultipleSigners()) {
                info.apkContentsSigners
            } else {
                info.signingCertificateHistory
            }
            signatures.map { sha256(it.toByteArray()) }
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures.orEmpty().map { sha256(it.toByteArray()) }
        }
    }.getOrDefault(emptyList())

    private fun installerPackage(packageName: String): String? =
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val source = packageManager.getInstallSourceInfo(packageName)
                source.installingPackageName ?: source.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)
            }
        }.getOrNull()

    private fun sha256(file: File): String {
        FileInputStream(file).use { input ->
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(1024 * 1024)

            while (true) {
                val count = input.read(buffer)
                if (count <= 0) break
                digest.update(buffer, 0, count)
            }

            return digest.digest().toHex()
        }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .toHex()

    private fun ByteArray.toHex(): String =
        joinToString(separator = "") { "%02x".format(it) }

    private fun normalizeHash(value: String): String =
        value.lowercase(Locale.US)
            .replace(":", "")
            .replace(" ", "")
            .trim()

    private fun PackageInfo.isSystemApp(): Boolean {
        val flags = applicationInfo?.flags ?: 0
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 ||
            flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }

    private fun <T> java.util.Enumeration<T>.asList(): List<T> =
        buildList {
            while (hasMoreElements()) add(nextElement())
        }

    private fun finding(
        code: String,
        title: String,
        detail: String,
        points: Int,
        confidence: DeepFindingConfidence,
    ) = DeepAppFinding(
        code = code,
        title = title,
        detail = detail,
        points = points,
        confidence = confidence,
    )

    companion object {
        private val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.amazon.venezia",
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.samsung.android.packageinstaller",
        )

        private val SENSITIVE_BINDINGS = setOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.BIND_VPN_SERVICE",
            "android.permission.BIND_INPUT_METHOD",
            "android.permission.BIND_AUTOFILL_SERVICE",
        )

        private val EMBEDDED_PAYLOAD_EXTENSIONS = setOf(
            ".apk", ".dex", ".jar", ".zip", ".7z", ".rar",
            ".bin", ".dat", ".enc", ".so",
        )

        private val SUSPICIOUS_NAME_TOKENS = setOf(
            "payload",
            "dropper",
            "inject",
            "keylog",
            "stealer",
            "banker",
            "rat_",
            "/rat",
            "xmrig",
            "cryptominer",
            "frida",
            "xposed",
            "magisk",
            "supersu",
            "rootkit",
        )

        private val DEX_INDICATORS = setOf(
            "DexClassLoader",
            "Runtime.exec",
            "/system/bin/su",
            "pm install",
            "chmod 777",
            "AccessibilityService",
            "MediaProjectionManager",
            "keylog",
            "xmrig",
            "stratum+tcp",
            "cryptonight",
            "magisk",
        )

        private const val MAX_DEX_FILES_TO_SCAN = 8
        private const val MAX_BYTES_PER_DEX = 32L * 1024L * 1024L
    }
}

enum class DeepAppRiskLevel {
    SAFE,
    LOW,
    CAUTION,
    SUSPICIOUS,
    DANGEROUS,
}

enum class DeepFindingConfidence {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    EXACT,
}

data class DeepAppFinding(
    val code: String,
    val title: String,
    val detail: String,
    val points: Int,
    val confidence: DeepFindingConfidence,
)

data class DeepApkHash(
    val path: String,
    val sha256: String,
    val sizeBytes: Long,
)

data class DeepAppScanResult(
    val packageName: String,
    val appLabel: String,
    val versionName: String,
    val versionCode: Long,
    val installerPackage: String?,
    val targetSdk: Int,
    val isSystemApp: Boolean,
    val isDebuggable: Boolean,
    val isSideloaded: Boolean,
    val apkHashes: List<DeepApkHash>,
    val signerSha256: List<String>,
    val requestedPermissions: List<String>,
    val sensitiveBindings: List<String>,
    val findings: List<DeepAppFinding>,
    val riskScore: Int,
    val riskLevel: DeepAppRiskLevel,
)

data class DeepAppScanProgress(
    val current: Int,
    val total: Int,
    val appLabel: String,
    val packageName: String,
    val stage: String,
)
