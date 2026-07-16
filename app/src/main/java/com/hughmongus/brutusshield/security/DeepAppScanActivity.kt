package com.hughmongus.brutusshield.security

import android.os.Bundle
import android.speech.tts.TextToSpeech
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Standalone launcher screen added by the v0.4 auto-installer.
 *
 * It runs inside the same Brutus Shield APK and can be opened from the Android
 * app drawer as "Brutus Deep Scan". This avoids fragile changes to the
 * existing dashboard until the full v0.3 project source is available.
 */
class DeepAppScanActivity : ComponentActivity(), TextToSpeech.OnInitListener {
    private var voice: TextToSpeech? = null
    private var voiceReady = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        voice = TextToSpeech(this, this)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DeepAppScanRoute(
                        onSpeak = ::speak,
                    )
                }
            }
        }
    }

    override fun onInit(status: Int) {
        voiceReady = status == TextToSpeech.SUCCESS
        if (voiceReady) {
            voice?.language = Locale.US
            voice?.setSpeechRate(0.82f)
            voice?.setPitch(0.72f)
        }
    }

    private fun speak(message: String) {
        if (!voiceReady) return
        voice?.speak(
            message,
            TextToSpeech.QUEUE_FLUSH,
            null,
            "brutus-deep-scan",
        )
    }

    override fun onDestroy() {
        voice?.stop()
        voice?.shutdown()
        voice = null
        super.onDestroy()
    }

    @Composable
    private fun DeepAppScanRoute(
        onSpeak: (String) -> Unit,
    ) {
        val scope = rememberCoroutineScope()
        var scanning by remember { mutableStateOf(false) }
        var progress by remember {
            mutableStateOf<DeepAppScanProgress?>(null)
        }
        var results by remember {
            mutableStateOf<List<DeepAppScanResult>>(emptyList())
        }
        var errorMessage by remember { mutableStateOf<String?>(null) }

        fun startScan() {
            if (scanning) return

            scanning = true
            progress = null
            results = emptyList()
            errorMessage = null
            onSpeak("Deep application scan initiated.")

            scope.launch {
                try {
                    val badHashes =
                        loadKnownBadHashesFromLocalRules()

                    val scanner = InstalledAppDeepScanner(
                        context = this@DeepAppScanActivity,
                        knownBadApkHashes = badHashes,
                    )

                    results = scanner.scanInstalledApps(
                        includeSystemApps = false,
                        onProgress = { progress = it },
                    )

                    val reviewCount = results.count {
                        it.riskLevel == DeepAppRiskLevel.CAUTION ||
                            it.riskLevel == DeepAppRiskLevel.SUSPICIOUS ||
                            it.riskLevel == DeepAppRiskLevel.DANGEROUS
                    }

                    val dangerousCount = results.count {
                        it.riskLevel == DeepAppRiskLevel.DANGEROUS
                    }

                    onSpeak(
                        when {
                            dangerousCount > 0 ->
                                "Deep scan complete. $dangerousCount high confidence threat findings require immediate review."
                            reviewCount > 0 ->
                                "Deep scan complete. $reviewCount applications require review."
                            else ->
                                "Deep scan complete. No meaningful warning signs were found."
                        }
                    )
                } catch (error: Throwable) {
                    errorMessage =
                        error.message ?: error.javaClass.simpleName
                    onSpeak("Deep scan stopped because of an error.")
                } finally {
                    scanning = false
                    progress = null
                }
            }
        }

        DeepAppScanScreen(
            scanning = scanning,
            progress = progress,
            results = results,
            errorMessage = errorMessage,
            onStart = ::startScan,
        )
    }

    private fun loadKnownBadHashesFromLocalRules(): Set<String> =
        runCatching {
            val raw = assets.open("threat_rules.json")
                .bufferedReader()
                .use { it.readText() }

            val root = raw.trim().let {
                when {
                    it.startsWith("[") -> JSONArray(it)
                    else -> JSONObject(it)
                }
            }

            buildSet {
                collectThreatHashes(
                    node = root,
                    path = "root",
                    output = this,
                )
            }
        }.getOrDefault(emptySet())

    private fun collectThreatHashes(
        node: Any?,
        path: String,
        output: MutableSet<String>,
    ) {
        when (node) {
            is JSONObject -> {
                val keys = node.keys()
                while (keys.hasNext()) {
                    val key = keys.next()
                    collectThreatHashes(
                        node = node.opt(key),
                        path = "$path.$key",
                        output = output,
                    )
                }
            }

            is JSONArray -> {
                for (index in 0 until node.length()) {
                    collectThreatHashes(
                        node = node.opt(index),
                        path = "$path[$index]",
                        output = output,
                    )
                }
            }

            is String -> {
                val normalized = node
                    .lowercase(Locale.US)
                    .replace(":", "")
                    .replace(" ", "")
                    .trim()

                val pathLower = path.lowercase(Locale.US)
                val looksLikeSha256 =
                    normalized.matches(Regex("[a-f0-9]{64}"))

                val badContext = BAD_PATH_WORDS.any {
                    it in pathLower
                }

                val excludedContext = GOOD_PATH_WORDS.any {
                    it in pathLower
                }

                if (
                    looksLikeSha256 &&
                    badContext &&
                    !excludedContext
                ) {
                    output += normalized
                }
            }
        }
    }

    companion object {
        private val BAD_PATH_WORDS = setOf(
            "malware",
            "malicious",
            "threat",
            "known_bad",
            "knownbad",
            "deny",
            "block",
            "blacklist",
        )

        private val GOOD_PATH_WORDS = setOf(
            "good",
            "clean",
            "trusted",
            "allow",
            "whitelist",
            "safe",
        )
    }
}

@Composable
private fun DeepAppScanScreen(
    scanning: Boolean,
    progress: DeepAppScanProgress?,
    results: List<DeepAppScanResult>,
    errorMessage: String?,
    onStart: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(18.dp),
    ) {
        Text(
            text = "BRUTUS DEEP APP SCAN",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Black,
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text =
                "Inspects installed APK code, split APKs, permissions, " +
                    "signatures, installers, components, embedded payloads, " +
                    "and selected behavior indicators.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Spacer(modifier = Modifier.height(12.dp))

        Button(
            onClick = onStart,
            enabled = !scanning,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                if (scanning) {
                    "SCANNING…"
                } else {
                    "START DEEP APP SCAN"
                }
            )
        }

        if (scanning) {
            Spacer(modifier = Modifier.height(12.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                CircularProgressIndicator()

                Column {
                    Text(
                        text = progress?.appLabel ?: "Preparing app inventory…",
                        fontWeight = FontWeight.Bold,
                    )

                    val current = progress?.current ?: 0
                    val total = progress?.total ?: 0

                    Text(
                        text =
                            if (total > 0) {
                                "Application $current of $total"
                            } else {
                                "Loading installed applications"
                            },
                    )

                    progress?.packageName?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }

        errorMessage?.let {
            Spacer(modifier = Modifier.height(12.dp))
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "SCAN ERROR",
                        fontWeight = FontWeight.Bold,
                    )
                    Text(text = it)
                }
            }
        }

        if (!scanning && results.isNotEmpty()) {
            Spacer(modifier = Modifier.height(12.dp))
            ScanSummary(results)
            Spacer(modifier = Modifier.height(8.dp))
        }

        Box(modifier = Modifier.weight(1f)) {
            if (!scanning && results.isEmpty() && errorMessage == null) {
                Text(
                    text =
                        "Android blocks normal apps from reading another " +
                            "app's private /data/data sandbox. Brutus scans " +
                            "everything Android legitimately exposes without root.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.align(Alignment.Center),
                )
            }

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxSize(),
            ) {
                items(
                    items = results,
                    key = { it.packageName },
                ) { result ->
                    DeepAppResultCard(result)
                }
            }
        }
    }
}

@Composable
private fun ScanSummary(
    results: List<DeepAppScanResult>,
) {
    val dangerous = results.count {
        it.riskLevel == DeepAppRiskLevel.DANGEROUS
    }
    val suspicious = results.count {
        it.riskLevel == DeepAppRiskLevel.SUSPICIOUS
    }
    val caution = results.count {
        it.riskLevel == DeepAppRiskLevel.CAUTION
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = "SCAN COMPLETE",
                fontWeight = FontWeight.Black,
            )
            Text(text = "${results.size} applications inspected")
            Text(
                text =
                    "$dangerous dangerous · " +
                        "$suspicious suspicious · " +
                        "$caution review",
            )
        }
    }
}

@Composable
private fun DeepAppResultCard(
    result: DeepAppScanResult,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = result.appLabel,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = result.packageName,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                Text(
                    text = "${result.riskLevel} ${result.riskScore}",
                    fontWeight = FontWeight.Black,
                )
            }

            if (result.findings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Divider()
                Spacer(modifier = Modifier.height(8.dp))

                result.findings
                    .filter { it.points > 0 }
                    .take(5)
                    .forEach { finding ->
                        Text(
                            text = "• ${finding.title}",
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = finding.detail,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                    }
            } else {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "No meaningful warning signs found.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
