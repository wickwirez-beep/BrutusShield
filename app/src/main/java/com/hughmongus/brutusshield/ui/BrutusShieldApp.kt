package com.hughmongus.brutusshield.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import android.speech.RecognizerIntent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.hughmongus.brutusshield.BrutusViewModel
import com.hughmongus.brutusshield.R
import com.hughmongus.brutusshield.model.ApkAnalysis
import com.hughmongus.brutusshield.model.AppFinding
import com.hughmongus.brutusshield.model.FileFinding
import com.hughmongus.brutusshield.model.HistoryEntry
import com.hughmongus.brutusshield.model.LinkAnalysis
import com.hughmongus.brutusshield.model.RiskLevel
import com.hughmongus.brutusshield.model.ScanState
import com.hughmongus.brutusshield.model.Screen
import com.hughmongus.brutusshield.voice.BrutusCommand
import com.hughmongus.brutusshield.voice.BrutusVoiceController
import com.hughmongus.brutusshield.voice.parseBrutusCommand
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrutusShieldApp(viewModel: BrutusViewModel = viewModel()) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("brutus_shield", Activity.MODE_PRIVATE) }
    val voice = remember { BrutusVoiceController(context) }
    var showArtworkSplash by rememberSaveable { mutableStateOf(true) }
    var pendingDeepScan by rememberSaveable { mutableStateOf(false) }
    var selectedTreeUri by rememberSaveable {
        mutableStateOf(prefs.getString("scan_tree_uri", null))
    }

    DisposableEffect(Unit) {
        onDispose { voice.shutdown() }
    }

    LaunchedEffect(Unit) {
        delay(1100)
        showArtworkSplash = false
    }

    val folderLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            selectedTreeUri = uri.toString()
            prefs.edit().putString("scan_tree_uri", uri.toString()).apply()
            viewModel.runFileScan(context, uri, pendingDeepScan)
            voice.speak(if (pendingDeepScan) "Deep scan initiated." else "Quick scan initiated.")
        }
    }

    val apkLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            viewModel.analyzeApk(context, uri)
            voice.speak("Analyzing selected Android package.")
        }
    }

    val launchScan: (Boolean) -> Unit = { deep ->
        pendingDeepScan = deep
        val uri = selectedTreeUri?.let(Uri::parse)
        if (uri == null) {
            folderLauncher.launch(null)
        } else {
            viewModel.runFileScan(context, uri, deep)
            voice.speak(if (deep) "Deep scan initiated." else "Quick scan initiated.")
        }
    }

    val speechLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val spoken = result.data
            ?.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS)
            ?.firstOrNull()

        if (spoken.isNullOrBlank()) {
            voice.speak("I did not catch that command.")
        } else {
            when (parseBrutusCommand(spoken)) {
                BrutusCommand.QUICK_SCAN -> launchScan(false)
                BrutusCommand.DEEP_SCAN -> launchScan(true)
                BrutusCommand.APP_AUDIT -> {
                    viewModel.runAppAudit(context)
                    voice.speak("Installed app audit initiated.")
                }
                BrutusCommand.APK_ANALYZER -> apkLauncher.launch("application/vnd.android.package-archive")
                BrutusCommand.LINK_SCANNER -> {
                    viewModel.navigate(Screen.LINK_SCANNER)
                    voice.speak("Link scanner ready.")
                }
                BrutusCommand.STATUS_REPORT -> voice.speak(viewModel.statusReport())
                BrutusCommand.STOP_SCAN -> {
                    viewModel.stopScan()
                    voice.speak("Scan stopped.")
                }
                BrutusCommand.UNKNOWN -> voice.speak(
                    "Command not recognized. Say quick scan, deep scan, app audit, check a link, or status report."
                )
            }
        }
    }

    val micPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            speechLauncher.launch(createSpeechIntent())
        } else {
            viewModel.showMessage("Microphone permission is required for voice commands.")
        }
    }

    val requestVoice: () -> Unit = {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            speechLauncher.launch(createSpeechIntent())
        } else {
            micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
        }
    }

    if (showArtworkSplash) {
        Image(
            painter = painterResource(R.drawable.brutus_splash),
            contentDescription = "Brutus Shield splash screen",
            modifier = Modifier.fillMaxSize(),
            contentScale = ContentScale.Crop
        )
        return
    }

    Scaffold(
        containerColor = BrutusBlack,
        topBar = {
            BrutusTopBar(
                screen = viewModel.screen,
                onBack = viewModel::goHome
            )
        },
        bottomBar = {
            VoiceDock(
                onVoice = requestVoice,
                onStatus = { voice.speak(viewModel.statusReport()) }
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(BrutusBlack)
        ) {
            when (viewModel.screen) {
                Screen.HOME -> HomeScreen(
                    viewModel = viewModel,
                    onQuickScan = { launchScan(false) },
                    onDeepScan = { launchScan(true) },
                    onAppAudit = {
                        viewModel.runAppAudit(context)
                        voice.speak("Installed app audit initiated.")
                    },
                    onApkAnalyzer = { apkLauncher.launch("application/vnd.android.package-archive") },
                    onLinkScanner = { viewModel.navigate(Screen.LINK_SCANNER) },
                    onHistory = { viewModel.navigate(Screen.HISTORY) },
                    onAbout = { viewModel.navigate(Screen.ABOUT) }
                )

                Screen.FILE_RESULTS -> FileScanScreen(
                    state = viewModel.scanState,
                    onStop = viewModel::stopScan,
                    onQuarantine = { finding ->
                        viewModel.quarantine(context, finding) { result ->
                            if (result != null) {
                                val message = if (result.originalDeleted) {
                                    "Threat isolated. Original file removed."
                                } else {
                                    "Private quarantine copy created. Android did not allow removal of the original."
                                }
                                viewModel.showMessage(message)
                                voice.speak(message)
                            }
                        }
                    }
                )

                Screen.APP_AUDIT -> AppAuditScreen(
                    running = viewModel.appAuditRunning,
                    findings = viewModel.appFindings,
                    onOpenSettings = { packageName ->
                        context.startActivity(
                            Intent(
                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.parse("package:$packageName")
                            )
                        )
                    }
                )

                Screen.APK_ANALYZER -> ApkAnalyzerScreen(
                    running = viewModel.apkAnalysisRunning,
                    analysis = viewModel.apkAnalysis,
                    onChooseApk = { apkLauncher.launch("application/vnd.android.package-archive") }
                )

                Screen.LINK_SCANNER -> LinkScannerScreen(
                    analysis = viewModel.linkAnalysis,
                    onAnalyze = viewModel::analyzeLink
                )

                Screen.HISTORY -> HistoryScreen(viewModel.history)
                Screen.ABOUT -> AboutScreen()
            }

            AnimatedVisibility(
                visible = viewModel.bannerMessage != null,
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .padding(14.dp)
            ) {
                viewModel.bannerMessage?.let { message ->
                    MessageBanner(message = message, onDismiss = viewModel::clearMessage)
                }
            }
        }
    }
}

private fun createSpeechIntent(): Intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
    putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
    putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.US.toLanguageTag())
    putExtra(RecognizerIntent.EXTRA_PROMPT, "Give Brutus a command")
    putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 3)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BrutusTopBar(screen: Screen, onBack: () -> Unit) {
    val title = when (screen) {
        Screen.HOME -> "BRUTUS SHIELD"
        Screen.FILE_RESULTS -> "FILE SCAN"
        Screen.APP_AUDIT -> "APP AUDIT"
        Screen.APK_ANALYZER -> "APK ANALYZER"
        Screen.LINK_SCANNER -> "LINK SCANNER"
        Screen.HISTORY -> "SCAN HISTORY"
        Screen.ABOUT -> "ABOUT"
    }

    TopAppBar(
        modifier = Modifier.statusBarsPadding(),
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = BrutusBlack,
            titleContentColor = BrutusWhite
        ),
        navigationIcon = {
            if (screen != Screen.HOME) {
                IconButton(onClick = onBack) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = BrutusWhite)
                }
            }
        },
        title = {
            Column {
                Text(
                    text = title,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 1.5.sp,
                    fontSize = 19.sp
                )
                if (screen == Screen.HOME) {
                    Text(
                        text = "VIRUS & MALWARE SCANNER",
                        color = BrutusRed,
                        fontSize = 10.sp,
                        letterSpacing = 1.3.sp
                    )
                }
            }
        },
        actions = {
            Icon(Icons.Default.Shield, contentDescription = null, tint = BrutusRed, modifier = Modifier.padding(end = 16.dp))
        }
    )
}

@Composable
private fun HomeScreen(
    viewModel: BrutusViewModel,
    onQuickScan: () -> Unit,
    onDeepScan: () -> Unit,
    onAppAudit: () -> Unit,
    onApkAnalyzer: () -> Unit,
    onLinkScanner: () -> Unit,
    onHistory: () -> Unit,
    onAbout: () -> Unit
) {
    val status = homeStatus(viewModel)
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            DeviceStatusCard(status)
        }
        item {
            ScanOrb(
                isScanning = viewModel.scanState is ScanState.Running,
                onClick = onQuickScan
            )
        }
        item {
            FeatureGrid(
                onDeepScan = onDeepScan,
                onAppAudit = onAppAudit,
                onApkAnalyzer = onApkAnalyzer,
                onLinkScanner = onLinkScanner,
                onHistory = onHistory,
                onAbout = onAbout
            )
        }
        item {
            HonestProtectionCard()
        }
    }
}

private data class HomeStatus(
    val title: String,
    val detail: String,
    val color: Color,
    val imageRes: Int
)

private fun homeStatus(viewModel: BrutusViewModel): HomeStatus {
    val scan = viewModel.scanState
    return when {
        scan is ScanState.Running -> HomeStatus(
            "SCANNING",
            "${scan.scannedCount} files checked • ${scan.currentName}",
            ScanningBlue,
            R.drawable.status_scanning
        )
        scan is ScanState.Finished && scan.summary.dangerousCount > 0 -> HomeStatus(
            "DANGER",
            "${scan.summary.dangerousCount} serious warning(s) require review",
            AlertRed,
            R.drawable.status_danger
        )
        scan is ScanState.Finished && scan.summary.flaggedCount > 0 -> HomeStatus(
            "CAUTION",
            "${scan.summary.flaggedCount} item(s) need review",
            CautionGold,
            R.drawable.status_caution
        )
        else -> HomeStatus(
            "PROTECTED",
            "Brutus is standing guard",
            AllClearGreen,
            R.drawable.status_all_clear
        )
    }
}

@Composable
private fun DeviceStatusCard(status: HomeStatus) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, status.color.copy(alpha = 0.55f), RoundedCornerShape(18.dp)),
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        shape = RoundedCornerShape(18.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Image(
                painter = painterResource(status.imageRes),
                contentDescription = null,
                modifier = Modifier
                    .size(104.dp)
                    .clip(RoundedCornerShape(14.dp)),
                contentScale = ContentScale.Crop
            )
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("DEVICE STATUS", color = SteelSilver, fontSize = 11.sp, letterSpacing = 1.2.sp)
                Text(
                    status.title,
                    color = status.color,
                    fontWeight = FontWeight.Black,
                    fontSize = 25.sp
                )
                Text(
                    status.detail,
                    color = BrutusWhite.copy(alpha = 0.78f),
                    fontSize = 13.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun ScanOrb(isScanning: Boolean, onClick: () -> Unit) {
    val transition = rememberInfiniteTransition(label = "scan")
    val rotation by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(2800),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )
    val pulse by transition.animateFloat(
        initialValue = 0.62f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(238.dp)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Canvas(
            modifier = Modifier
                .size(218.dp)
                .rotate(if (isScanning) rotation else 0f)
        ) {
            val radius = size.minDimension / 2f
            drawCircle(BrutusRed.copy(alpha = 0.10f), radius = radius)
            drawCircle(
                BrutusRed.copy(alpha = if (isScanning) pulse else 0.58f),
                radius = radius * 0.84f,
                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
            )
            drawArc(
                color = AlertRed,
                startAngle = -30f,
                sweepAngle = 118f,
                useCenter = false,
                topLeft = center - androidx.compose.ui.geometry.Offset(radius * 0.70f, radius * 0.70f),
                size = androidx.compose.ui.geometry.Size(radius * 1.40f, radius * 1.40f),
                style = Stroke(width = 8.dp.toPx(), cap = StrokeCap.Round)
            )
            drawCircle(
                Color.White.copy(alpha = 0.10f),
                radius = radius * 0.52f,
                style = Stroke(width = 2.dp.toPx())
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                if (isScanning) Icons.Default.Analytics else Icons.Default.Security,
                contentDescription = null,
                tint = BrutusWhite,
                modifier = Modifier.size(42.dp)
            )
            Text(
                if (isScanning) "SCANNING" else "SCAN",
                color = BrutusWhite,
                fontWeight = FontWeight.Black,
                fontSize = 28.sp,
                letterSpacing = 1.4.sp
            )
            Text(
                if (isScanning) "BRUTUS IS WORKING" else "TAP FOR QUICK SCAN",
                color = BrutusRed,
                fontSize = 10.sp,
                letterSpacing = 1.2.sp
            )
        }
    }
}

@Composable
private fun FeatureGrid(
    onDeepScan: () -> Unit,
    onAppAudit: () -> Unit,
    onApkAnalyzer: () -> Unit,
    onLinkScanner: () -> Unit,
    onHistory: () -> Unit,
    onAbout: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            FeatureCard("DEEP SCAN", "Chosen folder, recursive", Icons.Default.Folder, Modifier.weight(1f), onDeepScan)
            FeatureCard("APP AUDIT", "Installed app risks", Icons.Default.Android, Modifier.weight(1f), onAppAudit)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            FeatureCard("APK ANALYZER", "Inspect before install", Icons.Default.BugReport, Modifier.weight(1f), onApkAnalyzer)
            FeatureCard("LINK SCANNER", "Check URL warning signs", Icons.Default.Link, Modifier.weight(1f), onLinkScanner)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            FeatureCard("HISTORY", "Previous activity", Icons.Default.History, Modifier.weight(1f), onHistory)
            FeatureCard("ABOUT", "Version and privacy", Icons.Default.Info, Modifier.weight(1f), onAbout)
        }
    }
}

@Composable
private fun FeatureCard(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier
            .height(116.dp)
            .clickable(onClick = onClick)
            .border(1.dp, Color.White.copy(alpha = 0.09f), RoundedCornerShape(14.dp)),
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(13.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Icon(icon, contentDescription = null, tint = BrutusRed, modifier = Modifier.size(28.dp))
            Column {
                Text(title, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text(subtitle, color = SteelSilver, fontSize = 10.sp, lineHeight = 13.sp)
            }
        }
    }
}

@Composable
private fun HonestProtectionCard() {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1710)),
        shape = RoundedCornerShape(14.dp)
    ) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.Top) {
            Icon(Icons.Default.Shield, contentDescription = null, tint = AllClearGreen)
            Spacer(Modifier.width(10.dp))
            Column {
                Text("HONEST PROTECTION", color = AllClearGreen, fontWeight = FontWeight.Bold)
                Text(
                    "Warnings are based on visible file traits, APK manifests, install source, and permission combinations. A warning is not proof of infection.",
                    color = BrutusWhite.copy(alpha = 0.74f),
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )
            }
        }
    }
}

@Composable
private fun FileScanScreen(
    state: ScanState,
    onStop: () -> Unit,
    onQuarantine: (FileFinding) -> Unit
) {
    when (state) {
        ScanState.Idle -> CenterMessage("Scanner ready", "Choose Quick Scan or Deep Scan from the home screen.")
        is ScanState.Failed -> CenterMessage("Scan failed", state.message, AlertRed)
        is ScanState.Running -> RunningScan(state, onStop)
        is ScanState.Finished -> FinishedScan(state, onQuarantine)
    }
}

@Composable
private fun RunningScan(state: ScanState.Running, onStop: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Image(
            painter = painterResource(R.drawable.brutus_guard),
            contentDescription = null,
            modifier = Modifier.height(220.dp),
            contentScale = ContentScale.Fit
        )
        CircularProgressIndicator(
            color = BrutusRed,
            trackColor = BrutusPanelRaised,
            strokeWidth = 7.dp,
            modifier = Modifier.size(92.dp)
        )
        Spacer(Modifier.height(18.dp))
        Text("${state.scannedCount}", fontSize = 42.sp, fontWeight = FontWeight.Black)
        Text("FILES CHECKED", color = BrutusRed, letterSpacing = 1.2.sp, fontSize = 11.sp)
        Spacer(Modifier.height(12.dp))
        Text(
            state.currentName,
            color = SteelSilver,
            textAlign = TextAlign.Center,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
        Spacer(Modifier.height(22.dp))
        Button(
            onClick = onStop,
            colors = ButtonDefaults.buttonColors(containerColor = AlertRed),
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Stop, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("STOP SCAN")
        }
    }
}

@Composable
private fun FinishedScan(state: ScanState.Finished, onQuarantine: (FileFinding) -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            SummaryCard(state)
        }
        if (state.findings.isEmpty()) {
            item {
                CenterMessage(
                    title = "ALL CLEAR",
                    detail = "No local warning signs were found in the selected folder.",
                    color = AllClearGreen
                )
            }
        } else {
            items(state.findings, key = { it.uri.toString() }) { finding ->
                FileFindingCard(finding, onQuarantine)
            }
        }
    }
}

@Composable
private fun SummaryCard(state: ScanState.Finished) {
    val risk = when {
        state.summary.dangerousCount > 0 -> RiskLevel.DANGEROUS
        state.summary.flaggedCount > 0 -> RiskLevel.CAUTION
        else -> RiskLevel.CLEAR
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        modifier = Modifier.border(1.dp, riskColor(risk).copy(alpha = 0.5f), RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("SCAN COMPLETE", color = riskColor(risk), fontWeight = FontWeight.Black, fontSize = 21.sp)
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Stat("CHECKED", state.summary.scannedCount.toString())
                Stat("FLAGGED", state.summary.flaggedCount.toString())
                Stat("DANGER", state.summary.dangerousCount.toString())
                Stat("TIME", formatDuration(state.summary.elapsedMillis))
            }
        }
    }
}

@Composable
private fun Stat(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontWeight = FontWeight.Black, fontSize = 18.sp)
        Text(label, color = SteelSilver, fontSize = 9.sp)
    }
}

@Composable
private fun FileFindingCard(finding: FileFinding, onQuarantine: (FileFinding) -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.border(1.dp, riskColor(finding.riskLevel).copy(alpha = 0.42f), RoundedCornerShape(14.dp))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Description, contentDescription = null, tint = riskColor(finding.riskLevel))
                Spacer(Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(finding.name, fontWeight = FontWeight.Bold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    Text("${finding.riskLevel.displayName} • ${formatBytes(finding.sizeBytes)}", color = riskColor(finding.riskLevel), fontSize = 11.sp)
                }
            }
            Spacer(Modifier.height(10.dp))
            finding.reasons.forEach { reason ->
                Text("• $reason", color = BrutusWhite.copy(alpha = 0.76f), fontSize = 12.sp, lineHeight = 17.sp)
            }
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { onQuarantine(finding) },
                colors = ButtonDefaults.buttonColors(containerColor = BrutusRed),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Shield, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("QUARANTINE")
            }
        }
    }
}

@Composable
private fun AppAuditScreen(
    running: Boolean,
    findings: List<AppFinding>,
    onOpenSettings: (String) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            InfoCard(
                title = "RISK INDICATORS, NOT A VERDICT",
                detail = "Brutus reviews permissions, accessibility services, hidden launchers, and installation source. Legitimate apps can still trigger warnings."
            )
        }
        if (running) {
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 70.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    CircularProgressIndicator(color = BrutusRed)
                    Spacer(Modifier.height(16.dp))
                    Text("AUDITING INSTALLED APPS…", color = SteelSilver)
                }
            }
        } else if (findings.isEmpty()) {
            item { CenterMessage("NO MAJOR INDICATORS", "No installed user apps crossed the review threshold.", AllClearGreen) }
        } else {
            items(findings, key = { it.packageName }) { finding ->
                AppFindingCard(finding, onOpenSettings)
            }
        }
    }
}

@Composable
private fun AppFindingCard(finding: AppFinding, onOpenSettings: (String) -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.border(1.dp, riskColor(finding.riskLevel).copy(alpha = 0.42f), RoundedCornerShape(14.dp))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Android, contentDescription = null, tint = riskColor(finding.riskLevel), modifier = Modifier.size(34.dp))
                Spacer(Modifier.width(11.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(finding.appName, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                    Text(finding.packageName, color = SteelSilver, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("Risk score ${finding.score} • ${finding.riskLevel.displayName}", color = riskColor(finding.riskLevel), fontSize = 11.sp)
                }
            }
            Spacer(Modifier.height(9.dp))
            finding.reasons.forEach { Text("• $it", color = BrutusWhite.copy(alpha = 0.76f), fontSize = 12.sp, lineHeight = 17.sp) }
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = { onOpenSettings(finding.packageName) }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Settings, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("OPEN APP SETTINGS")
            }
        }
    }
}

@Composable
private fun ApkAnalyzerScreen(
    running: Boolean,
    analysis: ApkAnalysis?,
    onChooseApk: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Button(
            onClick = onChooseApk,
            colors = ButtonDefaults.buttonColors(containerColor = BrutusRed),
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.BugReport, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("SELECT APK TO ANALYZE")
        }
        InfoCard(
            "LOCAL APK INSPECTION",
            "The file is copied temporarily into private cache, inspected locally, hashed with SHA-256, and then removed from cache. It is not uploaded."
        )
        if (running) {
            Box(Modifier.fillMaxWidth().height(220.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = BrutusRed)
            }
        }
        analysis?.let { ApkAnalysisCard(it) }
    }
}

@Composable
private fun ApkAnalysisCard(analysis: ApkAnalysis) {
    Card(
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        modifier = Modifier.border(1.dp, riskColor(analysis.riskLevel).copy(alpha = 0.5f), RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(analysis.riskLevel.displayName.uppercase(), color = riskColor(analysis.riskLevel), fontWeight = FontWeight.Black, fontSize = 24.sp)
            Text(analysis.appName, fontWeight = FontWeight.Bold, fontSize = 20.sp)
            Text(analysis.packageName, color = SteelSilver, fontSize = 11.sp)
            Text("Version ${analysis.versionName} • Score ${analysis.score}", color = BrutusWhite.copy(alpha = 0.75f), fontSize = 12.sp)
            Spacer(Modifier.height(12.dp))
            analysis.reasons.forEach { Text("• $it", fontSize = 12.sp, lineHeight = 17.sp) }
            HorizontalDivider(Modifier.padding(vertical = 14.dp), color = Color.White.copy(alpha = 0.1f))
            Text("SHA-256", color = BrutusRed, fontWeight = FontWeight.Bold, fontSize = 11.sp)
            Text(analysis.sha256, color = SteelSilver, fontSize = 10.sp, lineHeight = 14.sp)
            Spacer(Modifier.height(12.dp))
            Text("REQUESTED PERMISSIONS (${analysis.requestedPermissions.size})", color = BrutusRed, fontWeight = FontWeight.Bold, fontSize = 11.sp)
            analysis.requestedPermissions.take(20).forEach {
                Text(it.substringAfterLast('.'), color = SteelSilver, fontSize = 10.sp)
            }
            if (analysis.requestedPermissions.size > 20) {
                Text("+ ${analysis.requestedPermissions.size - 20} more", color = SteelSilver, fontSize = 10.sp)
            }
        }
    }
}

@Composable
private fun LinkScannerScreen(analysis: LinkAnalysis?, onAnalyze: (String) -> Unit) {
    var input by rememberSaveable { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .imePadding()
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            label = { Text("Paste a link") },
            placeholder = { Text("https://example.com") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true
        )
        Button(
            onClick = { onAnalyze(input) },
            colors = ButtonDefaults.buttonColors(containerColor = BrutusRed),
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Link, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("CHECK LINK")
        }
        InfoCard(
            "LOCAL HEURISTIC CHECK",
            "Brutus checks formatting, HTTPS, punycode, shorteners, raw IP addresses, misleading symbols, and suspicious wording. It does not open the site."
        )
        analysis?.let { LinkAnalysisCard(it) }
    }
}

@Composable
private fun LinkAnalysisCard(analysis: LinkAnalysis) {
    Card(
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        modifier = Modifier.border(1.dp, riskColor(analysis.riskLevel).copy(alpha = 0.5f), RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(analysis.riskLevel.displayName.uppercase(), color = riskColor(analysis.riskLevel), fontSize = 24.sp, fontWeight = FontWeight.Black)
            Text(analysis.host, fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Text("Risk score ${analysis.score}", color = SteelSilver, fontSize = 11.sp)
            Spacer(Modifier.height(12.dp))
            analysis.reasons.forEach { Text("• $it", fontSize = 12.sp, lineHeight = 18.sp) }
        }
    }
}

@Composable
private fun HistoryScreen(history: List<HistoryEntry>) {
    if (history.isEmpty()) {
        CenterMessage("NO HISTORY YET", "Completed scans and analyses will appear here.")
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(9.dp)
    ) {
        items(history, key = { it.timestamp }) { entry ->
            Card(colors = CardDefaults.cardColors(containerColor = BrutusPanel)) {
                Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.History, contentDescription = null, tint = riskColor(entry.riskLevel))
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(entry.title, fontWeight = FontWeight.Bold)
                        Text(entry.detail, color = SteelSilver, fontSize = 11.sp)
                    }
                    Text(
                        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(entry.timestamp)),
                        color = SteelSilver,
                        fontSize = 9.sp,
                        textAlign = TextAlign.End
                    )
                }
            }
        }
    }
}

@Composable
private fun AboutScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(18.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Image(
            painter = painterResource(R.drawable.brutus_arms_crossed),
            contentDescription = null,
            modifier = Modifier.height(270.dp),
            contentScale = ContentScale.Fit
        )
        Text("BRUTUS SHIELD", fontWeight = FontWeight.Black, fontSize = 29.sp, letterSpacing = 1.4.sp)
        Text("VERSION 0.1.0 • MVP", color = BrutusRed, fontSize = 11.sp, letterSpacing = 1.2.sp)
        Spacer(Modifier.height(20.dp))
        InfoCard(
            "BUILT AND DESIGNED BY HUGH MONGUS",
            "A native Android security utility with local file analysis, installed-app auditing, APK inspection, link heuristics, quarantine assistance, spoken reports, and hands-free commands."
        )
        Spacer(Modifier.height(12.dp))
        InfoCard(
            "PRIVACY FIRST",
            "Brutus Shield does not upload scanned files or links in this version. Speech recognition behavior depends on the recognition service configured on the device."
        )
        Spacer(Modifier.height(12.dp))
        InfoCard(
            "ANDROID LIMITS",
            "Android isolates app-private data. Brutus scans folders you explicitly select and can open system settings for risky apps, but it cannot silently inspect or uninstall everything on the phone."
        )
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun InfoCard(title: String, detail: String) {
    Card(
        colors = CardDefaults.cardColors(containerColor = BrutusPanel),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(title, color = BrutusRed, fontWeight = FontWeight.Bold, fontSize = 12.sp, letterSpacing = 0.7.sp)
            Spacer(Modifier.height(5.dp))
            Text(detail, color = BrutusWhite.copy(alpha = 0.76f), fontSize = 12.sp, lineHeight = 18.sp)
        }
    }
}

@Composable
private fun CenterMessage(title: String, detail: String, color: Color = SteelSilver) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(38.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(Icons.Default.Shield, contentDescription = null, tint = color, modifier = Modifier.size(54.dp))
        Spacer(Modifier.height(12.dp))
        Text(title, color = color, fontWeight = FontWeight.Black, textAlign = TextAlign.Center, fontSize = 20.sp)
        Spacer(Modifier.height(6.dp))
        Text(detail, color = BrutusWhite.copy(alpha = 0.68f), textAlign = TextAlign.Center, fontSize = 12.sp, lineHeight = 17.sp)
    }
}

@Composable
private fun MessageBanner(message: String, onDismiss: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF2A0B0B)),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, BrutusRed, RoundedCornerShape(12.dp))
    ) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Shield, contentDescription = null, tint = BrutusRed)
            Spacer(Modifier.width(9.dp))
            Text(message, modifier = Modifier.weight(1f), fontSize = 12.sp)
            TextButton(onClick = onDismiss) { Text("DISMISS", color = BrutusRed) }
        }
    }
}

@Composable
private fun VoiceDock(onVoice: () -> Unit, onStatus: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF080808))
            .navigationBarsPadding()
            .padding(horizontal = 14.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Image(
            painter = painterResource(R.drawable.brutus_attack),
            contentDescription = null,
            modifier = Modifier.size(56.dp),
            contentScale = ContentScale.Fit
        )
        Column(modifier = Modifier.weight(1f)) {
            Text("BRUTUS VOICE", color = BrutusRed, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            Text("Tap the mic and give a command", color = SteelSilver, fontSize = 10.sp)
        }
        TextButton(onClick = onStatus) { Text("STATUS", color = SteelSilver, fontSize = 10.sp) }
        Box(
            modifier = Modifier
                .size(52.dp)
                .clip(CircleShape)
                .background(BrutusRed)
                .clickable(onClick = onVoice),
            contentAlignment = Alignment.Center
        ) {
            Icon(Icons.Default.Mic, contentDescription = "Voice command", tint = Color.White, modifier = Modifier.size(27.dp))
        }
    }
}

private fun riskColor(risk: RiskLevel): Color = when (risk) {
    RiskLevel.CLEAR -> AllClearGreen
    RiskLevel.LOW -> ScanningBlue
    RiskLevel.CAUTION -> CautionGold
    RiskLevel.DANGEROUS -> AlertRed
}

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    bytes < 1024L * 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
    else -> String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
}

private fun formatDuration(milliseconds: Long): String {
    val seconds = milliseconds / 1000
    return if (seconds < 60) "${seconds}s" else "${seconds / 60}m ${seconds % 60}s"
}
