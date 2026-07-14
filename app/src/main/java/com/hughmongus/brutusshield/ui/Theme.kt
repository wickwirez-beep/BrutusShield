package com.hughmongus.brutusshield.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val BrutusBlack = Color(0xFF050505)
val BrutusPanel = Color(0xFF111111)
val BrutusPanelRaised = Color(0xFF181818)
val BrutusRed = Color(0xFFE01919)
val AlertRed = Color(0xFFFF2A2A)
val SteelSilver = Color(0xFFA9B0B8)
val AllClearGreen = Color(0xFF00E85A)
val ScanningBlue = Color(0xFF168CFF)
val CautionGold = Color(0xFFFFC21A)
val BrutusWhite = Color(0xFFF2F2F2)

private val BrutusColors = darkColorScheme(
    primary = BrutusRed,
    onPrimary = Color.White,
    secondary = SteelSilver,
    background = BrutusBlack,
    onBackground = BrutusWhite,
    surface = BrutusPanel,
    onSurface = BrutusWhite,
    error = AlertRed,
    onError = Color.White
)

@Composable
fun BrutusShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = BrutusColors,
        content = content
    )
}
