package com.hughmongus.brutusshield

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.core.view.WindowCompat
import com.hughmongus.brutusshield.ui.BrutusShieldApp
import com.hughmongus.brutusshield.ui.BrutusShieldTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        setContent {
            BrutusShieldTheme {
                BrutusShieldApp()
            }
        }
    }
}
