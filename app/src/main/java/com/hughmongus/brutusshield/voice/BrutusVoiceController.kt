package com.hughmongus.brutusshield.voice

import android.content.Context
import android.speech.tts.TextToSpeech
import java.util.Locale

class BrutusVoiceController(context: Context) : TextToSpeech.OnInitListener {
    private val tts = TextToSpeech(context.applicationContext, this)
    private var ready = false

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            val result = tts.setLanguage(Locale.US)
            ready = result != TextToSpeech.LANG_MISSING_DATA &&
                result != TextToSpeech.LANG_NOT_SUPPORTED
            tts.setPitch(0.72f)
            tts.setSpeechRate(0.88f)
        }
    }

    fun speak(message: String) {
        if (!ready || message.isBlank()) return
        tts.speak(message, TextToSpeech.QUEUE_FLUSH, null, "brutus-status")
    }

    fun stop() {
        tts.stop()
    }

    fun shutdown() {
        tts.stop()
        tts.shutdown()
    }
}

enum class BrutusCommand {
    QUICK_SCAN,
    DEEP_SCAN,
    APP_AUDIT,
    APK_ANALYZER,
    LINK_SCANNER,
    STATUS_REPORT,
    STOP_SCAN,
    UNKNOWN
}

fun parseBrutusCommand(spokenText: String): BrutusCommand {
    val text = spokenText.lowercase(Locale.US)
    return when {
        "stop" in text && "scan" in text -> BrutusCommand.STOP_SCAN
        "deep scan" in text || "full scan" in text -> BrutusCommand.DEEP_SCAN
        "quick scan" in text || "scan my phone" in text || "scan the phone" in text -> BrutusCommand.QUICK_SCAN
        "suspicious app" in text || "app audit" in text || "audit apps" in text -> BrutusCommand.APP_AUDIT
        "scan this file" in text || "analyze apk" in text || "apk analyzer" in text -> BrutusCommand.APK_ANALYZER
        "check this link" in text || "link scanner" in text || "scan a link" in text -> BrutusCommand.LINK_SCANNER
        "status report" in text || "device status" in text || "give me a report" in text -> BrutusCommand.STATUS_REPORT
        else -> BrutusCommand.UNKNOWN
    }
}
