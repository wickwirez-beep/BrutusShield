# BRUTUS SHIELD v0.1.0

Native Android virus and malware **risk scanner** with Brutus voice integration.

## Working MVP features

- Quick scan of files directly inside a folder selected by the user
- Recursive deep scan of the selected folder
- Suspicious APK, executable, double-extension, and filename warning rules
- Private quarantine copy with removal attempt through Android's Storage Access Framework
- Installed-app audit for high-risk permission combinations, accessibility services, hidden launchers, and install source
- Local APK manifest analysis and SHA-256 hashing
- Local URL warning-sign analysis without opening the site
- Spoken status reports through Android Text-to-Speech
- Voice commands through Android speech recognition
- Scan history during the current app session
- Brutus artwork, splash screen, launcher icons, and danger/status artwork

## Voice commands

- “Brutus, scan my phone.”
- “Run a deep scan.”
- “Show suspicious apps.”
- “Analyze APK.”
- “Check this link.”
- “Status report.”
- “Stop scan.”

## Important security truth

Brutus Shield reports **risk indicators**, not laboratory-confirmed malware. Android prevents an ordinary app from silently reading every other app's private storage or uninstalling apps without user involvement. File access is granted only when the user selects a folder.

Files and links are not uploaded in v0.1.0. APKs are copied temporarily to the app's private cache for local inspection and removed afterward. The configured Android speech-recognition service may process voice commands according to that service's privacy behavior.

## Build the APK from a phone using GitHub Actions

This repository includes `.github/workflows/build-apk.yml`. Push the source to GitHub and the cloud build starts automatically.

1. Open the repository's **Actions** tab.
2. Open **Build Brutus Shield APK**.
3. Open the newest successful run.
4. Download the `BrutusShield-v0.1.0-debug` artifact.
5. Extract it and install `BrutusShield-v0.1.0-debug.apk`.

Android may ask permission to install unknown apps for the browser or file manager used to open the APK.

## Toolchain

- Kotlin 2.0.21
- Android Gradle Plugin 8.7.3
- Gradle 8.9
- Java 17
- compileSdk / targetSdk 35
- Minimum Android version: Android 8.0 (API 26)

## Credits

Built and designed by **Hugh Mongus**.
