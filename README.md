# BRUTUS SHIELD v0.2.0

Native Android virus and malware **risk scanner** with Brutus voice integration.

## v0.2.0 features

- True deep scan of Android-readable shared storage after the user enables **All Files Access**
- Automatic traversal of Downloads, Documents, media folders, readable SD-card storage, and other shared folders
- Separate recursive folder scan through Android's folder picker
- File-signature checks for disguised Windows, ELF, DEX, and malformed Android packages
- EICAR antivirus test-signature detection
- APK manifest inspection for dangerous permission combinations and accessibility services
- SHA-256 hashes for suspicious executables and Android packages
- Direct private quarantine with an attempt to remove the original file
- Installed-app audit for high-risk permissions, accessibility services, hidden launchers, and install source
- Local APK analyzer and local URL warning-sign analyzer
- Spoken status reports and Android voice commands
- Brutus artwork, splash screen, launcher icons, and status artwork

## Voice commands

- “Brutus, scan my phone.” — opens the remembered folder scan
- “Run a deep scan.” — scans Android-readable shared storage
- “Show suspicious apps.”
- “Analyze APK.”
- “Check this link.”
- “Status report.”
- “Stop scan.”

## Important security truth

Brutus Shield reports **risk indicators**, not laboratory-confirmed malware. On Android 11 and newer, the full deep scan requires the user to enable **Allow access to manage all files** in Android settings. Android still blocks other apps' private sandboxes, protected system partitions, and some protected `Android/data` and `Android/obb` content unless the phone is rooted.

Files and links are not uploaded in v0.2.0. Scanning and hashing happen locally. The configured Android speech-recognition service may process voice commands according to that service's privacy behavior.

## Build the APK from a phone using GitHub Actions

This repository includes `.github/workflows/build-apk.yml`. Push the source to GitHub and the cloud build starts automatically.

1. Open the repository's **Actions** tab.
2. Open **Build Brutus Shield APK**.
3. Open the newest successful run.
4. Download the `BrutusShield-v0.2.0-debug` artifact.
5. Extract it and install `BrutusShield-v0.2.0-debug.apk`.

## Toolchain

- Kotlin 2.0.21
- Android Gradle Plugin 8.7.3
- Gradle 8.9
- Java 17
- compileSdk / targetSdk 35
- Minimum Android version: Android 8.0 (API 26)

## Credits

Built and designed by **Hugh Mongus**.
