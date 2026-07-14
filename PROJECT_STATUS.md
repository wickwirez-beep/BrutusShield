# Brutus Shield Project Status — v0.2.0

Implemented:

- All Files Access onboarding for Android 11+
- Full shared-storage traversal with cancellation and live progress
- Separate recursive folder scanner
- File signature, extension-disguise, APK manifest, permission-combination, and EICAR checks
- SHA-256 hashing of suspicious executable files
- Direct-file and Storage Access Framework quarantine paths
- Installed-app audit, APK analyzer, link analyzer, scan history, voice commands, and speech output

Android limits remain: no ordinary non-root app can read other apps' private sandboxes or protected system partitions.
