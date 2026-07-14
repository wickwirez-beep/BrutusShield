# Brutus Shield Project Status — v0.3.0

Implemented:

- All Files Access onboarding for Android 11+
- Full shared-storage traversal with cancellation and live progress
- Separate recursive folder scanner
- File signature, extension-disguise, APK manifest, permission-combination, and EICAR checks
- SHA-256 hashing of suspicious executable files
- Direct-file and Storage Access Framework quarantine paths
- Installed-app audit, APK analyzer, link analyzer, scan history, voice commands, and speech output

Android limits remain: no ordinary non-root app can read other apps' private sandboxes or protected system partitions.

## v0.3.0 additions
- Offline malware engine and dedicated Malware Scan screen
- Bundled rule database: 2026.07.14.1
- Exact hashes for EICAR and a starter set of publicly reported Android malware samples
- YARA-inspired APK content and behavior rules
- Installed-app APK scanning and downloaded-APK signer mismatch detection
- No file, APK, hash, or URL uploads
- Bundled rules are static in v0.3.0; cryptographically signed rule updates are planned for the next engine milestone
