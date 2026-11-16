# Mobile AppSec Toolkit

A lightweight **mobile application security** assessment toolkit for **Android (APK)**
and **iOS (IPA)** apps. It combines static analysis with runtime (Frida) instrumentation,
and maps every finding to the **OWASP MASVS** controls and **MASTG** test IDs so results
are standards-aligned and audit-ready.

Built to support application security reviews across the mobile stack — iOS/Android,
APIs, authentication flows, secure storage, and TLS — and to wire security checks into
CI/CD as a "shift-left" gate.

> The included `sample-vulnerable-app/` is intentionally insecure and exists only to
> demonstrate findings and remediation. Only test apps you are authorised to assess.

## What it does

**Static analysis**
- **Android** — parses `AndroidManifest.xml` and DEX strings for: debuggable/backup flags,
  cleartext traffic, exported components without permission guards, dangerous permissions,
  hardcoded secrets, and weak crypto.
- **iOS** — parses `Info.plist` and the Mach-O binary for: App Transport Security
  (NSAllowsArbitraryLoads) issues, per-domain HTTP exceptions, risky custom URL schemes,
  file-sharing exposure, hardcoded secrets, and weak crypto.
- Secrets are **redacted** in output — the tool never prints a credential in full.

**Dynamic analysis (Frida)**
- `ssl_pinning_bypass.js` — test TLS pinning enforcement (OkHttp, TrustManager, iOS SecTrust).
- `android_storage_audit.js` — trace SharedPreferences / SQLite / Base64 "obfuscation".
- `ios_keychain_audit.js` — observe Keychain accessibility classes and sensitive NSUserDefaults keys.

**Reporting**
- Markdown or JSON, with a severity summary and per-finding MASVS/MASTG mapping and remediation.
- A `--fail-on` severity gate for CI pipelines.

## Install

```bash
git clone https://github.com/<your-username>/mobile-appsec-toolkit.git
cd mobile-appsec-toolkit
pip install -r requirements.txt            # androguard is optional (APK binary parsing)
```

## Usage

```bash
# Scan a real APK or IPA (APK parsing needs androguard installed)
PYTHONPATH=src python -m mobile_appsec scan app.apk --format md -o report.md
PYTHONPATH=src python -m mobile_appsec scan app.ipa --format json

# Quick manifest / plist checks (no mobile binary required)
PYTHONPATH=src python -m mobile_appsec scan AndroidManifest.xml
PYTHONPATH=src python -m mobile_appsec scan Info.plist

# CI gate: non-zero exit if any High+ finding exists
PYTHONPATH=src python -m mobile_appsec scan app.apk --fail-on high
```

Run the Frida scripts against a device/emulator during an authorised assessment:

```bash
frida -U -f com.example.app -l frida/ssl_pinning_bypass.js --no-pause
```

## Example output

See [`examples/android_manifest_report.md`](examples/android_manifest_report.md) and
[`examples/ios_plist_report.md`](examples/ios_plist_report.md), generated from the sample app.

## OWASP MASVS / MASTG coverage

See [`docs/MASVS_mapping.md`](docs/MASVS_mapping.md) for the full rule-to-control matrix.

## Development

```bash
pip install pytest
python -m pytest -q
```

CI runs the test suite and scans the sample app on every push (`.github/workflows/ci.yml`).

## Roadmap

- Native-library (`.so` / Mach-O) hardening checks (PIE, stack canary, RELRO)
- MobSF result ingestion and de-duplication
- Semgrep rule pack for mobile source (Kotlin/Swift)
- SARIF output for GitHub code scanning

## License

MIT — see [`LICENSE`](LICENSE).
