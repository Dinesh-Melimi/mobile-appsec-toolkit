# OWASP MASVS / MASTG Coverage

Every rule emitted by the toolkit maps to an OWASP **Mobile Application Security
Verification Standard (MASVS)** control and, where applicable, a **Mobile Application
Security Testing Guide (MASTG)** test. This keeps assessment output aligned with the
standard security teams and auditors expect.

| Rule ID | Platform | Severity | MASVS | MASTG | What it catches |
| --- | --- | --- | --- | --- | --- |
| `ANDROID_DEBUGGABLE` | Android | High | MASVS-RESILIENCE-4 | MASTG-TEST-0070 | `android:debuggable="true"` in release |
| `ANDROID_ALLOW_BACKUP` | Android | Medium | MASVS-STORAGE-2 | MASTG-TEST-0009 | ADB backup of app data allowed |
| `ANDROID_CLEARTEXT_TRAFFIC` | Android | High | MASVS-NETWORK-1 | MASTG-TEST-0021 | Cleartext HTTP permitted |
| `ANDROID_EXPORTED_COMPONENT` | Android | Medium | MASVS-PLATFORM-1 | MASTG-TEST-0024 | Exported activity/service/provider w/o permission |
| `ANDROID_DANGEROUS_PERMISSION` | Android | Low | MASVS-PLATFORM-1 | MASTG-TEST-0025 | Excessive / dangerous permission requested |
| `IOS_ATS_DISABLED` | iOS | High | MASVS-NETWORK-1 | MASTG-TEST-0063 | App Transport Security disabled globally |
| `IOS_ATS_EXCEPTION` | iOS | Medium | MASVS-NETWORK-1 | MASTG-TEST-0063 | Per-domain insecure HTTP exception |
| `IOS_CUSTOM_URL_SCHEME` | iOS | Low | MASVS-PLATFORM-1 | MASTG-TEST-0062 | Custom URL scheme (input/hijack surface) |
| `IOS_FILE_SHARING` | iOS | Medium | MASVS-STORAGE-2 | MASTG-TEST-0009 | iTunes file sharing enabled |
| `SECRET_*` | Both | High | MASVS-STORAGE-1 | MASTG-TEST-0011 | Hardcoded API keys, tokens, private keys |
| `CRYPTO_*` | Both | Medium | MASVS-CRYPTO-1 | MASTG-TEST-0014 | MD5/SHA-1/DES/ECB/RC4/static-IV usage |

## Dynamic (Frida) coverage

| Script | MASVS | MASTG | Purpose |
| --- | --- | --- | --- |
| `ssl_pinning_bypass.js` | MASVS-NETWORK-2 | MASTG-TEST-0022 | Verify TLS pinning is actually enforced |
| `android_storage_audit.js` | MASVS-STORAGE-1 | MASTG-TEST-0001 | Observe runtime data-at-rest sinks |
| `ios_keychain_audit.js` | MASVS-STORAGE-1 | MASTG-TEST-0053 | Keychain accessibility + NSUserDefaults misuse |

## Assessment methodology

1. **Recon** — unpack the app, enumerate components, entitlements, and third-party SDKs.
2. **Static** — run the analyzers; triage findings, remove false positives, map to MASVS.
3. **Dynamic** — instrument on device with Frida: pinning, storage, Keychain/Keystore, WebViews.
4. **Report** — document each issue with evidence, business impact, and remediation; gate CI on severity.
