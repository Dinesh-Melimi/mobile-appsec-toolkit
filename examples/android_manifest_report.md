# Mobile AppSec Report — sample-vulnerable-app/android/AndroidManifest.xml

## Summary

| Severity | Count |
| --- | --- |
| High | 2 |
| Medium | 3 |
| Low | 2 |

## Findings

### [HIGH] Cleartext (HTTP) traffic permitted

- **Rule:** `ANDROID_CLEARTEXT_TRAFFIC`
- **OWASP MASVS:** MASVS-NETWORK-1  |  **MASTG:** MASTG-TEST-0021
- **Location:** AndroidManifest.xml
- **Evidence:** `android:usesCleartextTraffic="true"`
- **Remediation:** Disable cleartext traffic and enforce TLS via a network security config.

### [HIGH] Application is debuggable

- **Rule:** `ANDROID_DEBUGGABLE`
- **OWASP MASVS:** MASVS-RESILIENCE-4  |  **MASTG:** MASTG-TEST-0070
- **Location:** AndroidManifest.xml
- **Evidence:** `android:debuggable="true"`
- **Remediation:** Ship release builds with android:debuggable=false.

### [MEDIUM] ADB backup of app data allowed

- **Rule:** `ANDROID_ALLOW_BACKUP`
- **OWASP MASVS:** MASVS-STORAGE-2  |  **MASTG:** MASTG-TEST-0009
- **Location:** AndroidManifest.xml
- **Evidence:** `android:allowBackup not disabled`
- **Remediation:** Set android:allowBackup=false or define a strict backup rules set.

### [MEDIUM] Exported activity without permission

- **Rule:** `ANDROID_EXPORTED_COMPONENT`
- **OWASP MASVS:** MASVS-PLATFORM-1  |  **MASTG:** MASTG-TEST-0024
- **Location:** AndroidManifest.xml
- **Evidence:** `.TransferActivity`
- **Remediation:** Set exported=false, or guard the component with a signature-level permission.

### [MEDIUM] Exported provider without permission

- **Rule:** `ANDROID_EXPORTED_COMPONENT`
- **OWASP MASVS:** MASVS-PLATFORM-1  |  **MASTG:** MASTG-TEST-0024
- **Location:** AndroidManifest.xml
- **Evidence:** `.AccountProvider`
- **Remediation:** Set exported=false, or guard the component with a signature-level permission.

### [LOW] Dangerous permission: READ_SMS

- **Rule:** `ANDROID_DANGEROUS_PERMISSION`
- **OWASP MASVS:** MASVS-PLATFORM-1  |  **MASTG:** MASTG-TEST-0025
- **Location:** AndroidManifest.xml
- **Evidence:** `android.permission.READ_SMS`
- **Remediation:** Request only the permissions the feature needs; justify each dangerous one.

### [LOW] Dangerous permission: WRITE_EXTERNAL_STORAGE

- **Rule:** `ANDROID_DANGEROUS_PERMISSION`
- **OWASP MASVS:** MASVS-PLATFORM-1  |  **MASTG:** MASTG-TEST-0025
- **Location:** AndroidManifest.xml
- **Evidence:** `android.permission.WRITE_EXTERNAL_STORAGE`
- **Remediation:** Request only the permissions the feature needs; justify each dangerous one.
