# Mobile AppSec Report — sample-vulnerable-app/ios/Info.plist

## Summary

| Severity | Count |
| --- | --- |
| High | 1 |
| Medium | 2 |
| Low | 1 |

## Findings

### [HIGH] App Transport Security disabled globally

- **Rule:** `IOS_ATS_DISABLED`
- **OWASP MASVS:** MASVS-NETWORK-1  |  **MASTG:** MASTG-TEST-0063
- **Location:** Info.plist
- **Evidence:** `NSAllowsArbitraryLoads = true`
- **Remediation:** Remove NSAllowsArbitraryLoads; require TLS 1.2+ and forward secrecy.

### [MEDIUM] ATS exception allows HTTP for api.insecurebank.example

- **Rule:** `IOS_ATS_EXCEPTION`
- **OWASP MASVS:** MASVS-NETWORK-1  |  **MASTG:** MASTG-TEST-0063
- **Location:** Info.plist
- **Evidence:** `api.insecurebank.example: NSExceptionAllowsInsecureHTTPLoads`
- **Remediation:** Remove the per-domain HTTP exception; serve the domain over HTTPS.

### [MEDIUM] iTunes file sharing enabled

- **Rule:** `IOS_FILE_SHARING`
- **OWASP MASVS:** MASVS-STORAGE-2  |  **MASTG:** MASTG-TEST-0009
- **Location:** Info.plist
- **Evidence:** `UIFileSharingEnabled = true`
- **Remediation:** Disable file sharing unless required; never expose sensitive files.

### [LOW] Custom URL scheme registered: insecurebank

- **Rule:** `IOS_CUSTOM_URL_SCHEME`
- **OWASP MASVS:** MASVS-PLATFORM-1  |  **MASTG:** MASTG-TEST-0062
- **Location:** Info.plist
- **Evidence:** `insecurebank`
- **Remediation:** Prefer Universal Links; validate and authenticate all URL-scheme input.
