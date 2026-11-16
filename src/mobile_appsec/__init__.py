"""
mobile_appsec — a lightweight mobile application security assessment toolkit.

Static analysis for Android (APK) and iOS (IPA) apps, mapped to the OWASP
Mobile Application Security Verification Standard (MASVS) and Testing Guide (MASTG).
"""
from .detectors import Finding, scan_secrets, scan_weak_crypto, dedupe
from .android_static import analyze_apk, analyze_manifest_xml
from .ios_static import analyze_ipa, analyze_info_plist
from .report import to_json, to_markdown

__version__ = "0.1.0"
__all__ = [
    "Finding", "scan_secrets", "scan_weak_crypto", "dedupe",
    "analyze_apk", "analyze_manifest_xml",
    "analyze_ipa", "analyze_info_plist",
    "to_json", "to_markdown",
]
