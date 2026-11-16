"""
Android (APK) static analysis.

Uses androguard when available to parse the real binary (manifest + DEX strings).
Also exposes manifest-level checks that run on a plain AndroidManifest.xml string,
so the rules are testable without shipping an APK in the repo.

Checks (mapped to OWASP MASVS / MASTG):
  - Debuggable / backup flags            MASVS-RESILIENCE / MASVS-STORAGE
  - Cleartext traffic allowed            MASVS-NETWORK-1   / MASTG-TEST-0021
  - Exported components w/o permission   MASVS-PLATFORM-1  / MASTG-TEST-0024
  - Dangerous / excessive permissions    MASVS-PLATFORM-1
  - Hardcoded secrets in DEX strings     MASVS-STORAGE-1   / MASTG-TEST-0011
  - Weak crypto usage in DEX strings     MASVS-CRYPTO-1    / MASTG-TEST-0014
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from .detectors import Finding, scan_secrets, scan_weak_crypto, dedupe

_ANDROID = "{http://schemas.android.com/apk/res/android}"

_DANGEROUS_PERMS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_CALL_LOG",
    "android.permission.CAMERA", "android.permission.REQUEST_INSTALL_PACKAGES",
}


def analyze_manifest_xml(xml: str) -> list[Finding]:
    """Run manifest-level checks against a decoded AndroidManifest.xml string."""
    out: list[Finding] = []
    root = ET.fromstring(xml)
    app = root.find("application")

    if app is not None:
        if app.get(f"{_ANDROID}debuggable") == "true":
            out.append(Finding(
                "ANDROID_DEBUGGABLE", "Application is debuggable", "high",
                "MASVS-RESILIENCE-4", "MASTG-TEST-0070",
                evidence='android:debuggable="true"', location="AndroidManifest.xml",
                remediation="Ship release builds with android:debuggable=false."))
        if app.get(f"{_ANDROID}allowBackup") in (None, "true"):
            out.append(Finding(
                "ANDROID_ALLOW_BACKUP", "ADB backup of app data allowed", "medium",
                "MASVS-STORAGE-2", "MASTG-TEST-0009",
                evidence='android:allowBackup not disabled', location="AndroidManifest.xml",
                remediation="Set android:allowBackup=false or define a strict backup rules set."))
        if app.get(f"{_ANDROID}usesCleartextTraffic") == "true":
            out.append(Finding(
                "ANDROID_CLEARTEXT_TRAFFIC", "Cleartext (HTTP) traffic permitted", "high",
                "MASVS-NETWORK-1", "MASTG-TEST-0021",
                evidence='android:usesCleartextTraffic="true"', location="AndroidManifest.xml",
                remediation="Disable cleartext traffic and enforce TLS via a network security config."))

    # Exported components reachable by other apps with no permission guard.
    for tag in ("activity", "service", "receiver", "provider"):
        for comp in root.iter(tag):
            exported = comp.get(f"{_ANDROID}exported")
            has_filter = comp.find("intent-filter") is not None
            name = comp.get(f"{_ANDROID}name", "<unknown>")
            # Exported if explicitly true, or (pre-S default) has an intent-filter.
            is_exported = exported == "true" or (exported is None and has_filter)
            if is_exported and not comp.get(f"{_ANDROID}permission"):
                out.append(Finding(
                    "ANDROID_EXPORTED_COMPONENT", f"Exported {tag} without permission", "medium",
                    "MASVS-PLATFORM-1", "MASTG-TEST-0024",
                    evidence=name, location="AndroidManifest.xml",
                    remediation="Set exported=false, or guard the component with a signature-level permission."))

    for perm in root.iter("uses-permission"):
        pname = perm.get(f"{_ANDROID}name", "")
        if pname in _DANGEROUS_PERMS:
            out.append(Finding(
                "ANDROID_DANGEROUS_PERMISSION", f"Dangerous permission: {pname.split('.')[-1]}", "low",
                "MASVS-PLATFORM-1", "MASTG-TEST-0025",
                evidence=pname, location="AndroidManifest.xml",
                remediation="Request only the permissions the feature needs; justify each dangerous one."))
    return out


def analyze_apk(path: str) -> list[Finding]:
    """Full APK analysis using androguard. Returns [] with an INFO finding if unavailable."""
    try:
        from androguard.core.apk import APK  # type: ignore
    except Exception:
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore  (older androguard)
        except Exception:
            return [Finding(
                "TOOLING_ANDROGUARD_MISSING", "androguard not installed", "info",
                "-", "-", evidence="pip install androguard",
                remediation="Install androguard to parse APK binaries.")]

    findings: list[Finding] = []
    apk = APK(path)
    try:
        findings += analyze_manifest_xml(apk.get_android_manifest_axml().get_xml())
    except Exception:
        pass

    # DEX string scan for secrets / weak crypto.
    blob = _dex_strings(apk)
    findings += scan_secrets(blob, location="classes.dex")
    findings += scan_weak_crypto(blob, location="classes.dex")
    return dedupe(findings)


def _dex_strings(apk) -> str:
    """Concatenate DEX string constants for pattern scanning."""
    out = []
    try:
        from androguard.core.dex import DEX  # type: ignore
        for dex in apk.get_all_dex():
            try:
                out.extend(DEX(dex).get_strings())
            except Exception:
                continue
    except Exception:
        return ""
    return "\n".join(str(s) for s in out)
