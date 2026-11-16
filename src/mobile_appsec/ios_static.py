"""
iOS (IPA / app bundle) static analysis.

Parses Info.plist for App Transport Security and URL-scheme issues, and scans
the Mach-O binary's printable strings for hardcoded secrets and weak crypto.

Checks (mapped to OWASP MASVS / MASTG):
  - ATS disabled (NSAllowsArbitraryLoads)   MASVS-NETWORK-1 / MASTG-TEST-0063
  - Per-domain ATS exceptions               MASVS-NETWORK-1
  - Custom URL schemes (hijack surface)      MASVS-PLATFORM-1
  - Hardcoded secrets in binary strings      MASVS-STORAGE-1 / MASTG-TEST-0011
  - Weak crypto references                    MASVS-CRYPTO-1  / MASTG-TEST-0014
"""
from __future__ import annotations

import plistlib
import zipfile
from typing import Union

from .detectors import Finding, scan_secrets, scan_weak_crypto, dedupe


def analyze_info_plist(data: Union[bytes, dict]) -> list[Finding]:
    """Run checks on an Info.plist (raw bytes or an already-parsed dict)."""
    plist = data if isinstance(data, dict) else plistlib.loads(data)
    out: list[Finding] = []

    ats = plist.get("NSAppTransportSecurity", {})
    if ats.get("NSAllowsArbitraryLoads") is True:
        out.append(Finding(
            "IOS_ATS_DISABLED", "App Transport Security disabled globally", "high",
            "MASVS-NETWORK-1", "MASTG-TEST-0063",
            evidence="NSAllowsArbitraryLoads = true", location="Info.plist",
            remediation="Remove NSAllowsArbitraryLoads; require TLS 1.2+ and forward secrecy."))
    for domain, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            out.append(Finding(
                "IOS_ATS_EXCEPTION", f"ATS exception allows HTTP for {domain}", "medium",
                "MASVS-NETWORK-1", "MASTG-TEST-0063",
                evidence=f"{domain}: NSExceptionAllowsInsecureHTTPLoads", location="Info.plist",
                remediation="Remove the per-domain HTTP exception; serve the domain over HTTPS."))

    for scheme_entry in plist.get("CFBundleURLTypes", []) or []:
        for scheme in scheme_entry.get("CFBundleURLSchemes", []) or []:
            out.append(Finding(
                "IOS_CUSTOM_URL_SCHEME", f"Custom URL scheme registered: {scheme}", "low",
                "MASVS-PLATFORM-1", "MASTG-TEST-0062",
                evidence=scheme, location="Info.plist",
                remediation="Prefer Universal Links; validate and authenticate all URL-scheme input."))

    if plist.get("UIFileSharingEnabled") is True:
        out.append(Finding(
            "IOS_FILE_SHARING", "iTunes file sharing enabled", "medium",
            "MASVS-STORAGE-2", "MASTG-TEST-0009",
            evidence="UIFileSharingEnabled = true", location="Info.plist",
            remediation="Disable file sharing unless required; never expose sensitive files."))
    return out


def analyze_ipa(path: str) -> list[Finding]:
    """Analyse an .ipa: pull Info.plist and scan the app binary's strings."""
    findings: list[Finding] = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        plist_name = next((n for n in names if n.endswith(".app/Info.plist")), None)
        if plist_name:
            try:
                findings += analyze_info_plist(z.read(plist_name))
            except Exception:
                pass
        # Mach-O binary: Payload/<App>.app/<App>  (no extension, same stem as .app)
        for n in names:
            if ".app/" in n and n.rsplit("/", 1)[-1] and "." not in n.rsplit("/", 1)[-1]:
                try:
                    blob = _printable_strings(z.read(n))
                    findings += scan_secrets(blob, location=n.rsplit("/", 1)[-1])
                    findings += scan_weak_crypto(blob, location=n.rsplit("/", 1)[-1])
                except Exception:
                    continue
    return dedupe(findings)


def _printable_strings(data: bytes, minlen: int = 6) -> str:
    """Extract printable ASCII runs from a binary (like the `strings` tool)."""
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return "\n".join(out)
