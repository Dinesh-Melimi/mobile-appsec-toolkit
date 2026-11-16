"""
Shared detection logic for mobile application security analysis.

Pure-Python, dependency-free detectors used by both the Android (APK) and iOS
(IPA) static analyzers. Keeping them here makes the rules unit-testable without
needing a real mobile binary, and lets the same rule fire across platforms.

Findings are mapped to OWASP MASVS controls and MASTG test IDs where applicable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


# Severity ordering used for sorting and report summaries.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    """A single security finding."""
    id: str                      # stable rule id, e.g. "ANDROID_CLEARTEXT_TRAFFIC"
    title: str
    severity: str                # critical | high | medium | low | info
    masvs: str                   # OWASP MASVS control, e.g. "MASVS-NETWORK-1"
    mastg: str                   # OWASP MASTG test id, e.g. "MASTG-TEST-0021"
    evidence: str = ""           # concrete string/line that triggered the rule
    location: str = ""           # file / component the evidence came from
    remediation: str = ""

    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 99), self.id)


# --- Hardcoded-secret detection -------------------------------------------------
# High-signal patterns only; tuned to keep false positives low. Each entry is
# (rule_id, human label, compiled regex).
_SECRET_PATTERNS = [
    ("SECRET_AWS_AKID", "AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("SECRET_GOOGLE_API", "Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("SECRET_SLACK_TOKEN", "Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("SECRET_PRIVATE_KEY", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SECRET_JWT", "JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("SECRET_GENERIC_API", "Generic api/secret assignment",
     re.compile(r"""(?i)(?:api[_-]?key|secret|passwd|password|auth[_-]?token)\s*[:=]\s*['"][^'"\s]{8,}['"]""")),
    ("SECRET_BEARER", "Hardcoded bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
]

# Weak / broken cryptography indicators. MASVS-CRYPTO-1 / MASVS-CRYPTO-2.
_WEAK_CRYPTO_PATTERNS = [
    ("CRYPTO_MD5", "MD5 used", re.compile(r'(?i)\b(?:MessageDigest\.getInstance\(\s*)?["\']?MD5["\']?')),
    ("CRYPTO_SHA1", "SHA-1 used", re.compile(r'(?i)["\']SHA-?1["\']')),
    ("CRYPTO_DES", "DES/3DES used", re.compile(r'(?i)["\'](?:DESede|DES)(?:/|["\'])')),
    ("CRYPTO_ECB", "ECB cipher mode", re.compile(r'(?i)["\'][A-Z0-9]+/ECB/')),
    ("CRYPTO_STATIC_IV", "Static/zero IV", re.compile(r"(?i)IvParameterSpec\(\s*new byte\[")),
    ("CRYPTO_RC4", "RC4 stream cipher", re.compile(r'(?i)["\']RC4["\']')),
]


def scan_secrets(text: str, location: str = "") -> list[Finding]:
    """Return hardcoded-secret findings for a blob of text."""
    out: list[Finding] = []
    for rule_id, label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            out.append(Finding(
                id=rule_id,
                title=f"Hardcoded secret: {label}",
                severity="high",
                masvs="MASVS-STORAGE-1",
                mastg="MASTG-TEST-0011",
                evidence=_redact(m.group(0)),
                location=location,
                remediation="Remove the secret from the app bundle. Store credentials "
                            "server-side or in the platform keystore/keychain and fetch at runtime.",
            ))
    return out


def scan_weak_crypto(text: str, location: str = "") -> list[Finding]:
    """Return weak-cryptography findings for a blob of text."""
    out: list[Finding] = []
    for rule_id, label, pat in _WEAK_CRYPTO_PATTERNS:
        if pat.search(text):
            out.append(Finding(
                id=rule_id,
                title=f"Weak cryptography: {label}",
                severity="medium",
                masvs="MASVS-CRYPTO-1",
                mastg="MASTG-TEST-0014",
                evidence=label,
                location=location,
                remediation="Use AES-256-GCM (or platform AEAD) with random IVs and keys from "
                            "the Keystore/Keychain. Use SHA-256+ for hashing.",
            ))
    return out


def _redact(secret: str) -> str:
    """Show only enough of a secret to recognise it; never emit it in full."""
    secret = secret.replace("\n", " ")
    if len(secret) <= 10:
        return secret[:2] + "***"
    return secret[:6] + "***" + secret[-2:]


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse identical (id, evidence, location) findings and sort by severity."""
    seen = {}
    for f in findings:
        seen[(f.id, f.evidence, f.location)] = f
    return sorted(seen.values(), key=lambda f: f.sort_key())
