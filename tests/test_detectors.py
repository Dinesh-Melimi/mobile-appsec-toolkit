"""Unit tests for the platform-agnostic detectors and manifest/plist checks."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mobile_appsec import (  # noqa: E402
    scan_secrets, scan_weak_crypto, analyze_manifest_xml, analyze_info_plist, dedupe,
)

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "sample-vulnerable-app")


def test_scan_secrets_finds_google_and_generic():
    text = 'String k = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"; password="hunter2secret";'
    ids = {f.id for f in scan_secrets(text)}
    assert "SECRET_GOOGLE_API" in ids
    assert "SECRET_GENERIC_API" in ids


def test_secrets_are_redacted_not_leaked():
    text = 'key = "AKIAIOSFODNN7EXAMPLE"'
    f = scan_secrets(text)[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence
    assert "***" in f.evidence


def test_scan_weak_crypto():
    ids = {f.id for f in scan_weak_crypto('Cipher.getInstance("DES/ECB/PKCS5Padding")')}
    assert "CRYPTO_DES" in ids
    assert "CRYPTO_ECB" in ids


def test_android_manifest_flags():
    with open(os.path.join(SAMPLE, "android", "AndroidManifest.xml"), encoding="utf-8") as fh:
        findings = analyze_manifest_xml(fh.read())
    ids = {f.id for f in findings}
    assert "ANDROID_DEBUGGABLE" in ids
    assert "ANDROID_CLEARTEXT_TRAFFIC" in ids
    assert "ANDROID_ALLOW_BACKUP" in ids
    assert "ANDROID_EXPORTED_COMPONENT" in ids       # TransferActivity + AccountProvider
    assert "ANDROID_DANGEROUS_PERMISSION" in ids      # READ_SMS


def test_ios_info_plist_flags():
    with open(os.path.join(SAMPLE, "ios", "Info.plist"), "rb") as fh:
        findings = analyze_info_plist(fh.read())
    ids = {f.id for f in findings}
    assert "IOS_ATS_DISABLED" in ids
    assert "IOS_ATS_EXCEPTION" in ids
    assert "IOS_CUSTOM_URL_SCHEME" in ids
    assert "IOS_FILE_SHARING" in ids


def test_dedupe_and_severity_sort():
    text = 'k1="AKIAIOSFODNN7EXAMPLE" k2="AKIAIOSFODNN7EXAMPLE"'
    merged = dedupe(scan_secrets(text) + scan_secrets(text))
    # Two distinct matches by position collapse to unique (id, evidence, location) pairs.
    assert all(merged[i].sort_key() <= merged[i + 1].sort_key() for i in range(len(merged) - 1))
