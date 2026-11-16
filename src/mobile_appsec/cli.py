"""
Command-line entry point.

Usage:
    python -m mobile_appsec scan app.apk --format md -o report.md
    python -m mobile_appsec scan app.ipa --format json
    python -m mobile_appsec scan AndroidManifest.xml      # manifest-only quick check
"""
from __future__ import annotations

import argparse
import sys

from .android_static import analyze_apk, analyze_manifest_xml
from .ios_static import analyze_ipa, analyze_info_plist
from .report import to_json, to_markdown
from .detectors import SEVERITY_ORDER


def _analyze(path: str):
    low = path.lower()
    if low.endswith(".apk"):
        return analyze_apk(path)
    if low.endswith(".ipa"):
        return analyze_ipa(path)
    if low.endswith(".xml"):
        with open(path, "r", encoding="utf-8") as fh:
            return analyze_manifest_xml(fh.read())
    if low.endswith(".plist"):
        with open(path, "rb") as fh:
            return analyze_info_plist(fh.read())
    raise SystemExit(f"Unsupported target: {path} (expected .apk, .ipa, .xml, .plist)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mobile_appsec", description="Mobile AppSec static analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an APK / IPA / manifest / plist")
    s.add_argument("target")
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.add_argument("-o", "--output", help="write report to a file instead of stdout")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                   help="exit non-zero if a finding at/above this severity exists (for CI gates)")
    args = p.parse_args(argv)

    findings = _analyze(args.target)
    rendered = to_json(findings, args.target) if args.format == "json" else to_markdown(findings, args.target)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        print(rendered)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
