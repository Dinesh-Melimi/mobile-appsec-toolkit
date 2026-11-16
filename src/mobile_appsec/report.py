"""Render findings as JSON or a Markdown report."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from typing import Iterable

from .detectors import Finding, SEVERITY_ORDER


def to_json(findings: Iterable[Finding], target: str = "") -> str:
    return json.dumps(
        {"target": target, "findings": [asdict(f) for f in findings]},
        indent=2,
    )


def to_markdown(findings: list[Finding], target: str = "") -> str:
    counts = Counter(f.severity for f in findings)
    lines = [
        f"# Mobile AppSec Report — {target or 'target'}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 99)):
        lines.append(f"| {sev.capitalize()} | {counts[sev]} |")
    if not findings:
        lines.append("| — | No findings |")
    lines += ["", "## Findings", ""]
    for f in sorted(findings, key=lambda f: f.sort_key()):
        lines += [
            f"### [{f.severity.upper()}] {f.title}",
            "",
            f"- **Rule:** `{f.id}`",
            f"- **OWASP MASVS:** {f.masvs}  |  **MASTG:** {f.mastg}",
            f"- **Location:** {f.location or '-'}",
            f"- **Evidence:** `{f.evidence}`" if f.evidence else "- **Evidence:** -",
            f"- **Remediation:** {f.remediation or '-'}",
            "",
        ]
    return "\n".join(lines)
