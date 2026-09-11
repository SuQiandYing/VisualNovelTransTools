"""Gate: the extraction produced a plausible set of entries.

Byte coverage and roundtrip identity can both pass while zero lines of dialogue
were extracted, so this checks the *content* of the output instead.

Exit code 0 when every check passes, 1 otherwise.  JSON report on stdout.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

# Categories a script corpus must yield.  A visual-novel script cannot contain
# zero dialogue lines, so an empty `msg` count is a failure, not a corpus trait.
REQUIRED_TAGS = ("msg",)
# Dialogue dominating the output is normal and healthy for a script corpus
# (measured: 95.6% msg on a clean extraction), so a high `msg` share is not a
# finding.  What the skew check is really for is a *non-dialogue* category
# swallowing everything, which means text was classified into the wrong bucket.
SKEW_LIMIT = 0.95
SKEW_EXEMPT_TAGS = ("msg",)
MAGNITUDE_RATIO = 10.0


def check(report: dict, baseline: dict | None = None) -> list[dict]:
    findings: list[dict] = []
    tags = report.get("tags", {})
    total = sum(tags.values())

    for tag in REQUIRED_TAGS:
        if not tags.get(tag):
            findings.append({
                "code": "REQUIRED_TAG_ZERO",
                "detail": f"no {tag!r} entries were extracted; a script corpus must contain some",
            })

    if total:
        for tag, count in tags.items():
            if tag in SKEW_EXEMPT_TAGS or len(tags) <= 1:
                continue
            if count / total > SKEW_LIMIT:
                findings.append({
                    "code": "OUTPUT_SKEWED",
                    "detail": f"{tag!r} is {count / total:.1%} of all entries "
                              f"({count}/{total}); dialogue should dominate instead, "
                              "so text is probably classified into the wrong category",
                })

    processed = report.get("processed", 0)
    if processed and total:
        per_file = total / processed
        if per_file < 1.0:
            findings.append({
                "code": "ENTRY_DENSITY_LOW",
                "detail": f"only {per_file:.2f} entries per file",
            })

    if not report.get("roundtrip_identical", False):
        findings.append({
            "code": "ROUNDTRIP_FAILED",
            "detail": f"{len(report.get('roundtrip_failures', []))} files do not rebuild "
                      "byte-identically",
        })

    coverage = report.get("min_byte_coverage", 0.0)
    if coverage < 1.0:
        findings.append({
            "code": "COVERAGE_INCOMPLETE",
            "detail": f"min byte coverage is {coverage}, must be 1.0",
        })

    if report.get("failures"):
        findings.append({
            "code": "FILES_FAILED",
            "detail": f"{len(report['failures'])} files failed to process",
        })

    if baseline:
        old_total = sum(baseline.get("tags", {}).values())
        old_files = baseline.get("processed", 0)
        if old_total and old_files and processed and total:
            old_density = old_total / old_files
            new_density = total / processed
            ratio = max(new_density, old_density) / max(1e-9, min(new_density, old_density))
            if ratio > MAGNITUDE_RATIO:
                findings.append({
                    "code": "DENSITY_SHIFT",
                    "detail": f"entries per file moved from {old_density:.1f} to "
                              f"{new_density:.1f}, more than {MAGNITUDE_RATIO}x",
                })
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=pathlib.Path, help="reports/extract_report.json")
    parser.add_argument("--baseline", type=pathlib.Path, default=None,
                        help="an earlier report to compare entry density against")
    args = parser.parse_args(argv)

    report = json.loads(args.report.read_text(encoding="utf-8"))
    baseline = (
        json.loads(args.baseline.read_text(encoding="utf-8")) if args.baseline else None
    )
    findings = check(report, baseline)
    print(json.dumps({
        "gate": "output_sanity",
        "input": str(args.report),
        "entries": sum(report.get("tags", {}).values()),
        "tags": report.get("tags", {}),
        "violations": findings,
        "passed": not findings,
    }, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
