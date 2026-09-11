"""Gate: byte ownership is complete, exclusive and verifiable.

Recomputes every interval hash from the source, so a certificate cannot claim
coverage it does not have.

Exit code 0 when every check passes, 1 otherwise.  JSON report on stdout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import disassembler as dis  # noqa: E402

TIER_CAPABILITIES = {
    "T0": set(),
    "T1": {"roundtrip"},
    "T2": {"roundtrip", "in_place", "pointer-rewrite"},
    "T3": {"roundtrip", "in_place", "pointer-rewrite", "full-layout"},
    "T4": {"roundtrip", "in_place", "pointer-rewrite", "full-layout", "control-flow"},
}


def check(certificate: dict, plain: bytes) -> list[dict]:
    violations: list[dict] = []
    size = certificate["source_size"]
    if size != len(plain):
        violations.append({
            "code": "SIZE_MISMATCH",
            "detail": f"certificate says {size} bytes, decoded source is {len(plain)}",
        })

    intervals = sorted(certificate["intervals"], key=lambda item: item["start"])
    if not intervals:
        violations.append({"code": "NO_INTERVALS", "detail": "certificate lists no intervals"})
        return violations

    if intervals[0]["start"] != 0:
        violations.append({
            "code": "GAP", "detail": f"coverage starts at {intervals[0]['start']}, not 0",
        })
    if intervals[-1]["end"] != len(plain):
        violations.append({
            "code": "GAP",
            "detail": f"coverage ends at {intervals[-1]['end']}, source is {len(plain)}",
        })

    cursor = 0
    for item in intervals:
        if item["start"] > cursor:
            violations.append({
                "code": "GAP", "detail": f"bytes {cursor}..{item['start']} belong to nobody",
            })
        elif item["start"] < cursor:
            violations.append({
                "code": "OVERLAP",
                "detail": f"bytes {item['start']}..{min(cursor, item['end'])} have two owners",
            })
        actual = hashlib.sha256(plain[item["start"]:item["end"]]).hexdigest()
        if actual != item["raw_sha256"]:
            violations.append({
                "code": "HASH_MISMATCH",
                "detail": f"interval {item['id']} hash does not match the source bytes",
            })
        cursor = max(cursor, item["end"])

    if certificate.get("gaps"):
        violations.append({"code": "GAP", "detail": "certificate itself reports gaps"})
    if certificate.get("overlaps"):
        violations.append({"code": "OVERLAP", "detail": "certificate itself reports overlaps"})
    if certificate.get("byte_coverage") != 1.0:
        violations.append({
            "code": "COVERAGE_INCOMPLETE",
            "detail": f"byte_coverage is {certificate.get('byte_coverage')}, must be 1.0",
        })

    tier_total = sum(certificate.get("tier_coverage", {}).values())
    if tier_total != size:
        violations.append({
            "code": "TIER_SUM",
            "detail": f"tier coverage sums to {tier_total}, source is {size}",
        })

    declared = set(certificate.get("declared_capabilities", []))
    allowed = TIER_CAPABILITIES.get(certificate.get("min_tier", "T0"), set())
    excess = declared - allowed
    if excess:
        violations.append({
            "code": "CAPABILITY_OVERCLAIM",
            "detail": f"min tier {certificate.get('min_tier')} does not allow {sorted(excess)}",
        })

    instruction = certificate.get("instruction_coverage")
    min_tier = certificate.get("min_tier", "T0")
    if min_tier in ("T3", "T4"):
        if instruction != 1.0:
            violations.append({
                "code": "INSTRUCTION_COVERAGE",
                "detail": f"tier {min_tier} requires instruction coverage 1.0, got {instruction}",
            })
    elif instruction != "not_applicable":
        violations.append({
            "code": "INSTRUCTION_COVERAGE",
            "detail": f"tier {min_tier} must report not_applicable, got {instruction}",
        })

    for edge in certificate.get("transform_edges", []):
        if hashlib.sha256(plain).hexdigest() != edge.get("output_hash"):
            violations.append({
                "code": "TRANSFORM_HASH",
                "detail": "transform output hash does not match the decoded source",
            })
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=pathlib.Path, help="original script file")
    parser.add_argument("certificate", type=pathlib.Path, nargs="?", default=None,
                        help="certificate JSON; recomputed from the source when omitted")
    args = parser.parse_args(argv)

    try:
        document = dis.parse(args.source)
    except dis.DisassemblyError as exc:
        print(json.dumps({
            "gate": "coverage_certificate",
            "violations": [{"code": "PARSE_FAILED", "detail": str(exc)}],
            "passed": False,
        }, ensure_ascii=False, indent=2))
        return 1

    certificate = (
        json.loads(args.certificate.read_text(encoding="utf-8")) if args.certificate
        else dis.coverage_certificate(document)
    )
    violations = check(certificate, document.plain)
    print(json.dumps({
        "gate": "coverage_certificate",
        "source": str(args.source),
        "byte_coverage": certificate.get("byte_coverage"),
        "min_tier": certificate.get("min_tier"),
        "intervals": len(certificate.get("intervals", [])),
        "violations": violations,
        "passed": not violations,
    }, ensure_ascii=False, indent=2))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
