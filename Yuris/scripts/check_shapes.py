"""Gate: every structural shape is declared, and every declared shape is used.

Catches the failure where a newly added shape declaration never matches while an
existing branch "succeeds" and returns nothing.

Exit code 0 when every check passes, 1 otherwise.  JSON report on stdout.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import opcodelist  # noqa: E402

DRIFT_RATIO = 10.0


def check(observed: dict[str, int], corpus_wide: bool,
          baseline: dict[str, int] | None) -> tuple[list[dict], list[dict]]:
    declared = {shape["id"] for shape in opcodelist.DIALECT["entry_shapes"]}
    optional = {shape["id"] for shape in opcodelist.DIALECT["entry_shapes"]
                if shape.get("optional")}
    violations: list[dict] = []
    advisories: list[dict] = []

    for shape_id, count in sorted(observed.items()):
        if shape_id not in declared:
            violations.append({
                "code": "SHAPE_UNDECLARED",
                "detail": f"{shape_id!r} was observed {count} times but is not declared",
            })
        elif count == 0:
            violations.append({
                "code": "BARREN_SHAPE",
                "detail": f"{shape_id!r} matched entries but produced no text",
            })

    # A single file legitimately shows only some shapes, so "never matched" is
    # only a failure when judged over the whole corpus.
    for shape_id in sorted(declared - set(observed)):
        finding = {
            "code": "SHAPE_NEVER_MATCHED",
            "detail": f"{shape_id!r} is declared but never matched; "
                      "its match condition may be wrong",
        }
        fail = corpus_wide and shape_id not in optional
        (violations if fail else advisories).append(finding)

    if baseline:
        for shape_id, old in baseline.items():
            new = observed.get(shape_id, 0)
            if not old:
                continue
            ratio = max(new, old) / max(1, min(new, old)) if new else float("inf")
            if ratio > DRIFT_RATIO:
                violations.append({
                    "code": "SHAPE_DRIFT",
                    "detail": f"{shape_id!r} moved from {old} to {new} against the baseline",
                })
    return violations, advisories


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=pathlib.Path, help="reports/shapes.json")
    parser.add_argument("--corpus-wide", action="store_true",
                        help="the report covers a whole corpus, so unused shapes are failures")
    parser.add_argument("--baseline", type=pathlib.Path, default=None,
                        help="an earlier shapes.json to compare against")
    args = parser.parse_args(argv)

    payload = json.loads(args.report.read_text(encoding="utf-8"))
    observed = payload.get("shape_signatures", payload)
    baseline = None
    if args.baseline:
        raw = json.loads(args.baseline.read_text(encoding="utf-8"))
        baseline = raw.get("shape_signatures", raw)

    violations, advisories = check(observed, args.corpus_wide, baseline)
    print(json.dumps({
        "gate": "shapes",
        "input": str(args.report),
        "declared": sorted(s["id"] for s in opcodelist.DIALECT["entry_shapes"]),
        "observed": observed,
        "unresolved": payload.get("unresolved", 0),
        "violations": violations,
        "advisories": advisories,
        "passed": not violations,
    }, ensure_ascii=False, indent=2))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
