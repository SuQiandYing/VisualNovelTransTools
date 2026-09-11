"""Gate: rendering is deterministic and hash semantics point the right way.

Two subcommands, deliberately opposite in direction:

  rerun  same input rendered twice must be byte-identical
  edit   no edits => output identical to source;
         with edits => output MUST differ (otherwise edits were dropped)

Treating "hash unchanged" as success after an edit is exactly how a silently
dropped edit passes review, so both directions are tested.

Exit code 0 when every check passes, 1 otherwise.  JSON report on stdout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import assembler  # noqa: E402
import disassembler as dis  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cmd_rerun(args) -> tuple[list[dict], dict]:
    violations: list[dict] = []
    if args.second is not None:
        first = args.first.read_bytes()
        second = args.second.read_bytes()
        if first != second:
            violations.append({
                "code": "RENDER_NONDETERMINISTIC",
                "detail": f"{args.first} and {args.second} differ",
            })
        return violations, {"a": sha(first), "b": sha(second)}

    # No second file: render the source twice in-process.
    document = dis.parse(args.first)
    asm_a, asm_b = dis.render_asm(document), dis.render_asm(document)
    texts_a, texts_b = dis.render_texts(document), dis.render_texts(document)
    if asm_a != asm_b:
        violations.append({"code": "RENDER_NONDETERMINISTIC", "detail": "asm differs between runs"})
    if texts_a != texts_b:
        violations.append({"code": "RENDER_NONDETERMINISTIC", "detail": "texts differ between runs"})
    # Re-parsing the same bytes must give the same IR too.
    again = dis.parse(args.first)
    if dis.render_asm(again) != asm_a:
        violations.append({"code": "PARSE_NONDETERMINISTIC", "detail": "re-parse renders differently"})
    return violations, {
        "asm_sha256": sha(asm_a.encode()),
        "texts_sha256": sha(texts_a.encode()),
    }


def cmd_edit(args) -> tuple[list[dict], dict]:
    violations: list[dict] = []
    document = dis.parse(args.source)
    source_hash = sha(document.raw)

    zero = assembler.serialize(document, {})
    if sha(zero) != source_hash:
        violations.append({
            "code": "ZERO_EDIT_CHANGED",
            "detail": "rebuilding without edits did not reproduce the source",
        })

    details = {"source_sha256": source_hash, "zero_edit_sha256": sha(zero)}

    if not args.no_edit:
        entries = dis.extract_text_entries(document)
        # Prefer a dialogue line, but any editable single-slot entry proves
        # determinism.  A character-name table holds no `msg` at all, and its
        # rows are exactly what this tool now edits.
        target = next(
            (e for e in entries if e.tag == "msg" and "{{" not in e.source
             and len(e.arg_indexes) == 1),
            None,
        ) or next(
            (e for e in entries
             if e.translate_policy != "frozen" and "{{" not in e.source
             and len(e.arg_indexes) == 1),
            None,
        )
        if target is None:
            violations.append({
                "code": "NO_EDITABLE_ENTRY",
                "detail": "no editable single-slot entry to test an edit with",
            })
            return violations, details
        payload = dis.encode_display(target.source * 2, "cp932")
        replacements = {target.arg_indexes[0]: payload}
        edited = assembler.serialize(document, replacements)
        details["edited_sha256"] = sha(edited)
        details["size_delta"] = len(edited) - len(document.raw)
        if sha(edited) == source_hash:
            violations.append({
                "code": "EDIT_LOST",
                "detail": "the file was edited but the output is unchanged",
            })
        else:
            try:
                assembler.verify(document, edited, replacements, expect_identical=False)
            except assembler.RepackError as exc:
                violations.append({"code": "EDIT_UNVERIFIED", "detail": str(exc)})
    return violations, details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="mode", required=True)

    rerun = subparsers.add_parser("rerun", help="rendering is byte-stable across runs")
    rerun.add_argument("first", type=pathlib.Path)
    rerun.add_argument("second", type=pathlib.Path, nargs="?", default=None)

    edit = subparsers.add_parser("edit", help="hash changes exactly when edits are applied")
    edit.add_argument("source", type=pathlib.Path)
    edit.add_argument("rebuilt", type=pathlib.Path, nargs="?", default=None)
    edit.add_argument("--no-edit", action="store_true",
                      help="only check the zero-edit direction")

    args = parser.parse_args(argv)
    try:
        violations, details = cmd_rerun(args) if args.mode == "rerun" else cmd_edit(args)
    except (dis.DisassemblyError, assembler.RepackError) as exc:
        violations, details = [{"code": "ERROR", "detail": str(exc)}], {}

    print(json.dumps({
        "gate": f"determinism/{args.mode}",
        "details": details,
        "violations": violations,
        "passed": not violations,
    }, ensure_ascii=False, indent=2))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
