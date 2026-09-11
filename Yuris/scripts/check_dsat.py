"""Gate: dual-line text files pass every import check.

Runs the same validation the repacker runs, so a file that passes here will not
be rejected later, and any tampering is reported with its precise location.

Exit code 0 when every check passes, 1 otherwise.  JSON report on stdout.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import assembler  # noqa: E402
import disassembler as dis  # noqa: E402


def check_one(source: pathlib.Path, text_path: pathlib.Path,
              table: dis.CommandTable | None) -> list[dict]:
    try:
        document = dis.parse(source, command_table=table)
    except dis.NotAScriptError:
        return []
    except dis.DisassemblyError as exc:
        return [{"code": "PARSE_FAILED", "file": source.name, "detail": str(exc)}]

    entries = dis.extract_text_entries(document)
    fresh = dis.render_texts(document, entries)
    user = text_path.read_text(encoding=assembler.DIALECT["encodings"]["text_file"])
    try:
        edits = assembler.diff_texts(fresh, user, str(text_path))
        assembler.build_replacements(
            document, entries, edits,
            assembler.DIALECT["encodings"]["target"], source.name,
        )
    except assembler.ImportError_ as exc:
        return [{"code": exc.code, "file": source.name, "detail": exc.detail.split("\n")[0]}]
    except assembler.RepackError as exc:
        return [{"code": "REPACK_REFUSED", "file": source.name, "detail": str(exc)}]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sources", type=pathlib.Path, help="directory of original scripts")
    parser.add_argument("texts", type=pathlib.Path, help="directory holding texts/")
    args = parser.parse_args(argv)

    text_root = args.texts / "texts" if (args.texts / "texts").is_dir() else args.texts
    table = dis.CommandTable.find(args.sources)
    violations: list[dict] = []
    checked = 0
    missing = 0
    for source in dis.iter_sources(args.sources):
        text_path = dis.mirror_path(source, args.sources, text_root, ".txt")
        if not text_path.is_file():
            missing += 1
            continue
        found = check_one(source, text_path, table)
        violations.extend(found)
        checked += 1

    if not checked:
        violations.append({
            "code": "NO_TEXT_FILES",
            "detail": f"no dual-line files found under {text_root}",
        })
    print(json.dumps({
        "gate": "dsat",
        "sources": str(args.sources),
        "texts": str(text_root),
        "checked": checked,
        "without_text_file": missing,
        "violations": violations,
        "passed": not violations,
    }, ensure_ascii=False, indent=2))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
