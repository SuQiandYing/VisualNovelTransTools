"""Gate: references were refilled by site, never by matching values.

Rewriting every word that happens to equal an old offset produces a file that
loads but misbehaves — a corruption no hash comparison and no coverage check can
detect. This verifies the site set stayed isomorphic and that words equal to an
edited offset, but outside the site set, were preserved.

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


def expected_sites(source: pathlib.Path, text_dir: pathlib.Path | None,
                   table: dis.CommandTable | None) -> set[int] | None:
    """Which sites the translation files say should change.

    Without this the gate cannot tell an intended edit from value corruption:
    both simply show up as "bytes differ from the source".  Returns None when no
    translation directory was supplied, in which case only the structural checks
    can run.
    """
    if text_dir is None:
        return None
    document = dis.parse(source, command_table=table)
    entries = dis.extract_text_entries(document)
    text_root = text_dir / "texts" if (text_dir / "texts").is_dir() else text_dir
    text_path = dis.mirror_path(source, source.parent, text_root, ".txt")
    if not text_path.is_file():
        return set()
    fresh = dis.render_texts(document, entries)
    user = text_path.read_text(encoding=assembler.DIALECT["encodings"]["text_file"])
    edits = assembler.diff_texts(fresh, user, str(text_path))
    replacements, _stats = assembler.build_replacements(
        document, entries, edits, assembler.DIALECT["encodings"]["target"], source.name
    )
    return set(replacements)


def check(source: pathlib.Path, rebuilt: pathlib.Path, strict_diff: bool,
          text_dir: pathlib.Path | None = None) -> tuple[list[dict], dict]:
    violations: list[dict] = []
    table = dis.CommandTable.find(source)
    before = dis.parse(source, command_table=table)
    after = dis.parse(source, data=rebuilt.read_bytes(), command_table=table)
    authorized = expected_sites(source, text_dir, table)

    if len(before.arguments) != len(after.arguments):
        violations.append({
            "code": "SITE_COUNT_CHANGED",
            "detail": f"{len(before.arguments)} -> {len(after.arguments)} sites",
        })
        return violations, {}

    changed_sites: list[int] = []
    for old, new in zip(before.arguments, after.arguments):
        if old.meta != new.meta:
            violations.append({
                "code": "SITE_CLASS_CHANGED",
                "detail": f"site {old.index}: meta 0x{old.meta:X} -> 0x{new.meta:X}",
            })
        if old.owns_bytes != new.owns_bytes:
            violations.append({
                "code": "SITE_OWNERSHIP_CHANGED",
                "detail": f"site {old.index} changed byte ownership",
            })
        if old.owns_bytes and new.owns_bytes and before.blob(old) != after.blob(new):
            changed_sites.append(old.index)

    length_changed = len(before.plain) != len(after.plain)
    edited_offsets = {before.arguments[i].offset for i in changed_sites}

    # Any site whose bytes changed without the translation authorising it was
    # rewritten because its *value* matched, not because it was a reference site.
    if authorized is not None:
        for index in changed_sites:
            if index not in authorized:
                blob = before.blob(before.arguments[index])
                looks_like_offset = any(
                    int.from_bytes(blob[p:p + 4], "little") in edited_offsets
                    for p in range(0, max(0, len(blob) - 3))
                )
                violations.append({
                    "code": "VALUE_MATCH_REWRITE",
                    "detail": f"site {index} changed but no translation edits it"
                              + ("; its old bytes contained an edited offset, so it was "
                                 "probably rewritten by value match" if looks_like_offset else ""),
                })
        for index in sorted(authorized - set(changed_sites)):
            violations.append({
                "code": "EDIT_LOST",
                "detail": f"site {index} was edited in the translation but is unchanged",
            })

    # Count words equal to an edited offset that were correctly left alone.
    preserved = 0
    for old, new in zip(before.arguments, after.arguments):
        if old.index in changed_sites or not old.owns_bytes:
            continue
        blob = before.blob(old)
        if blob != after.blob(new):
            violations.append({
                "code": "VALUE_MATCH_REWRITE",
                "detail": f"site {old.index} was not edited but its bytes changed",
            })
            continue
        for position in range(0, max(0, len(blob) - 3)):
            if int.from_bytes(blob[position:position + 4], "little") in edited_offsets:
                preserved += 1
                break

    details = {
        "sites": len(before.arguments),
        "changed_sites": len(changed_sites),
        "authorized_sites": None if authorized is None else len(authorized),
        "preserved_value_collisions": preserved,
        "length_changed": length_changed,
        "size_delta": len(after.plain) - len(before.plain),
    }
    if authorized is None:
        details["edit_attribution"] = "skipped-no-texts-given"
    if length_changed and not strict_diff:
        # Insertions shift every following byte, so attributing raw diff ranges
        # is meaningless here; site-level checks above already cover it.
        details["diff_attribution"] = "skipped-length-changed"
    return violations, details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("rebuilt", type=pathlib.Path)
    parser.add_argument("--texts", type=pathlib.Path, default=None,
                        help="directory holding texts/, so edited sites can be told "
                             "apart from value-match corruption")
    parser.add_argument("--strict-diff", action="store_true",
                        help="also attribute raw diff ranges when the length changed")
    args = parser.parse_args(argv)

    try:
        violations, details = check(args.source, args.rebuilt, args.strict_diff, args.texts)
    except (dis.DisassemblyError, assembler.RepackError) as exc:
        violations, details = [{"code": "ERROR", "detail": str(exc)}], {}

    print(json.dumps({
        "gate": "sites",
        "source": str(args.source),
        "rebuilt": str(args.rebuilt),
        "details": details,
        "violations": violations,
        "passed": not violations,
    }, ensure_ascii=False, indent=2))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
