"""Run the whole verification matrix against one or both corpora.

Every check here failed at least once during development, so each one is guarding
a real mistake rather than restating an invariant.

    python scripts/run_verification.py E:/77/ysbin
    python scripts/run_verification.py E:/77/ysbin --second-corpus C:/tmp/prim/src

Exit code 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import assembler  # noqa: E402
import disassembler as dis  # noqa: E402


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[tuple[str, str]] = []

    def check(self, name: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.passed += 1
            print(f"  ok   {name}")
        else:
            self.failed.append((name, detail))
            print(f"  FAIL {name}" + (f" — {detail}" if detail else ""))
        return condition


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_corpus(root: pathlib.Path, label: str, results: Results) -> dict:
    print(f"\n=== {label}: {root} ===")
    table = dis.CommandTable.find(root)
    results.check(f"{label}/command table found", table is not None)
    if table is None:
        return {}

    sources = dis.iter_sources(root)
    stats = {
        "files": 0, "skipped": 0, "entries": 0, "roundtrip_ok": 0,
        "roundtrip_bad": [], "coverage_bad": [], "tags": {}, "shapes": {},
        "codecs": {}, "nondeterministic": [],
    }
    for source in sources:
        try:
            document = dis.parse(source, command_table=table)
        except dis.NotAScriptError:
            stats["skipped"] += 1
            continue
        stats["files"] += 1
        entries = dis.extract_text_entries(document)
        stats["entries"] += len(entries)
        for entry in entries:
            stats["tags"][entry.tag] = stats["tags"].get(entry.tag, 0) + 1
            for codec in entry.encodings:
                key = codec or "undecodable"
                stats["codecs"][key] = stats["codecs"].get(key, 0) + 1
        for shape, count in document.shape_counts.items():
            stats["shapes"][shape] = stats["shapes"].get(shape, 0) + count

        if assembler.serialize(document, {}) == document.raw:
            stats["roundtrip_ok"] += 1
        else:
            stats["roundtrip_bad"].append(source.name)

        certificate = dis.coverage_certificate(document)
        if (certificate["byte_coverage"] != 1.0 or certificate["gaps"]
                or certificate["overlaps"]):
            stats["coverage_bad"].append(source.name)

        # Rendering must be byte-stable, otherwise diffing a fresh projection
        # against the user's file reports phantom edits.
        if dis.render_texts(document, entries) != dis.render_texts(document, entries):
            stats["nondeterministic"].append(source.name)

    results.check(f"{label}/every file parses or is knowingly skipped",
                  stats["files"] + stats["skipped"] == len(sources))
    results.check(f"{label}/zero-edit roundtrip is byte-identical",
                  not stats["roundtrip_bad"],
                  f"{len(stats['roundtrip_bad'])} files differ")
    results.check(f"{label}/byte coverage is complete",
                  not stats["coverage_bad"],
                  f"{len(stats['coverage_bad'])} files incomplete")
    results.check(f"{label}/rendering is deterministic", not stats["nondeterministic"])
    results.check(f"{label}/dialogue was extracted", stats["tags"].get("msg", 0) > 0,
                  "zero msg entries")
    results.check(f"{label}/no undecodable text", stats["codecs"].get("undecodable", 0) == 0,
                  f"{stats['codecs'].get('undecodable', 0)} undecodable")
    print(f"  ---- {stats['files']} files, {stats['entries']} entries, "
          f"tags={stats['tags']}, shapes={stats['shapes']}")
    return stats


def script_sources(root: pathlib.Path, table: dis.CommandTable | None) -> list[pathlib.Path]:
    """Files that actually parse as scripts.

    Selected by parse result rather than by name: several non-script files share
    the .ybn extension (the command table and the engine config), and more may
    exist in other games.
    """
    out: list[pathlib.Path] = []
    for candidate in dis.iter_sources(root):
        try:
            dis.parse(candidate, command_table=table)
        except dis.DisassemblyError:
            continue
        out.append(candidate)
    return out


def _first_editable(root: pathlib.Path, table: dis.CommandTable | None):
    """First file that actually offers a single-argument message to edit.

    Not every script has one: a character-name table holds only names, so
    picking file[0] blindly raises StopIteration on some corpora.
    """
    for source in script_sources(root, table):
        document = dis.parse(source, command_table=table)
        entries = dis.extract_text_entries(document)
        target = next(
            (e for e in entries
             if e.tag == "msg" and "{{" not in e.source and len(e.arg_indexes) == 1),
            None,
        )
        if target is not None:
            return source, document, entries, target
    return None


def verify_editing(root: pathlib.Path, results: Results) -> None:
    """Length changes in both directions, plus the refusal paths."""
    print(f"\n=== editing behaviour: {root} ===")
    table = dis.CommandTable.find(root)
    picked = _first_editable(root, table)
    if picked is None:
        results.check("editing/found an editable message", False,
                      "no single-argument message anywhere in this corpus")
        return
    source, document, entries, target = picked
    index = target.arg_indexes[0]

    # Grow
    longer = dis.encode_display(target.source * 2, "cp932")
    grown = assembler.serialize(document, {index: longer})
    results.check("grow/output differs from source", grown != document.raw)
    results.check("grow/output is larger", len(grown) > len(document.raw))
    try:
        report = assembler.verify(document, grown, {index: longer}, expect_identical=False)
        results.check("grow/passes full verification", True)
        results.check("grow/coverage still complete", report["byte_coverage"] == 1.0)
    except assembler.RepackError as exc:
        results.check("grow/passes full verification", False, str(exc))
    rebuilt = dis.parse(source, data=grown, command_table=table)
    results.check("grow/new text is present in the output",
                  any(target.source * 2 == e.source for e in dis.extract_text_entries(rebuilt)))

    # Shrink — same path, so it must be tested too, not assumed.
    shorter = dis.encode_display(target.source[:2], "cp932")
    shrunk = assembler.serialize(document, {index: shorter})
    results.check("shrink/output is smaller", len(shrunk) < len(document.raw))
    try:
        assembler.verify(document, shrunk, {index: shorter}, expect_identical=False)
        results.check("shrink/passes full verification", True)
    except assembler.RepackError as exc:
        results.check("shrink/passes full verification", False, str(exc))

    # Hash semantics point in opposite directions.
    results.check("hash/no edits gives an identical file",
                  sha(assembler.serialize(document, {})) == sha(document.raw))
    results.check("hash/an edit changes the file", sha(grown) != sha(document.raw))

    # A cell that carries no editable bytes must be refused as an edit target.
    # Branch targets are the interesting case, but a corpus may legitimately have
    # none (measured: 89 across 35 files in 77, zero in Nepgear2), so fall back to
    # any byte-less argument and say which kind was actually exercised.
    probe_document = None
    probe_argument = None
    kind = ""
    for candidate in script_sources(root, table):
        probe = dis.parse(candidate, command_table=table)
        found = next((a for a in probe.arguments if a.is_branch_target), None)
        if found is not None:
            probe_document, probe_argument, kind = probe, found, "branch target"
            break
        if probe_argument is None:
            spare = next((a for a in probe.arguments if not a.owns_bytes), None)
            if spare is not None:
                probe_document, probe_argument, kind = probe, spare, "byte-less cell"
    if probe_argument is None:
        results.check("refuse/found an uneditable cell to test with", False,
                      "no branch target and no byte-less cell in this corpus")
    else:
        try:
            assembler.serialize(probe_document, {probe_argument.index: b"x"})
            results.check(f"refuse/editing a {kind}", False, "it was accepted")
        except assembler.RepackError:
            results.check(f"refuse/editing a {kind}", True)

    # A word whose value equals an edited argument's stored offset, but which is
    # not itself a reference site, must survive untouched.  Search the corpus for
    # a real instance instead of hoping the first file has one.
    def collisions_for(doc: dis.Document, edited: int) -> int:
        offset = doc.arguments[edited].offset
        found = 0
        for argument in doc.arguments:
            if not argument.owns_bytes or argument.index == edited:
                continue
            blob = doc.blob(argument)
            for position in range(0, max(0, len(blob) - 3)):
                if int.from_bytes(blob[position:position + 4], "little") == offset:
                    found += 1
                    break
        return found

    collision_case = None
    for candidate in script_sources(root, table):
        probe = dis.parse(candidate, command_table=table)
        probe_entries = dis.extract_text_entries(probe)
        pick = next(
            (e for e in probe_entries
             if e.tag == "msg" and "{{" not in e.source and len(e.arg_indexes) == 1),
            None,
        )
        if pick is None:
            continue
        count = collisions_for(probe, pick.arg_indexes[0])
        if count:
            collision_case = (probe, pick.arg_indexes[0], count)
            break
    if collision_case is None:
        # "By site, not by value" can only be demonstrated where a value collision
        # exists.  A corpus without one does not disprove it, so this is reported
        # as not-applicable rather than as a failure (measured: 77 has collisions,
        # G.I.B. has none).
        print("  n/a  sites/no value collision in this corpus, check not applicable")
    else:
        probe, edited, count = collision_case
        entry = next(e for e in dis.extract_text_entries(probe) if e.arg_indexes[0] == edited)
        payload = dis.encode_display(entry.source * 2, "cp932")
        output = assembler.serialize(probe, {edited: payload})
        after = dis.parse(probe.path, data=output, command_table=table)
        preserved = all(
            probe.blob(a) == after.blob(after.arguments[a.index])
            for a in probe.arguments if a.owns_bytes and a.index != edited
        )
        results.check(f"sites/{count} value-collision word(s) preserved after a grow",
                      preserved)


def verify_text_rejections(root: pathlib.Path, results: Results) -> None:
    """Every documented rejection actually fires."""
    print("\n=== translation file validation ===")
    table = dis.CommandTable.find(root)
    picked = _first_editable(root, table)
    if picked is None:
        results.check("reject/found an editable file", False)
        return
    source, document, entries, _target = picked
    fresh = dis.render_texts(document, entries)
    path = "test.txt"

    def expect(name: str, mutated: str, code: str) -> None:
        try:
            edits = assembler.diff_texts(fresh, mutated, path)
            assembler.build_replacements(document, entries, edits, "cp932", source.name)
            results.check(f"reject/{name}", False, f"accepted, expected {code}")
        except assembler.ImportError_ as exc:
            results.check(f"reject/{name}", exc.code == code,
                          f"got {exc.code}, expected {code}")

    def mutate(predicate, transform) -> str:
        lines = fresh.splitlines()
        for position, line in enumerate(lines):
            if predicate(line):
                lines[position] = transform(line)
                break
        return "\n".join(lines)

    def parts(line: str, bullet: str) -> list[str]:
        return line.split(bullet, 3)

    is_target = lambda l: l.startswith(dis.BLACK_BULLET)
    is_source = lambda l: l.startswith(dis.WHITE_BULLET)

    results.check("accept/unmodified file",
                  assembler.diff_texts(fresh, fresh, path) == {})

    expect("edited source row",
           mutate(is_source, lambda l: (lambda a: f"○{a[1]}○{a[2]}○{a[3]}XX")(parts(l, "○"))),
           "SOURCE_ANCHOR")
    expect("empty translation",
           mutate(is_target, lambda l: (lambda a: f"●{a[1]}●{a[2]}●")(parts(l, "●"))),
           "EMPTY_TRANSLATION")
    expect("stale source hash", fresh.replace("src_sha256=", "src_sha256=0000", 1),
           "SRC_SHA256")
    expect("changed tag",
           mutate(is_target, lambda l: (lambda a: f"●{a[1]}●choice●{a[3]}")(parts(l, "●"))),
           "TAG_MISMATCH")
    expect("idx not eight digits",
           mutate(is_target,
                  lambda l: (lambda a: f"●{int(a[1]) + 1}●{a[2]}●{a[3]}")(parts(l, "●"))),
           "IDX_WIDTH")
    expect("unrepresentable character",
           mutate(is_target, lambda l: (lambda a: f"●{a[1]}●{a[2]}●≈Ω")(parts(l, "●"))),
           "ENCODING_UNREPRESENTABLE")

    lines = fresh.splitlines()
    deleted = [l for i, l in enumerate(lines) if not (is_target(l) and i == next(
        (j for j, x in enumerate(lines) if is_target(x)), -1))]
    expect("deleted row", "\n".join(deleted), "ROW_DELETED")

    blocks = [i for i, l in enumerate(lines) if l.startswith("#") and "idx=" in l]
    if len(blocks) >= 2:
        first, second = blocks[0], blocks[1]
        swapped = (lines[:first] + lines[second:second + 3] + lines[first + 3:second]
                   + lines[first:first + 3] + lines[second + 3:])
        expect("swapped blocks", "\n".join(swapped), "ROW_REORDERED")

    mixed = mutate(is_target,
                   lambda l: (lambda a: f"●{a[1]}○{a[2]}●{a[3]}")(parts(l, "●")))
    problem = assembler._mixed_bullets(mixed)
    results.check("reject/mixed bullets", problem is not None)

    # A dialogue line containing ○ as visible text must NOT be rejected.
    with_bullet_text = mutate(
        is_target, lambda l: (lambda a: f"●{a[1]}●{a[2]}●『○』とか『×』")(parts(l, "●"))
    )
    results.check("accept/dialogue containing ○ as text",
                  assembler._mixed_bullets(with_bullet_text) is None)


def verify_batch_isolation(root: pathlib.Path, results: Results) -> None:
    """Editing one file must leave every other file byte-identical.

    Restricted to a handful of files: the property being tested is that an
    edit cannot leak into a neighbouring file, so two or three files are
    enough.  Running the whole corpus here would repeat work already done.
    """
    print("\n=== batch isolation ===")
    table = dis.CommandTable.find(root)
    sources = script_sources(root, table)[:4]
    if len(sources) < 2:
        results.check("isolation/enough files to compare", False)
        return
    with tempfile.TemporaryDirectory() as raw_temp:
        temp = pathlib.Path(raw_temp)
        sample = temp / "src"
        sample.mkdir()
        for source in sources:
            (sample / source.name).write_bytes(source.read_bytes())
        command_table = pathlib.Path(table.source)
        (sample / command_table.name).write_bytes(command_table.read_bytes())

        dis.export(sample, temp, texts=True, asm=False)
        chosen = None
        for source in sources:
            document = dis.parse(sample / source.name, command_table=table)
            entries = dis.extract_text_entries(document)
            if any(e.tag == "msg" and "{{" not in e.source for e in entries):
                chosen = (source, document, entries)
                break
        if chosen is None:
            results.check("isolation/found an editable file", False)
            return
        source, document, entries = chosen
        target = next(e for e in entries if e.tag == "msg" and "{{" not in e.source)

        text_path = dis.mirror_path(sample / source.name, sample, temp / "texts", ".txt")
        lines = text_path.read_text(encoding="utf-8-sig").splitlines()
        for position, line in enumerate(lines):
            if line.startswith(dis.BLACK_BULLET):
                fields = line.split(dis.BLACK_BULLET, 3)
                if int(fields[1]) == target.idx:
                    lines[position] = (
                        f"{dis.BLACK_BULLET}{fields[1]}{dis.BLACK_BULLET}"
                        f"{fields[2]}{dis.BLACK_BULLET}{fields[3]}、テスト用に伸ばした訳文"
                    )
                    break
        text_path.write_text("\n".join(lines), encoding="utf-8-sig")

        out = temp / "rebuilt"
        summary = assembler.repack(sample, temp, out, target_encoding="cp932")
        results.check("isolation/no failures", not summary["failures"],
                      json.dumps(summary["failures"][:2], ensure_ascii=False))
        results.check("isolation/exactly one file changed",
                      summary["files_changed"] == 1, f"{summary['files_changed']} changed")
        results.check("isolation/size grew", summary["byte_delta"] > 0)

        identical = 0
        differing = []
        for other in sources:
            rebuilt = out / other.name
            original = sample / other.name
            if not rebuilt.exists():
                continue
            if sha(original.read_bytes()) == sha(rebuilt.read_bytes()):
                identical += 1
            else:
                differing.append(other.name)
        results.check(f"isolation/{identical} other files untouched",
                      differing == [source.name], f"changed: {differing}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("corpus", type=pathlib.Path)
    parser.add_argument("--second-corpus", type=pathlib.Path, default=None,
                        help="a corpus from a different source, for cross-sample checks")
    args = parser.parse_args(argv)

    results = Results()
    first = verify_corpus(args.corpus, "corpus A", results)
    verify_editing(args.corpus, results)
    verify_text_rejections(args.corpus, results)
    verify_batch_isolation(args.corpus, results)

    if args.second_corpus:
        second = verify_corpus(args.second_corpus, "corpus B", results)
        print("\n=== cross-corpus ===")
        # Shape distributions must differ, otherwise the second corpus is not an
        # independent test and shares the first one's blind spots.
        results.check("cross/shape distributions differ",
                      first.get("shapes") != second.get("shapes"),
                      "both corpora exercise the same branches only")
        both = set(first.get("shapes", {})) | set(second.get("shapes", {}))
        declared = {s["id"] for s in dis.DIALECT["entry_shapes"] if not s.get("optional")}
        results.check("cross/every declared shape is exercised somewhere",
                      declared <= both, f"never matched: {sorted(declared - both)}")
    else:
        print("\nNOTE: only one corpus was checked, so cross-sample validation "
              "was NOT performed. This is a known gap.")

    print(f"\npassed={results.passed} failed={len(results.failed)}")
    for name, detail in results.failed:
        print(f"  FAILED {name}: {detail}")
    return 1 if results.failed else 0


if __name__ == "__main__":
    sys.exit(main())
