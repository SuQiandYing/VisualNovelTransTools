"""Source binary + edits from the two editing surfaces -> rebuilt binary.

The IR is re-parsed from the source on every run and a *fresh* projection is
rendered in memory, then diffed against the user's file.  That means there is no
ASM parser to write, edits carry their own provenance, and a conflict between the
two surfaces is a set intersection rather than a priority rule.

Repack is full-layout: ``arg_data`` is rebuilt from scratch and every argument
offset is refilled by site.  Values are never matched by content.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import struct
import sys
from dataclasses import dataclass, field

import opcodelist as dialect_module
import disassembler as dis

DIALECT = dialect_module.DIALECT
_HEADER = struct.Struct("<8I")
_ARG_CELL = struct.Struct("<3I")


class RepackError(Exception):
    """Base class for every refusal raised while repacking."""


class ImportError_(RepackError):
    """A translation file was rejected. Carries a reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class ConflictError(RepackError):
    def __init__(self, conflicts: list[dict]) -> None:
        super().__init__(f"{len(conflicts)} entries edited differently on both surfaces")
        self.conflicts = conflicts


# --------------------------------------------------------------------------
# Serialization (layout solver)
# --------------------------------------------------------------------------
def _blocks_covering_all(blocks: list[tuple[int, int]], size: int) -> list[tuple[int, int]]:
    """Fill the gaps between referenced blocks so the whole section is covered."""
    out: list[tuple[int, int]] = []
    cursor = 0
    for start, end in blocks:
        if start > cursor:
            out.append((cursor, start))
        out.append((start, end))
        cursor = max(cursor, end)
    if cursor < size:
        out.append((cursor, size))
    return out



# --------------------------------------------------------------------------
def serialize(document: dis.Document, replacements: dict[int, bytes],
              encrypt: bool | None = None) -> bytes:
    """Rebuild the container, optionally replacing individual argument payloads.

    ``replacements`` maps an argument index to its new raw payload bytes.

    Layout: referenced ranges are merged into maximal disjoint blocks and emitted
    in their original order.  Sharing and nesting are preserved because every
    argument is remapped through the block that contains it, so one edit reaches
    all of its aliases exactly as the engine sees them.

    With an empty ``replacements`` this is a byte-exact rebuild of the source.
    Unreferenced padding between those ranges is kept, not dropped: some files
    leave it (measured: 95 gaps, 362 bytes, in one name table) and omitting it
    shrinks the file.
    """
    arg_data = document.arg_data
    blocks = _blocks_covering_all(dis.referenced_blocks(document), len(arg_data))

    # Replacements are keyed by argument; collapse to byte ranges so aliases of
    # the same range stay consistent.
    by_range: dict[tuple[int, int], bytes] = {}
    for index, payload in replacements.items():
        argument = document.arguments[index]
        if not argument.owns_bytes:
            raise RepackError(
                f"argument {index} carries no editable bytes (branch target or empty)"
            )
        key = (argument.offset, argument.length)
        previous = by_range.get(key)
        if previous is not None and previous != payload:
            raise RepackError(
                f"two different values target the same stored range "
                f"0x{argument.offset:08X}+{argument.length}"
            )
        by_range[key] = payload

    # Emit each block, substituting replaced sub-ranges, and record how offsets move.
    new_data = bytearray()
    block_map: list[tuple[int, int, int, list[tuple[int, int, int, int]]]] = []
    for start, end in blocks:
        base = len(new_data)
        subs = sorted(k for k in by_range if start <= k[0] and k[0] + k[1] <= end)
        moves: list[tuple[int, int, int, int]] = []
        cursor = start
        for offset, length in subs:
            if offset < cursor:
                raise RepackError(
                    f"overlapping replacements at 0x{offset:08X}: edits would collide"
                )
            new_data += arg_data[cursor:offset]
            payload = by_range[(offset, length)]
            moves.append((offset, length, len(new_data), len(payload)))
            new_data += payload
            cursor = offset + length
        new_data += arg_data[cursor:end]
        block_map.append((start, end, base, moves))

    def remap(offset: int, length: int) -> tuple[int, int]:
        for start, end, base, moves in block_map:
            if not (start <= offset and offset + length <= end):
                continue
            for old_offset, old_length, new_offset, new_length in moves:
                if offset == old_offset and length == old_length:
                    return new_offset, new_length
            shift = sum(
                new_length - old_length
                for old_offset, old_length, _new_offset, new_length in moves
                if old_offset < offset
            )
            return base + (offset - start) + shift, length
        raise RepackError(f"range 0x{offset:08X}+{length} belongs to no block")

    cells = bytearray()
    for argument in document.arguments:
        if argument.owns_bytes:
            offset, length = remap(argument.offset, argument.length)
        else:
            # Empty cells and branch targets keep their stored fields verbatim:
            # an empty argument's offset is a cursor position, and a branch
            # target's length is an instruction index.
            offset, length = argument.offset, argument.length
        cells += _ARG_CELL.pack(argument.meta, length, offset)

    header = document.header
    inst_start, inst_len = document.section_offsets["inst_index"]
    line_start, line_len = document.section_offsets["line_index"]
    out = bytearray()
    out += _HEADER.pack(
        header["magic"], header["version"], header["count"],
        inst_len, len(cells), len(new_data), line_len, header["reserved"],
    )
    out += document.plain[inst_start:inst_start + inst_len]
    out += cells
    out += new_data
    out += document.plain[line_start:line_start + line_len]

    should_encrypt = document.encrypted if encrypt is None else encrypt
    if should_encrypt:
        return dis.xor_sections(bytes(out), document.key)
    return bytes(out)


# --------------------------------------------------------------------------
# Dual-line text parsing
# --------------------------------------------------------------------------
@dataclass(slots=True)
class TextEdit:
    idx: int
    tag: str
    source_row: str
    target_row: str


def parse_texts(text: str, path: str = "<text>") -> tuple[dict[str, str], dict[int, TextEdit]]:
    """Parse a dual-line file into its header fields and per-idx rows.

    Structural validation only; cross-checks against the IR happen in ``apply``.
    """
    lines = text.splitlines()
    headers: dict[str, str] = {}
    for line in lines[:4]:
        if not line.startswith("#"):
            break
        for token in line[1:].split():
            if "=" in token:
                key, value = token.split("=", 1)
                headers[key] = value
    if "src_sha256" not in headers:
        raise ImportError_("HEADER_MISSING", f"{path}: no src_sha256 in the first four lines")

    edits: dict[int, TextEdit] = {}
    current: dict[str, str] | None = None
    source_row: tuple[int, str, str] | None = None
    for number, line in enumerate(lines, 1):
        if line.startswith("#"):
            current = {}
            for token in line[1:].split():
                if "=" in token:
                    key, value = token.split("=", 1)
                    current[key] = value
            source_row = None
            continue
        if not line:
            continue
        for bullet in (dis.WHITE_BULLET, dis.BLACK_BULLET):
            if not line.startswith(bullet):
                continue
            parts = line.split(bullet, 3)
            if len(parts) != 4:
                raise ImportError_("ROW_MALFORMED", f"{path}:{number}: expected three {bullet}")
            digits, tag, value = parts[1], parts[2], parts[3]
            if len(digits) != 8 or not digits.isdigit():
                raise ImportError_("IDX_WIDTH", f"{path}:{number}: idx must be 8 digits, got {digits!r}")
            idx = int(digits)
            if current is None or "idx" not in current:
                raise ImportError_("ROW_ORPHAN", f"{path}:{number}: row without a metadata line")
            if int(current["idx"]) != idx:
                raise ImportError_(
                    "IDX_MISMATCH",
                    f"{path}:{number}: row idx {idx} != metadata idx {int(current['idx'])}",
                )
            if current.get("tag") != tag:
                raise ImportError_(
                    "TAG_MISMATCH",
                    f"{path}:{number}: row tag {tag!r} != metadata tag {current.get('tag')!r}",
                )
            if bullet == dis.WHITE_BULLET:
                source_row = (idx, tag, value)
            else:
                if source_row is None:
                    raise ImportError_("SOURCE_ROW_MISSING", f"{path}:{number}: no source row above")
                if source_row[0] != idx:
                    raise ImportError_(
                        "IDX_MISMATCH",
                        f"{path}:{number}: source row idx {source_row[0]} != {idx}",
                    )
                if not value:
                    raise ImportError_(
                        "EMPTY_TRANSLATION",
                        f"{path}:{number}: idx={idx:08d} translation row is empty "
                        "(delete means data loss; copy the source row to keep it untranslated)",
                    )
                if idx in edits:
                    raise ImportError_("IDX_DUPLICATE", f"{path}:{number}: idx {idx} appears twice")
                edits[idx] = TextEdit(idx, tag, source_row[2], value)
            break
    return headers, edits


def _mixed_bullets(text: str) -> str | None:
    """Check that a row's three separators are all the same bullet.

    Only the first three separators are examined.  Dialogue legitimately
    contains ``○`` and ``×`` as visible characters (e.g. describing marks drawn
    on a field), so scanning the whole line for the other bullet would reject
    perfectly good text.
    """
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line[0] not in (dis.WHITE_BULLET, dis.BLACK_BULLET):
            continue
        bullet = line[0]
        other = dis.BLACK_BULLET if bullet == dis.WHITE_BULLET else dis.WHITE_BULLET
        # Separators are: position 0, then after the 8-digit idx, then after the tag.
        head = line.split(bullet, 3)
        if len(head) != 4:
            return f"line {number}: expected three {bullet} separators"
        if other in "".join(head[:3]):
            return f"line {number}: {dis.WHITE_BULLET} and {dis.BLACK_BULLET} are mixed"
    return None


# --------------------------------------------------------------------------
# Applying text edits
# --------------------------------------------------------------------------
_PART_JOIN = DIALECT["line_break_marker"]
_LINE_BREAK_BYTES = DIALECT["line_break_bytes"]


def encoded_length(text: str, encoding: str) -> int:
    """Byte length in the target encoding, escapes counted as their bytes."""
    return (len(dis.encode_display(text, encoding, _LINE_BREAK_BYTES))
            + DIALECT["terminator_length"])


def _split_parts(entry: dis.TextEntry, translated: str) -> list[str]:
    """Split a translation back into the entry's physical parts.

    A message stored across several arguments keeps its part count: the bytecode
    fixes it, so a mismatch is reported rather than silently reflowed — guessing
    where to break would move text between records.  A single-argument message
    keeps its breaks inline, so the marker is left in the text for
    ``encode_display`` to turn back into bytes.
    """
    if len(entry.offsets) == 1:
        return [translated]
    parts = translated.split(_PART_JOIN)
    if len(parts) != len(entry.offsets):
        raise ImportError_(
            "PART_COUNT_MISMATCH",
            f"idx={entry.idx:08d} needs {len(entry.offsets)} parts separated by "
            f"{_PART_JOIN!r} but the translation has {len(parts)}",
        )
    return parts


def _rejoin_speaker_pair(entry: dis.TextEntry, by_idx: dict[int, dis.TextEntry],
                         edits: dict[int, "TextEdit"], source_name: str) -> str:
    """Rebuild the stored string from a speaker row and its dialogue row.

    Either row may be edited, so both are read: whichever was not edited
    contributes its original text.  The brackets come back from the dialect, so a
    translator never has to type them.
    """
    other = by_idx.get(entry.pair_idx) if entry.pair_idx is not None else None
    if other is None or other.role == entry.role:
        raise ImportError_(
            "PAIR_BROKEN",
            f"{source_name}: idx={entry.idx:08d} is half of a speaker pair but its "
            f"partner is missing",
        )
    name_entry = entry if entry.role == "speaker" else other
    body_entry = other if entry.role == "speaker" else entry

    def current(item: dis.TextEntry) -> str:
        edit = edits.get(item.idx)
        return edit.target_row if edit is not None else item.source

    name = current(name_entry)
    if not name:
        raise ImportError_(
            "EMPTY_TRANSLATION",
            f"{source_name}: idx={name_entry.idx:08d} speaker name is empty",
        )
    return dis._speaker_wrap(name) + current(body_entry)


def _wrap_delimiters_for(entry: dis.TextEntry) -> dict | None:
    """Engine wrap pair for this entry's callee group, or None."""
    shape = next((s for s in DIALECT["entry_shapes"] if s["id"] == entry.shape_id), None)
    if shape is None:
        return None
    group_id = shape.get("match", {}).get("callee_group")
    if not group_id:
        return None
    group = next((g for g in DIALECT["callee_groups"] if g["id"] == group_id), None)
    return None if group is None else group.get("wrap_delimiters")


def _rebuild_payload(document: dis.Document, argument: dis.Argument, entry: dis.TextEntry,
                     text: str, encoding: str) -> bytes:
    """Re-encode one part into the exact stored representation of its argument."""
    if argument.meta_class == dis._RAW_TEXT_CLASS:
        # Only a single-argument message stores its line breaks inline; when the
        # message spans arguments the marker was already consumed as a separator.
        inline_break = _LINE_BREAK_BYTES if len(entry.offsets) == 1 else None
        return dis.encode_display(text, encoding, inline_break)
    # Literal argument: rebuild the token frame and restore the original quoting.
    token = dis.string_token(document.blob(argument))
    if token is None:
        raise ImportError_(
            "UNEDITABLE_ARGUMENT",
            f"idx={entry.idx:08d} stored form is not a single string token",
        )
    quote, _inner = dis.strip_literal_quotes(token.payload)
    body = quote + dis.encode_display(text, encoding) + quote
    spec = DIALECT["arg_token"]
    return spec["string_tag"] + len(body).to_bytes(spec["length_width"], "little") + body


def build_replacements(document: dis.Document, entries: list[dis.TextEntry],
                       edits: dict[int, TextEdit], encoding: str,
                       source_name: str) -> tuple[dict[int, bytes], dict]:
    """Validate edits against the IR and turn them into per-argument payloads.

    Runs the import checks in order and refuses the whole file on any failure.
    """
    by_idx = {entry.idx: entry for entry in entries}
    replacements: dict[int, bytes] = {}
    changed = 0
    unchanged = 0
    grew = 0
    delta = 0
    # A speaker/body pair shares one stored string, so both rows must be resolved
    # together — writing them independently would make the second overwrite the
    # first.  Handled once, keyed by the lower idx of the pair.
    handled_pairs: set[int] = set()

    for idx in sorted(edits):
        edit = edits[idx]
        entry = by_idx.get(idx)
        if entry is None:
            raise ImportError_(
                "IDX_UNKNOWN", f"{source_name}: idx={idx:08d} does not exist in this file"
            )
        if edit.tag != entry.tag:
            raise ImportError_(
                "TAG_MISMATCH",
                f"{source_name}: idx={idx:08d} tag {edit.tag!r} != {entry.tag!r}",
            )
        # The source row is the alignment anchor: it catches shifted rows, edited
        # originals, stale files and editor auto-substitutions in one check.
        if edit.source_row != entry.source:
            raise ImportError_(
                "SOURCE_ANCHOR",
                f"{source_name}: idx={idx:08d} source row does not match the script\n"
                f"  script: {entry.source!r}\n  file:   {edit.source_row!r}",
            )
        if edit.target_row == entry.source:
            unchanged += 1
            continue
        if entry.translate_policy == "frozen":
            raise ImportError_(
                "FROZEN_EDITED",
                f"{source_name}: idx={idx:08d} is not editable "
                f"({'undecodable bytes' if entry.undecodable else 'engine-internal value'})",
            )

        if entry.role in ("speaker", "body"):
            pair_key = min(idx, entry.pair_idx or idx)
            if pair_key in handled_pairs:
                changed += 1
                continue
            handled_pairs.add(pair_key)
            text = _rejoin_speaker_pair(entry, by_idx, edits, source_name)
        else:
            text = edit.target_row

        parts = _split_parts(entry, text)
        wrap_delimiters = _wrap_delimiters_for(entry)
        for position, part in enumerate(parts):
            argument = document.arguments[entry.arg_indexes[position]]
            stored = part
            if position < len(entry.wraps) and entry.wraps[position]:
                stored = dis._apply_wrap(part, wrap_delimiters)
            try:
                payload = _rebuild_payload(document, argument, entry, stored, encoding)
            except UnicodeEncodeError as exc:
                bad = part[exc.start:exc.end]
                raise ImportError_(
                    "ENCODING_UNREPRESENTABLE",
                    f"{source_name}: idx={idx:08d} cannot write {bad!r} in {encoding}; "
                    f"pick an encoding that covers it",
                ) from exc
            except ValueError as exc:
                raise ImportError_(
                    "PLACEHOLDER_BROKEN", f"{source_name}: idx={idx:08d} {exc}"
                ) from exc
            replacements[argument.index] = payload
            delta += len(payload) - argument.length
            if len(payload) > argument.length:
                grew += 1
        changed += 1

    return replacements, {
        "changed_entries": changed,
        "unchanged_entries": unchanged,
        "grown_parts": grew,
        "byte_delta": delta,
    }


# --------------------------------------------------------------------------
# Verification after repack
# --------------------------------------------------------------------------
def verify(document: dis.Document, output: bytes, replacements: dict[int, bytes],
           expect_identical: bool) -> dict:
    """Re-parse the output and check every property the edit kind requires.

    Hash semantics are directional: with no edits the output must be identical;
    with edits it must differ, otherwise the edits were silently dropped.
    """
    identical = output == document.raw
    if expect_identical and not identical:
        raise RepackError("zero-edit repack changed the file: parsing or layout is faulty")
    if not expect_identical and identical:
        raise RepackError("EDIT_LOST: edits were applied but the output is unchanged")

    rebuilt = dis.parse(document.path, data=output, command_table=document.command_table)
    certificate = dis.coverage_certificate(rebuilt)
    if certificate["gaps"] or certificate["overlaps"]:
        raise RepackError("rebuilt file does not re-parse with full byte coverage")

    # Site isomorphism: same number of sites, one-to-one by index, same class.
    if len(rebuilt.arguments) != len(document.arguments):
        raise RepackError(
            f"site count changed: {len(document.arguments)} -> {len(rebuilt.arguments)}"
        )
    for before, after in zip(document.arguments, rebuilt.arguments):
        if before.meta != after.meta:
            raise RepackError(f"site {before.index} changed class/ordinal")
        if before.owns_bytes != after.owns_bytes:
            raise RepackError(f"site {before.index} changed byte ownership")

    # Every edited payload must actually be present, and untouched arguments must
    # keep their exact bytes.
    for index, payload in replacements.items():
        if rebuilt.blob(rebuilt.arguments[index]) != payload:
            raise RepackError(f"site {index}: new value is not in the output")
    # Words anywhere in an unedited payload that happen to equal an edited
    # argument's old stored offset.  They are preserved because they are not in
    # the site set ("by site, not by value").  A non-zero count is normal; a zero
    # count on a large edit is a hint that the site set is too narrow.
    edited_offsets = {document.arguments[index].offset for index in replacements}
    preserved_collisions = 0
    for before, after in zip(document.arguments, rebuilt.arguments):
        if before.index in replacements or not before.owns_bytes:
            continue
        blob = document.blob(before)
        if blob != rebuilt.blob(after):
            raise RepackError(f"site {before.index}: unedited value changed")
        for position in range(0, max(0, len(blob) - 3)):
            if int.from_bytes(blob[position:position + 4], "little") in edited_offsets:
                preserved_collisions += 1
                break

    expected_delta = sum(
        len(payload) - document.arguments[index].length
        for index, payload in replacements.items()
    )
    actual_delta = len(output) - len(document.raw)
    if actual_delta != expected_delta:
        raise RepackError(
            f"unexplained size change: {actual_delta} bytes, expected {expected_delta}"
        )
    return {
        "identical": identical,
        "byte_coverage": certificate["byte_coverage"],
        "site_count": len(rebuilt.arguments),
        "preserved_value_collisions": preserved_collisions,
        "size_delta": actual_delta,
    }


# --------------------------------------------------------------------------
# Diffing the two editing surfaces
# --------------------------------------------------------------------------
def diff_texts(fresh: str, user: str, path: str) -> dict[int, TextEdit]:
    """Return only the rows the user actually changed, after validating the file."""
    problem = _mixed_bullets(user)
    if problem:
        raise ImportError_("BULLET_MIXED", f"{path}: {problem}")
    fresh_headers, fresh_edits = parse_texts(fresh, path)
    user_headers, user_edits = parse_texts(user, path)
    if user_headers.get("src_sha256") != fresh_headers.get("src_sha256"):
        raise ImportError_(
            "SRC_SHA256",
            f"{path}: this file was exported from a different version of the script; "
            "re-export the text before importing",
        )
    part = user_headers.get("part", "1/1")
    if part != "1/1":
        index, _, total = part.partition("/")
        raise ImportError_(
            "SHARD_INCOMPLETE",
            f"{path}: this is shard {index} of {total}; import needs the whole set",
        )
    changed: dict[int, TextEdit] = {}
    for idx, edit in user_edits.items():
        baseline = fresh_edits.get(idx)
        if baseline is None:
            raise ImportError_("IDX_UNKNOWN", f"{path}: idx={idx:08d} is not in this script")
        # The source row is the alignment anchor and is checked for EVERY row,
        # not only edited ones.  Checking it lazily would let a shifted or
        # hand-edited original slip through whenever its translation happens to
        # be untouched — which is the common case in a partly translated file.
        if edit.source_row != baseline.source_row:
            raise ImportError_(
                "SOURCE_ANCHOR",
                f"{path}: idx={idx:08d} source row does not match the script\n"
                f"  script: {baseline.source_row!r}\n  file:   {edit.source_row!r}",
            )
        if edit.tag != baseline.tag:
            raise ImportError_(
                "TAG_MISMATCH",
                f"{path}: idx={idx:08d} tag {edit.tag!r} != {baseline.tag!r}",
            )
        if edit.target_row != baseline.target_row:
            changed[idx] = edit
    missing = set(fresh_edits) - set(user_edits)
    if missing:
        raise ImportError_(
            "ROW_DELETED",
            f"{path}: {len(missing)} entries were removed, first idx={min(missing):08d}",
        )
    # Entry order must match too: rows are keyed by idx, so two reordered blocks
    # would otherwise import as if nothing had moved.
    user_order = list(user_edits)
    fresh_order = list(fresh_edits)
    if user_order != fresh_order:
        for position, (got, want) in enumerate(zip(user_order, fresh_order)):
            if got != want:
                raise ImportError_(
                    "ROW_REORDERED",
                    f"{path}: entry {position + 1} is idx={got:08d} but should be "
                    f"idx={want:08d}; blocks were moved",
                )
    return changed


def diff_asm(fresh: str, user: str, path: str) -> dict[int, str]:
    """Return edited asm string rows keyed by their argument id (``sid=``).

    Only ``.arg`` string payloads are accepted.  Any other changed line means a
    structural edit, which needs a deeper understanding of the format than has
    been proven, so it is refused instead of attempted.
    """
    fresh_lines = fresh.splitlines()
    user_lines = user.splitlines()
    if len(fresh_lines) != len(user_lines):
        raise ImportError_(
            "ASM_STRUCTURE_CHANGED",
            f"{path}: lines were added or removed; only string values can be edited",
        )
    edits: dict[int, str] = {}
    current_sid: int | None = None
    for number, (before, after) in enumerate(zip(fresh_lines, user_lines), 1):
        stripped = before.strip()
        if stripped.startswith(".arg "):
            current_sid = None
            for token in stripped.split():
                if token.startswith("sid="):
                    current_sid = int(token[4:])
        if before == after:
            continue
        if not stripped.startswith(".string") or current_sid is None:
            raise ImportError_(
                "ASM_STRUCTURE_CHANGED",
                f"{path}:{number}: only .string values can be edited here, "
                f"changing instructions or data needs full structural support",
            )
        edits[current_sid] = after.strip()[len(".string"):].strip()
    return edits


# --------------------------------------------------------------------------
# Repack driver
# --------------------------------------------------------------------------
@dataclass(slots=True)
class RepackResult:
    name: str
    ok: bool
    changed_entries: int = 0
    unchanged_entries: int = 0
    grown_parts: int = 0
    size_delta: int = 0
    identical: bool = False
    preserved_value_collisions: int = 0
    written: str = ""
    skipped: str = ""
    error: str = ""


def _asm_string_edits_to_replacements(document: dis.Document, asm_edits: dict[int, str],
                                      encoding: str) -> dict[int, bytes]:
    replacements: dict[int, bytes] = {}
    for sid, value in asm_edits.items():
        if sid < 0 or sid >= len(document.arguments):
            raise ImportError_("ASM_SID_UNKNOWN", f"sid={sid} is not an argument of this file")
        argument = document.arguments[sid]
        if argument.meta_class == dis._RAW_TEXT_CLASS:
            replacements[sid] = dis.encode_display(value, encoding)
            continue
        token = dis.string_token(document.blob(argument))
        if token is None:
            raise ImportError_("UNEDITABLE_ARGUMENT", f"sid={sid} is not a single string token")
        quote, _inner = dis.strip_literal_quotes(token.payload)
        stripped = value
        if quote and stripped.startswith(quote.decode("ascii")) and stripped.endswith(quote.decode("ascii")):
            stripped = stripped[1:-1]
        body = quote + dis.encode_display(stripped, encoding) + quote
        spec = DIALECT["arg_token"]
        replacements[sid] = spec["string_tag"] + len(body).to_bytes(spec["length_width"], "little") + body
    return replacements


def repack_one(source: pathlib.Path, root: pathlib.Path, text_dir: pathlib.Path,
               out_dir: pathlib.Path, *, target_encoding: str | None = None,
               source_encoding: str | None = None, dry_run: bool = False,
               command_table: dis.CommandTable | None = None) -> RepackResult:
    """Repack one source file from whichever editing surfaces exist for it."""
    try:
        document = dis.parse(source, command_table=command_table)
    except dis.NotAScriptError as exc:
        return RepackResult(source.name, ok=True, skipped=str(exc))
    except dis.DisassemblyError as exc:
        return RepackResult(source.name, ok=False, error=str(exc))

    encoding = target_encoding or DIALECT["encodings"]["target"]
    entries = dis.extract_text_entries(document, source_encoding)

    text_path = dis.mirror_path(source, root, text_dir / "texts", ".txt")
    asm_path = dis.mirror_path(source, root, text_dir / "asm", ".asm.txt")

    text_edits: dict[int, TextEdit] = {}
    asm_edits: dict[int, str] = {}
    try:
        if text_path.is_file():
            fresh = dis.render_texts(document, entries, encoding, source_encoding)
            user = text_path.read_text(encoding=DIALECT["encodings"]["text_file"])
            text_edits = diff_texts(fresh, user, str(text_path))
        if asm_path.is_file():
            fresh_asm = dis.render_asm(document, source_encoding)
            user_asm = asm_path.read_text(encoding=DIALECT["encodings"]["asm"])
            # Skip the diff when the file is untouched: saves a render on the
            # common "translation only" path.
            if user_asm != fresh_asm:
                asm_edits = diff_asm(fresh_asm, user_asm, str(asm_path))
        replacements, stats = build_replacements(
            document, entries, text_edits, encoding, source.name
        )
        if asm_edits:
            asm_replacements = _asm_string_edits_to_replacements(document, asm_edits, encoding)
            conflicts = [
                {
                    "sid": sid,
                    "asm": asm_replacements[sid].decode(encoding, "replace"),
                    "texts": replacements[sid].decode(encoding, "replace"),
                }
                for sid in set(asm_replacements) & set(replacements)
                if asm_replacements[sid] != replacements[sid]
            ]
            if conflicts:
                raise ConflictError(conflicts)
            replacements.update(asm_replacements)

        output = serialize(document, replacements)
        report = verify(document, output, replacements, expect_identical=not replacements)
    except RepackError as exc:
        return RepackResult(source.name, ok=False, error=str(exc))

    written = ""
    if not dry_run:
        destination = dis.mirror_path(source, root, out_dir, "")
        destination = destination.with_name(source.name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Transaction: write to tmp, then atomically rename into place.
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(output)
        os.replace(temporary, destination)
        written = str(destination)

    return RepackResult(
        name=source.name,
        ok=True,
        changed_entries=stats["changed_entries"],
        unchanged_entries=stats["unchanged_entries"],
        grown_parts=stats["grown_parts"],
        size_delta=report["size_delta"],
        identical=report["identical"],
        preserved_value_collisions=report["preserved_value_collisions"],
        written=written,
    )


def repack(root: pathlib.Path, text_dir: pathlib.Path, out_dir: pathlib.Path, *,
           target_encoding: str | None = None, source_encoding: str | None = None,
           dry_run: bool = False, progress=None) -> dict:
    sources = dis.iter_sources(root)
    if not sources:
        raise RepackError(f"no {dis.SCRIPT_SUFFIX} files found under {root}")
    if not (text_dir / "texts").is_dir() and not (text_dir / "asm").is_dir():
        raise RepackError(f"no texts/ or asm/ directory under {text_dir}; export text first")
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    table = dis.CommandTable.find(root)
    results: list[RepackResult] = []
    for index, source in enumerate(sources, 1):
        results.append(repack_one(
            source, root, text_dir, out_dir,
            target_encoding=target_encoding, source_encoding=source_encoding,
            dry_run=dry_run, command_table=table,
        ))
        if progress:
            progress(index, len(sources), source.name)

    summary = {
        "tool_version": dis.TOOL_VERSION,
        "input": str(root),
        "texts": str(text_dir),
        "output": str(out_dir),
        "dry_run": dry_run,
        "file_count": len(sources),
        "repacked": sum(1 for r in results if r.ok and not r.skipped),
        "changed_entries": sum(r.changed_entries for r in results),
        "unchanged_entries": sum(r.unchanged_entries for r in results),
        "grown_parts": sum(r.grown_parts for r in results),
        "byte_delta": sum(r.size_delta for r in results),
        "files_changed": sum(1 for r in results if r.ok and not r.skipped and not r.identical),
        "preserved_value_collisions": sum(r.preserved_value_collisions for r in results),
        "skipped": [{"file": r.name, "reason": r.skipped} for r in results if r.skipped],
        "failures": [{"file": r.name, "error": r.error} for r in results if not r.ok],
        "strategy": "full-layout",
    }
    if not dry_run:
        reports = out_dir / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "repack_report.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild Yu-Ris YSTB scripts from edited dual-line text and/or asm."
    )
    parser.add_argument("input", type=pathlib.Path, help="original script file or directory")
    parser.add_argument("--texts", type=pathlib.Path, default=None,
                        help="directory holding texts/ and asm/ (default: output/ beside the input)")
    parser.add_argument("-o", "--out-dir", type=pathlib.Path, default=None,
                        help="where rebuilt files go (default: <texts>/rebuilt)")
    parser.add_argument("--target-encoding", default=None,
                        help=f"encoding to write translations in "
                             f"(default {DIALECT['encodings']['target']})")
    parser.add_argument("--source-encoding", default=None,
                        help=f"encoding the script's text is stored in "
                             f"(default {DIALECT['encodings']['source']})")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate and report without writing any file")
    args = parser.parse_args(argv)

    sources = dis.iter_sources(args.input)
    text_dir = args.texts or dis.default_output_dir(sources)
    out_dir = args.out_dir or (text_dir / "rebuilt")
    try:
        summary = repack(args.input, text_dir, out_dir,
                         target_encoding=args.target_encoding,
                         source_encoding=args.source_encoding, dry_run=args.dry_run)
    except RepackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"files={summary['repacked']}/{summary['file_count']}")
    print(f"changed_entries={summary['changed_entries']}")
    print(f"unchanged_entries={summary['unchanged_entries']}")
    print(f"files_changed={summary['files_changed']}")
    print(f"byte_delta={summary['byte_delta']:+d}")
    print(f"strategy={summary['strategy']}")
    if summary["failures"]:
        for failure in summary["failures"]:
            print(f"FAILED {failure['file']}: {failure['error']}", file=sys.stderr)
        return 1
    if not args.dry_run:
        print(f"output={summary['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
