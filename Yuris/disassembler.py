"""Source binary -> in-memory IR -> asm.txt / dual-line text + coverage certificate.

Structural logic only: every engine-specific value comes from ``opcodelist.py``.
The IR is rebuilt from the source bytes on every run (parsing is deterministic),
so nothing here depends on a previously written artifact.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import pathlib
import struct
import sys
from dataclasses import dataclass, field

import opcodelist as dialect_module

DIALECT = dialect_module.DIALECT
TOOL_VERSION = "2.0.0"
IR_VERSION = "2"

WHITE_BULLET = "○"
BLACK_BULLET = "●"


class DisassemblyError(Exception):
    """Base class for every refusal raised while parsing."""


class NotAScriptError(DisassemblyError):
    pass


class CellAlignmentError(DisassemblyError):
    pass


class AddressSpaceGapError(DisassemblyError):
    pass


class UnknownEntryShape(DisassemblyError):
    pass


# --------------------------------------------------------------------------
# Pre-computed struct objects (§12.1)
# --------------------------------------------------------------------------
_HEADER = struct.Struct("<8I")
_ARG_CELL = struct.Struct("<3I")
_U32 = struct.Struct("<I")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Cipher
# --------------------------------------------------------------------------
def _section_bounds(header: dict) -> list[tuple[str, int, int]]:
    """Return (name, start, length) for each section, in file order."""
    pos = DIALECT["container"]["header_size"]
    out = []
    for name, length_field, _cell, _note in DIALECT["container"]["sections"]:
        length = header[length_field]
        out.append((name, pos, length))
        pos += length
    return out


def xor_sections(data: bytes, key: int) -> bytes:
    """Apply the repeating-u32 XOR to the payload sections only.

    Uses one big-int XOR per section instead of a per-byte loop: 415 MB/s vs
    11 MB/s, with byte-identical output.
    """
    cipher = DIALECT["cipher"]
    width = cipher["key_width"]
    header = parse_header(data)
    out = bytearray(data)
    key_bytes = (key & 0xFFFFFFFF).to_bytes(width, "little")
    for name, start, length in _section_bounds(header):
        if name not in cipher["covers_sections"] or length <= 0:
            continue
        if start + length > len(out):
            raise DisassemblyError(
                f"section {name} exceeds file: start=0x{start:X} len=0x{length:X} file=0x{len(out):X}"
            )
        mask = (key_bytes * (length // width + 2))[:length]
        chunk = int.from_bytes(out[start:start + length], "little")
        out[start:start + length] = (chunk ^ int.from_bytes(mask, "little")).to_bytes(length, "little")
    return bytes(out)


def guess_key(data: bytes) -> int:
    """Recover the XOR key from the first argument's arg_data offset.

    That field is 0 in plaintext, so the stored bytes are the key itself.
    """
    probe = DIALECT["cipher"]["key_probe"]
    header = parse_header(data)
    cell = DIALECT["argument_cell"]
    field_off = next(f["offset"] for f in cell["fields"] if f["name"] == probe["field"])
    for name, start, length in _section_bounds(header):
        if name != probe["section"]:
            continue
        if length < cell["size"]:
            return 0
        at = start + probe["arg_ordinal"] * cell["size"] + field_off
        return _U32.unpack_from(data, at)[0]
    return 0


def sections_fit(data: bytes) -> bool:
    """True when the four section lengths add up to the file size.

    Holds for encrypted files too, because the header is never encrypted.
    """
    try:
        header = parse_header(data)
    except DisassemblyError:
        return False
    total = DIALECT["container"]["header_size"] + sum(
        header[f] for _n, f, _c, _d in DIALECT["container"]["sections"]
    )
    return total == len(data)


def _why_not_a_script(data: bytes) -> str:
    """Explain why sections_fit() said no, in terms a user can act on."""
    container = DIALECT["container"]
    try:
        header = parse_header(data)
    except DisassemblyError as exc:
        # parse_header already names the version or the field it rejected.
        return str(exc)
    total = container["header_size"] + sum(
        header[f] for _n, f, _c, _d in container["sections"]
    )
    return (
        f"section lengths add up to {total} but the file is {len(data)} bytes"
        if total != len(data) else
        "header parsed but the section table is inconsistent"
    )


def is_plaintext(data: bytes) -> bool:
    """True when the payload sections are already decrypted.

    Tested via the argc-sum invariant: the per-instruction argument counts add up
    to the argument count only when the instruction index is plaintext.  The
    section-length sum cannot be used here because the header is not encrypted.
    """
    if not sections_fit(data):
        return False
    header = parse_header(data)
    count = header["count"]
    bounds = {name: (start, length) for name, start, length in _section_bounds(header)}
    inst_start, inst_len = bounds["inst_index"]
    _arg_start, arg_len = bounds["arg_index"]
    arg_size = DIALECT["argument_cell"]["size"]
    cell = DIALECT["instruction_cell"]
    if inst_len != count * cell["size"] or arg_len % arg_size:
        return False
    argc_off = next(f["offset"] for f in cell["fields"] if f["name"] == "argc")
    total = 0
    for i in range(count):
        total += data[inst_start + i * cell["size"] + argc_off]
    return total == arg_len // arg_size


def parse_header(data: bytes) -> dict:
    container = DIALECT["container"]
    size = container["header_size"]
    if len(data) < size:
        raise NotAScriptError(f"file too small for header: {len(data)} < {size}")
    values = _HEADER.unpack_from(data, 0)
    header = dict(zip(container["header_fields"], values))
    expected = int.from_bytes(container["magic_bytes"], "little")
    if header["magic"] != expected:
        found = bytes(data[:4])
        label = DIALECT["non_script_magics"].get(found)
        if label:
            raise NotAScriptError(f"not a script: {found.decode('ascii', 'replace')} ({label})")
        raise NotAScriptError(f"unexpected magic {found!r}")
    if header["version"] not in container["supported_versions"]:
        raise NotAScriptError(f"unsupported version {header['version']}")
    return header


# --------------------------------------------------------------------------
# Command table
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Command:
    opcode: int
    name: str
    parameters: tuple[str, ...]


class CommandTable:
    """Opcode -> command name, loaded from the engine's own YSCM table."""

    def __init__(self, commands: tuple[Command, ...], source: str) -> None:
        self.commands = commands
        self.source = source
        self._by_name = {command.name: command for command in commands}

    @classmethod
    def from_bytes(cls, data: bytes, source: str) -> "CommandTable":
        spec = DIALECT["command_table"]
        if data[:4] != spec["magic_bytes"]:
            raise NotAScriptError(f"not a command table: {data[:4]!r}")
        count = _U32.unpack_from(data, spec["count_field_offset"])[0]
        encoding = spec["encoding"]
        trailer = spec["entry"]["argument"]["trailer_width"]
        pos = spec["header_size"]
        commands: list[Command] = []
        for opcode in range(count):
            end = data.find(b"\x00", pos)
            if end < 0:
                raise NotAScriptError(f"command table truncated at 0x{pos:X}")
            name = data[pos:end].decode(encoding, "replace")
            pos = end + 1
            if pos >= len(data):
                raise NotAScriptError("command table truncated before arg count")
            argc = data[pos]
            pos += 1
            params: list[str] = []
            for _ in range(argc):
                end = data.find(b"\x00", pos)
                if end < 0:
                    raise NotAScriptError(f"command table truncated at 0x{pos:X}")
                params.append(data[pos:end].decode(encoding, "replace"))
                pos = end + 1 + trailer
            commands.append(Command(opcode, name, tuple(params)))
        return cls(tuple(commands), source)

    @classmethod
    def find(cls, root: pathlib.Path) -> "CommandTable | None":
        spec = DIALECT["command_table"]
        base = root if root.is_dir() else root.parent
        for candidate in (base / spec["file_name"], base.parent / spec["file_name"]):
            if candidate.is_file():
                try:
                    return cls.from_bytes(candidate.read_bytes(), str(candidate))
                except DisassemblyError:
                    continue
        return None

    def name_for(self, opcode: int) -> str:
        if 0 <= opcode < len(self.commands):
            return self.commands[opcode].name
        return f"OP_{opcode:02X}"

    def opcode_for(self, name: str) -> int | None:
        command = self._by_name.get(name)
        return command.opcode if command else None

    def resolve_roles(self) -> dict[str, int | None]:
        """Map the dialect's role names to concrete opcodes."""
        return {role: self.opcode_for(name) for role, name in DIALECT["commands"].items()}


# --------------------------------------------------------------------------
# In-memory IR
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Argument:
    index: int
    meta: int
    length: int
    offset: int
    # True when this cell carries a branch target in its length field instead of
    # addressing arg_data bytes (see the branch_target anchor).
    is_branch_target: bool = False

    @property
    def meta_class(self) -> int:
        return self.meta >> DIALECT["argument_cell"]["meta_class_shift"]

    @property
    def slot(self) -> int:
        return self.meta & DIALECT["argument_cell"]["meta_ordinal_mask"]

    @property
    def owns_bytes(self) -> bool:
        return self.length > 0 and not self.is_branch_target


@dataclass(frozen=True, slots=True)
class Instruction:
    index: int
    opcode: int
    name: str
    reserved: int
    arg_start: int
    arg_end: int
    line: int


@dataclass(slots=True)
class TextEntry:
    idx: int
    tag: str
    tag_source: str
    translate_policy: str
    shape_id: str
    instruction_index: int
    arg_indexes: tuple[int, ...]
    offsets: tuple[int, ...]
    lengths: tuple[int, ...]
    source: str
    encodings: tuple[str, ...]
    speaker: str | None = None
    undecodable: bool = False
    # A message with a bracketed speaker name is exported as two rows that share
    # one stored string: role "speaker" holds the name, role "body" the dialogue.
    # ``pair_idx`` links them so repack can rejoin the pair.  Empty role means an
    # ordinary single-row entry.
    role: str = ""
    pair_idx: int | None = None
    # Per stored slot: True means that slot was wrapped in engine delimiters
    # (【name】) which were stripped for editing and must be put back on repack.
    # Empty means no slot of this entry was wrapped.
    wraps: tuple[bool, ...] = ()


@dataclass(slots=True)
class Document:
    path: pathlib.Path
    name: str
    raw: bytes
    plain: bytes
    encrypted: bool
    key: int
    header: dict
    instructions: tuple[Instruction, ...]
    arguments: tuple[Argument, ...]
    arg_data: bytes
    lines: tuple[int, ...]
    section_offsets: dict[str, tuple[int, int]]
    command_table: CommandTable
    roles: dict[str, int | None]
    shape_counts: collections.Counter = field(default_factory=collections.Counter)

    @property
    def source_sha256(self) -> str:
        return sha256_bytes(self.raw)

    def blob(self, argument: Argument) -> bytes:
        return self.arg_data[argument.offset:argument.offset + argument.length]

    def args_of(self, instruction: Instruction) -> tuple[Argument, ...]:
        return self.arguments[instruction.arg_start:instruction.arg_end]


def parse(path: pathlib.Path, data: bytes | None = None,
          command_table: CommandTable | None = None,
          key: int | None = None) -> Document:
    """Parse one source file into the in-memory IR.

    Deterministic: the same bytes always yield the same IR.
    """
    raw = data if data is not None else path.read_bytes()
    if len(raw) < 4:
        raise NotAScriptError(f"file too small: {len(raw)} bytes")
    found_magic = bytes(raw[:4])
    if found_magic in DIALECT["non_script_magics"]:
        raise NotAScriptError(
            f"not a script: {found_magic.decode('ascii', 'replace')} "
            f"({DIALECT['non_script_magics'][found_magic]})"
        )

    if not sections_fit(raw):
        # Report the real reason.  sections_fit() folds several distinct failures
        # into one boolean, and "lengths do not add up" is actively misleading for
        # a file whose lengths are fine but whose version is not supported.
        raise NotAScriptError(_why_not_a_script(raw))

    encrypted = not is_plaintext(raw)
    used_key = 0
    if encrypted:
        used_key = guess_key(raw) if key is None else key
        plain = xor_sections(raw, used_key)
        if not is_plaintext(plain):
            raise NotAScriptError(
                f"cannot decrypt with key 0x{used_key:08X}: instruction stream stays unreadable"
            )
    else:
        plain = raw

    header = parse_header(plain)
    count = header["count"]
    bounds = {name: (start, length) for name, start, length in _section_bounds(header)}

    for name in DIALECT["container"]["count_scaled_sections"]:
        _start, length = bounds[name]
        if length != count * 4:
            raise CellAlignmentError(
                f"{name} length {length} != count*4 ({count * 4})"
            )

    inst_start, inst_len = bounds["inst_index"]
    arg_start, arg_len = bounds["arg_index"]
    data_start, data_len = bounds["arg_data"]
    line_start, line_len = bounds["line_index"]

    arg_size = DIALECT["argument_cell"]["size"]
    if arg_len % arg_size:
        raise CellAlignmentError(f"arg_index length {arg_len} not a multiple of {arg_size}")

    # Arguments
    arguments = [
        Argument(i, *_ARG_CELL.unpack_from(plain, arg_start + i * arg_size))
        for i in range(arg_len // arg_size)
    ]

    # Instructions.  sum(argc) must equal the argument count: that is the proof
    # that instruction boundaries tile the stream with no gap or overlap.
    cell = DIALECT["instruction_cell"]
    fields = {f["name"]: f for f in cell["fields"]}
    op_off = fields["opcode"]["offset"]
    argc_off = fields["argc"]["offset"]
    res_off = fields["reserved"]["offset"]
    res_width = fields["reserved"]["width"]

    table = command_table or CommandTable.find(path)
    if table is None:
        raise DisassemblyError(
            f"command table {DIALECT['command_table']['file_name']} not found next to {path}"
        )
    lines = struct.unpack_from(f"<{count}I", plain, line_start) if count else ()

    instructions: list[Instruction] = []
    cursor = 0
    for i in range(count):
        base = inst_start + i * cell["size"]
        opcode = plain[base + op_off]
        argc = plain[base + argc_off]
        reserved = int.from_bytes(plain[base + res_off:base + res_off + res_width], "little")
        instructions.append(
            Instruction(i, opcode, table.name_for(opcode), reserved,
                        cursor, cursor + argc, lines[i])
        )
        cursor += argc
    if cursor != len(arguments):
        raise AddressSpaceGapError(
            f"argc sum {cursor} != argument count {len(arguments)}"
        )

    # Flag branch-target cells: their length field is an instruction index, not a
    # byte count, so they must not claim arg_data bytes.  Only accepted when the
    # target actually resolves to a declared block closer.
    branch_anchor = next(
        (a for a in DIALECT["anchors"] if a["id"] == "branch_target"), None
    )
    if branch_anchor is not None:
        roles = table.resolve_roles()
        branch_ops = {roles[name] for name in branch_anchor["commands"] if roles.get(name) is not None}
        closer_ops = {roles[name] for name in branch_anchor["closer_commands"] if roles.get(name) is not None}
        if branch_anchor["target_in_field"] == "length":
            for instruction in instructions:
                if instruction.opcode not in branch_ops:
                    continue
                target_class = _META_CLASS_IDS[branch_anchor["target_meta_class"]]
                for position in range(instruction.arg_start, instruction.arg_end):
                    argument = arguments[position]
                    target = argument.length
                    if argument.length <= 0 or target >= len(instructions):
                        continue
                    if instructions[target].opcode not in closer_ops:
                        continue
                    # The length field is an instruction index, so it must sit in
                    # the slot class that carries one.  Do NOT additionally require
                    # the range to fall outside arg_data: that only holds in small
                    # files, so in a large script every target looked like data and
                    # the tool offered jump addresses as editable payload
                    # (measured: 89 of 1,453 real targets found before this fix,
                    # zero of them in G.I.B. and Nepgear2).
                    if argument.meta_class != target_class:
                        continue
                    arguments[position] = Argument(
                        argument.index, argument.meta, argument.length,
                        argument.offset, is_branch_target=True,
                    )

    for argument in arguments:
        if argument.owns_bytes and argument.offset + argument.length > data_len:
            raise AddressSpaceGapError(
                f"argument {argument.index} range 0x{argument.offset:X}+{argument.length} "
                f"exceeds arg_data ({data_len} bytes)"
            )

    return Document(
        path=path,
        name=path.name,
        raw=raw,
        plain=plain,
        encrypted=encrypted,
        key=used_key,
        header=header,
        instructions=tuple(instructions),
        arguments=tuple(arguments),
        arg_data=plain[data_start:data_start + data_len],
        lines=tuple(lines),
        section_offsets={
            "inst_index": (inst_start, inst_len),
            "arg_index": (arg_start, arg_len),
            "arg_data": (data_start, data_len),
            "line_index": (line_start, line_len),
        },
        command_table=table,
        roles=table.resolve_roles(),
    )


# --------------------------------------------------------------------------
# Argument token stream
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Token:
    tag: bytes
    payload: bytes
    start: int


def split_tokens(blob: bytes) -> tuple[Token, ...] | None:
    """Split a non-raw argument payload into (tag, length, payload) tokens.

    Returns None when the blob does not frame cleanly, so callers can keep it as
    an opaque block instead of guessing.
    """
    spec = DIALECT["arg_token"]
    head = spec["tag_width"] + spec["length_width"]
    tokens: list[Token] = []
    pos = 0
    while pos < len(blob):
        if pos + head > len(blob):
            return None
        length = int.from_bytes(blob[pos + spec["tag_width"]:pos + head], "little")
        end = pos + head + length
        if end > len(blob):
            return None
        tokens.append(Token(blob[pos:pos + spec["tag_width"]], blob[pos + head:end], pos))
        pos = end
    return tuple(tokens)


def strip_literal_quotes(payload: bytes) -> tuple[bytes, bytes]:
    """Split a script string literal into (quote, inner). Quote may be empty."""
    if len(payload) >= 2:
        first = payload[:1]
        if first in DIALECT["string_literal_quotes"] and payload[-1:] == first:
            return first, payload[1:-1]
    return b"", payload


def string_token(blob: bytes) -> Token | None:
    """Return the single string token of a literal argument, if that is all it is."""
    tokens = split_tokens(blob)
    if tokens is None or len(tokens) != 1:
        return None
    return tokens[0] if tokens[0].tag == DIALECT["arg_token"]["string_tag"] else None


# --------------------------------------------------------------------------
# Text decoding
# --------------------------------------------------------------------------
def decode_text(payload: bytes, encodings: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Decode strictly with the first candidate codec that accepts the whole string.

    No ``errors=`` fallback anywhere: bytes no codec accepts are reported as
    undecodable and kept as raw bytes.
    """
    for encoding in encodings:
        try:
            return payload.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return None, None


def decode_with_placeholders(payload: bytes, encoding: str) -> tuple[str, int]:
    """Decode as far as the codec allows, escaping what the codec rejects.

    Returns (display text, number of escaped bytes).  Byte pairs the dialect
    identifies as line breaks become the ordinary line-break marker; anything
    else the codec rejects becomes a byte placeholder.  Either way the bytes
    round-trip exactly, so nothing is guessed.
    """
    out: list[str] = []
    escaped = 0
    position = 0
    size = len(payload)
    while position < size:
        # A declared line break wins over codec decoding: the pair may happen to
        # be decodable in some codec, but its meaning is fixed by the dialect.
        pair = payload[position:position + 2]
        if pair in _LINE_BREAK_PAIRS:
            out.append(_PART_JOIN)
            escaped += 2
            position += 2
            continue
        for width in (2, 1):
            chunk = payload[position:position + width]
            if len(chunk) < width:
                continue
            try:
                character = chunk.decode(encoding)
            except UnicodeDecodeError:
                continue
            # Control characters have no safe visual form.
            out.append(as_placeholders(chunk) if ord(character[0]) < 0x20 else character)
            if ord(character[0]) < 0x20:
                escaped += width
            position += width
            break
        else:
            # Undecodable and not a declared marker: keep the raw bytes visible.
            chunk = payload[position:position + 2]
            out.append(as_placeholders(chunk))
            escaped += len(chunk)
            position += len(chunk)
    return "".join(out), escaped


def as_placeholders(payload: bytes) -> str:
    """Render bytes that cannot be shown as text as uppercase byte placeholders."""
    return "{{" + ":".join(f"{b:02X}" for b in payload) + "}}"


_PLACEHOLDER_START = "{{"


def render_display(payload: bytes, encodings: tuple[str, ...]) -> tuple[str, str | None]:
    """Return (display text, codec used, or None when nothing was decodable).

    A string that only partially decodes stays editable: the readable part is
    shown as text and the rejected bytes as placeholders.  Only a string with no
    decodable content at all is reported as undecodable.
    """
    # A declared line-break pair must be handled even when the whole string
    # decodes cleanly, otherwise the fast path below would show it as a literal
    # character in codecs that happen to accept those bytes.
    if any(pair in payload for pair in _LINE_BREAK_PAIRS):
        display, escaped = decode_with_placeholders(payload, encodings[0])
        return display, (None if escaped >= len(payload) else encodings[0])

    text, used = decode_text(payload, encodings)
    if text is not None:
        out: list[str] = []
        for character in text:
            out.append(
                as_placeholders(character.encode(used)) if ord(character) < 0x20 else character
            )
        return "".join(out), used
    display, escaped = decode_with_placeholders(payload, encodings[0])
    if escaped >= len(payload):
        return display, None
    return display, encodings[0]


def encode_display(text: str, encoding: str,
                   line_break: bytes | None = None) -> bytes:
    """Inverse of render_display: expand escapes, encode the rest strictly.

    ``line_break`` is the byte sequence a line-break marker turns back into.
    Pass it only for a string that stored its breaks inline; a message that
    breaks by splitting across arguments has no inline bytes to write, so the
    marker there is a part separator handled by the caller.
    """
    out = bytearray()
    pos = 0
    size = len(text)
    while pos < size:
        if line_break is not None and text.startswith(_PART_JOIN, pos):
            out += line_break
            pos += len(_PART_JOIN)
            continue
        if text.startswith(_PLACEHOLDER_START, pos):
            end = text.find("}}", pos)
            if end < 0:
                raise ValueError(f"unterminated placeholder at {pos}")
            body = text[pos + 2:end]
            for part in body.split(":"):
                if len(part) != 2 or part != part.upper():
                    raise ValueError(f"malformed placeholder {{{{{body}}}}}")
                out.append(int(part, 16))
            pos = end + 2
            continue
        # Encode up to whichever special sequence comes first.
        stops = [end for end in (text.find(_PLACEHOLDER_START, pos),) if end >= 0]
        if line_break is not None:
            found = text.find(_PART_JOIN, pos)
            if found >= 0:
                stops.append(found)
        end = min(stops) if stops else size
        out += text[pos:end].encode(encoding)
        pos = end
    return bytes(out)


# --------------------------------------------------------------------------
# Shape dispatch (§7.1.3)
# --------------------------------------------------------------------------
_SHAPES = {shape["id"]: shape for shape in DIALECT["entry_shapes"]}
# One marker for both ways a message can break a line: the `_` opcode between
# WORD instructions, and the EF F0 byte pair inside one argument.
_PART_JOIN = DIALECT["line_break_marker"]
_LINE_BREAK_BYTES = DIALECT["line_break_bytes"]
_LINE_BREAK_PAIRS = {
    bytes.fromhex(code): spec
    for code, spec in DIALECT["private_use_pairs"].items()
    if spec.get("role") == "line-break"
}
_SPEAKER_RULE = next(
    (rule for rule in DIALECT["text_rules"] if rule.get("annotation") == "speaker"), None
)
_ANCHORS = {anchor["id"]: anchor for anchor in DIALECT["anchors"]}
_CALLEE_GROUPS = {group["id"]: group for group in DIALECT["callee_groups"]}
_CALLEE_TO_GROUP = {
    callee: group for group in DIALECT["callee_groups"] for callee in group["callees"]
}
_META_CLASS_IDS = {spec["id"]: value for value, spec in DIALECT["meta_classes"].items()}
_RAW_TEXT_CLASS = _META_CLASS_IDS["raw-text"]
_LITERAL_CLASS = _META_CLASS_IDS["literal"]
_DEFAULT_POLICY = {
    "msg": "translatable",
    "choice": "translatable",
    "name": "translatable",
    "ui": "translatable",
    "system": "translatable",
    "ruby": "translatable",
    "label": "frozen",
    "misc": "review-required",
}


def _policy_for(tag: str, tag_source: str, override: str | None) -> str:
    if override:
        return override
    if tag_source == "unresolved":
        return "review-required"
    return _DEFAULT_POLICY.get(tag, "review-required")


def match_message_shape(part_count: int) -> str:
    """Pure predicate dispatch over declared message shapes; no fallback."""
    for shape in DIALECT["entry_shapes"]:
        match = shape["match"]
        if match.get("anchor") != "message_push":
            continue
        if "text_part_count" in match and part_count == match["text_part_count"]:
            return shape["id"]
        low = match.get("text_part_count_min")
        if low is not None and part_count >= low:
            return shape["id"]
    raise UnknownEntryShape(f"no declared message shape matches part_count={part_count}")


def shape_signature(document: Document, instruction: Instruction) -> str:
    """Stable signature used for corpus-wide shape census."""
    args = document.args_of(instruction)
    classes = ",".join(str(a.meta_class) for a in args)
    return f"{instruction.name}/{len(args)}[{classes}]"


def callee_name(document: Document, instruction: Instruction) -> str | None:
    """Resolve the callee of a call anchor from its declared slot."""
    anchor = _ANCHORS["engine_call"]
    if instruction.opcode != document.roles["call"]:
        return None
    args = document.args_of(instruction)
    slot = anchor["callee_slot"]
    if len(args) <= slot:
        return None
    argument = args[slot]
    if argument.meta_class != _META_CLASS_IDS[anchor["callee_meta_class"]]:
        return None
    token = string_token(document.blob(argument))
    if token is None:
        return None
    _quote, inner = strip_literal_quotes(token.payload)
    text, _used = decode_text(inner, (DIALECT["encodings"]["source"],))
    return text


def _speaker_of(text: str) -> tuple[str | None, str]:
    """Split a leading bracketed speaker name off an already-proven message.

    Returns ``(name without brackets, remaining body)``, or ``(None, text)`` when
    there is no speaker prefix.  The brackets are engine syntax, so they are not
    part of the editable name; they are restored on repack from the same rule.

    Measured on both corpora: 34,690 of 55,205 messages carry this prefix, every
    one closes its bracket, none nest, and none contain a line break — so the
    split is unambiguous.
    """
    rule = _SPEAKER_RULE
    if rule is None:
        return None, text
    opener = rule["delimiters"]["open"]
    closer = rule["delimiters"]["close"]
    if not text.startswith(opener):
        return None, text
    end = text.find(closer)
    if end <= 0:
        return None, text
    return text[len(opener):end], text[end + len(closer):]


def _speaker_wrap(name: str) -> str:
    """Rebuild the stored form of a speaker name, brackets included."""
    rule = _SPEAKER_RULE
    if rule is None:
        return name
    return rule["delimiters"]["open"] + name + rule["delimiters"]["close"]


def _unwrap_delimiters(text: str, delimiters: dict | None) -> tuple[str, bool]:
    """Strip a matching delimiter pair.  Returns (inner, was_wrapped)."""
    if not delimiters:
        return text, False
    opener = delimiters["open"]
    closer = delimiters["close"]
    if (text.startswith(opener) and text.endswith(closer)
            and len(text) >= len(opener) + len(closer)):
        return text[len(opener):len(text) - len(closer)], True
    return text, False


def _apply_wrap(text: str, delimiters: dict | None) -> str:
    """Put delimiters back, unless the translator already typed them."""
    if not delimiters:
        return text
    opener = delimiters["open"]
    closer = delimiters["close"]
    if text.startswith(opener) and text.endswith(closer):
        return text
    return opener + text + closer


def encoding_candidates(source_encoding: str | None = None) -> tuple[str, ...]:
    """Codecs to try, in order: the chosen source encoding first.

    The alternates only catch strings the chosen codec cannot decode at all; they
    never override it.  Order matters because a GBK string frequently also
    decodes as cp932 into mojibake, so guessing "first success" gives the wrong
    text on a translated corpus.
    """
    primary = source_encoding or DIALECT["encodings"]["source"]
    candidates = [primary]
    for alternate in (DIALECT["encodings"]["source"], *DIALECT["encodings"]["source_alternates"]):
        if alternate not in candidates:
            candidates.append(alternate)
    return tuple(candidates)


def extract_text_entries(document: Document,
                         source_encoding: str | None = None) -> list[TextEntry]:
    """Discover translatable text through proven anchors only.

    Two sources, both structural:
      * message: raw-text arguments of the message instruction, grouped into one
        entry per displayed message (``WORD (_ WORD)* RETURNCODE``);
      * call: literal arguments of calls whose callee is in a declared group.

    No byte scanning, no regex over the source, no appearance-based discovery.
    """
    encodings = encoding_candidates(source_encoding)
    message_op = document.roles["message"]
    break_op = document.roles["line_break"]
    end_op = document.roles["message_end"]
    call_op = document.roles["call"]
    window = next(w for w in DIALECT["windows"] if w["name"] == "message_scan")

    entries: list[TextEntry] = []
    idx = 1
    pending: list[Argument] = []
    run_length = 0
    start_instruction = -1

    def flush() -> None:
        nonlocal idx, pending, run_length, start_instruction
        if not pending:
            pending = []
            run_length = 0
            return
        shape_id = match_message_shape(len(pending))
        document.shape_counts[shape_id] += 1
        parts: list[str] = []
        used: list[str] = []
        undecodable = False
        for argument in pending:
            display, codec = render_display(document.blob(argument), encodings)
            parts.append(display)
            used.append(codec or "")
            if codec is None:
                undecodable = True
        joined = _PART_JOIN.join(parts)
        tag = _SHAPES[shape_id]["tag"]
        source = _SHAPES[shape_id]["tag_source"]
        policy = "frozen" if undecodable else _policy_for(tag, source, None)
        arg_indexes = tuple(a.index for a in pending)
        offsets = tuple(a.offset for a in pending)
        lengths = tuple(a.length for a in pending)
        codecs_used = tuple(used)

        # A bracketed speaker name becomes its own editable row.  Both rows point
        # at the same stored string and are rejoined on repack, so the name can be
        # translated without touching the dialogue around it.
        speaker, body = _speaker_of(joined)
        split_name = (
            speaker is not None
            # A name with no dialogue after it stays one row: splitting would
            # leave an empty body row, which import rightly rejects as deleted
            # content.  Measured: 4 such messages per corpus.
            and bool(body)
            and _SPEAKER_RULE is not None
            and _SPEAKER_RULE.get("split_row")
            and policy != "frozen"
        )
        if split_name:
            name_tag = _SPEAKER_RULE.get("row_tag", "name")
            entries.append(
                TextEntry(
                    idx=idx, tag=name_tag, tag_source=_SPEAKER_RULE["tag_source"],
                    translate_policy=_policy_for(name_tag, _SPEAKER_RULE["tag_source"], None),
                    shape_id=shape_id, instruction_index=start_instruction,
                    arg_indexes=arg_indexes, offsets=offsets, lengths=lengths,
                    source=speaker, encodings=codecs_used, speaker=None,
                    undecodable=False, role="speaker", pair_idx=idx + 1,
                )
            )
            idx += 1
            entries.append(
                TextEntry(
                    idx=idx, tag=tag, tag_source=source, translate_policy=policy,
                    shape_id=shape_id, instruction_index=start_instruction,
                    arg_indexes=arg_indexes, offsets=offsets, lengths=lengths,
                    source=body, encodings=codecs_used, speaker=speaker,
                    undecodable=undecodable, role="body", pair_idx=idx - 1,
                )
            )
        else:
            entries.append(
                TextEntry(
                    idx=idx, tag=tag, tag_source=source, translate_policy=policy,
                    shape_id=shape_id, instruction_index=start_instruction,
                    arg_indexes=arg_indexes, offsets=offsets, lengths=lengths,
                    source=joined, encodings=codecs_used, speaker=speaker,
                    undecodable=undecodable,
                )
            )
        idx += 1
        pending = []
        run_length = 0

    for instruction in document.instructions:
        opcode = instruction.opcode
        if opcode == message_op:
            texts = [
                a for a in document.args_of(instruction)
                if a.meta_class == _RAW_TEXT_CLASS and a.length > 0
            ]
            if texts:
                if start_instruction < 0 or not pending:
                    start_instruction = instruction.index
                pending.extend(texts)
            run_length += 1
        elif opcode == break_op:
            run_length += 1
        elif opcode == end_op:
            flush()
            start_instruction = -1
        else:
            # Any other instruction closes an open message run.
            flush()
            start_instruction = -1
            if opcode == call_op:
                group = _CALLEE_TO_GROUP.get(callee_name(document, instruction) or "")
                if group is not None:
                    idx = _emit_call_entries(
                        document, instruction, group, entries, idx, encodings
                    )
        if pending and run_length > window["value"]:
            # on_exceed = blocked: refuse rather than truncate and continue.
            raise DisassemblyError(
                f"{document.name}: message run at instruction {start_instruction} "
                f"exceeds {window['name']}={window['value']}"
            )
    flush()
    return entries


def _literal_display(document: Document, argument: Argument,
                     encodings: tuple[str, ...]) -> tuple[str, str | None] | None:
    """Decode one literal argument as display text, or None if it is not a string."""
    if argument.meta_class != _LITERAL_CLASS:
        return None
    token = string_token(document.blob(argument))
    if token is None:
        return None
    _quote, inner = strip_literal_quotes(token.payload)
    if not inner:
        return None
    return render_display(inner, encodings)


def _emit_call_entries(document: Document, instruction: Instruction, group: dict,
                       entries: list[TextEntry], idx: int,
                       encodings: tuple[str, ...]) -> int:
    """Emit one entry per translatable literal slot of a grouped call.

    One row per stored slot, even when two slots currently hold the same string:
    the row count follows the bytecode, not the data.
    """
    anchor = _ANCHORS["engine_call"]
    args = document.args_of(instruction)
    ordinals = group.get("text_slot_ordinals")
    shape_id = next(
        s["id"] for s in DIALECT["entry_shapes"]
        if s["match"].get("callee_group") == group["id"]
    )
    delimiters = group.get("wrap_delimiters")
    for position, argument in enumerate(args):
        if position == anchor["callee_slot"]:
            continue
        if ordinals is not None and position not in ordinals:
            continue
        decoded = _literal_display(document, argument, encodings)
        if decoded is None:
            continue
        display, codec = decoded
        stripped, wrapped = _unwrap_delimiters(display, delimiters)
        if not stripped:
            continue
        arg_indexes = (argument.index,)
        offsets = (argument.offset,)
        lengths = (argument.length,)
        wraps = (wrapped,)
        document.shape_counts[shape_id] += 1
        tag = _SHAPES[shape_id]["tag"]
        source = _SHAPES[shape_id]["tag_source"]
        policy = group.get("translate_policy")
        entries.append(
            TextEntry(
                idx=idx,
                tag=tag,
                tag_source=source,
                translate_policy="frozen" if codec is None else _policy_for(tag, source, policy),
                shape_id=shape_id,
                instruction_index=instruction.index,
                arg_indexes=arg_indexes,
                offsets=offsets,
                lengths=lengths,
                source=stripped,
                encodings=(codec or "",),
                speaker=None,
                undecodable=codec is None,
                wraps=wraps,
            )
        )
        idx += 1
    return idx


# --------------------------------------------------------------------------
# Coverage certificate
# --------------------------------------------------------------------------
def referenced_blocks(document: Document) -> list[tuple[int, int]]:
    """Merge every referenced arg_data range into maximal disjoint blocks.

    Arguments legitimately share and nest ranges (a conditional's body span
    contains the arguments inside it), so the union is the right unit for both
    the certificate and the layout solver.
    """
    ranges = sorted({(a.offset, a.length) for a in document.arguments if a.owns_bytes})
    blocks: list[list[int]] = []
    for offset, length in ranges:
        if blocks and offset <= blocks[-1][1]:
            blocks[-1][1] = max(blocks[-1][1], offset + length)
        else:
            blocks.append([offset, offset + length])
    return [(start, end) for start, end in blocks]


def coverage_certificate(document: Document) -> dict:
    """Every source byte gets exactly one owner; sha256 recomputable per span."""
    intervals: list[dict] = []
    plain = document.plain

    def add(kind: str, start: int, end: int, tier: str, status: str,
            owner: str, evidence: list[str]) -> None:
        if end <= start:
            return
        intervals.append({
            "id": f"{kind}@{start:08X}",
            "start": start,
            "end": end,
            "status": status,
            "kind": kind,
            "raw_sha256": sha256_bytes(plain[start:end]),
            "owner": owner,
            "decode_tier": tier,
            "tier_evidence_refs": evidence,
            "rewrite_policy": "derive" if status == "decoded" else "preserve",
        })

    add("header", 0, DIALECT["container"]["header_size"], "T3", "decoded",
        "container", DIALECT["container"]["evidence_refs"])
    inst_start, inst_len = document.section_offsets["inst_index"]
    add("inst_index", inst_start, inst_start + inst_len, "T3", "decoded",
        "instruction-stream", DIALECT["instruction_cell"]["evidence_refs"])
    arg_start, arg_len = document.section_offsets["arg_index"]
    add("arg_index", arg_start, arg_start + arg_len, "T3", "decoded",
        "argument-index", DIALECT["argument_cell"]["evidence_refs"])

    data_start, data_len = document.section_offsets["arg_data"]
    cursor = 0
    for start, end in referenced_blocks(document):
        if start > cursor:
            # Bytes no argument points at: preserved verbatim, never invented.
            # Their internal structure is unproven, so they stay opaque.
            add("arg_data_unreferenced", data_start + cursor, data_start + start,
                "T1", "opaque-preserved", "arg_data", DIALECT["argument_cell"]["evidence_refs"])
        # Referenced payload bytes: the argument index is the complete pointer
        # table into this section, so every element's start and length is known
        # explicitly rather than inferred, and the whole section can be rebuilt
        # from scratch at different sizes.  That is what full-layout requires.
        add("arg_data", data_start + start, data_start + end, "T3", "decoded",
            "arg_data", DIALECT["arg_token"]["evidence_refs"] + DIALECT["argument_cell"]["evidence_refs"])
        cursor = max(cursor, end)
    if cursor < data_len:
        add("arg_data_unreferenced", data_start + cursor, data_start + data_len,
            "T1", "opaque-preserved", "arg_data", DIALECT["argument_cell"]["evidence_refs"])

    line_start, line_len = document.section_offsets["line_index"]
    add("line_index", line_start, line_start + line_len, "T3", "decoded",
        "line-numbers", DIALECT["container"]["evidence_refs"])

    intervals.sort(key=lambda item: item["start"])
    size = len(plain)
    gaps: list[dict] = []
    overlaps: list[dict] = []
    cursor = 0
    for item in intervals:
        if item["start"] > cursor:
            gaps.append({"start": cursor, "end": item["start"]})
        elif item["start"] < cursor:
            overlaps.append({"start": item["start"], "end": min(cursor, item["end"])})
        cursor = max(cursor, item["end"])
    if cursor < size:
        gaps.append({"start": cursor, "end": size})

    covered = sum(item["end"] - item["start"] for item in intervals)
    tier_coverage = collections.Counter()
    for item in intervals:
        tier_coverage[item["decode_tier"]] += item["end"] - item["start"]
    tiers = [item["decode_tier"] for item in intervals]
    min_tier = min(tiers, key=lambda t: int(t[1:])) if tiers else "T0"

    status_counts = collections.Counter(item["status"] for item in intervals)
    # Capabilities are derived from the lowest tier actually proven, never
    # asserted: claiming an ability the evidence does not support is exactly the
    # overclaim the certificate exists to prevent.
    capabilities_by_tier = {
        "T0": [],
        "T1": ["roundtrip"],
        "T2": ["roundtrip", "in_place", "pointer-rewrite"],
        "T3": ["roundtrip", "in_place", "pointer-rewrite", "full-layout"],
        "T4": ["roundtrip", "in_place", "pointer-rewrite", "full-layout", "control-flow"],
    }
    return {
        "schema_version": "1.1.0",
        "layer_id": "L000",
        "source": document.name,
        "source_sha256": document.source_sha256,
        "source_size": size,
        "encrypted": document.encrypted,
        "intervals": intervals,
        "gaps": gaps,
        "overlaps": overlaps,
        "status_counts": dict(status_counts),
        "byte_coverage": (covered - sum(o["end"] - o["start"] for o in overlaps)) / size if size else 0.0,
        "structural_coverage": 1.0 if not gaps and not overlaps else 0.0,
        "tier_coverage": {t: tier_coverage.get(t, 0) for t in ("T0", "T1", "T2", "T3", "T4")},
        "min_tier": min_tier,
        "declared_capabilities": capabilities_by_tier[min_tier],
        "tier_blocked": [],
        "instruction_coverage": 1.0 if min_tier in ("T3", "T4") else "not_applicable",
        "transform_edges": ([{
            "algorithm": DIALECT["cipher"]["algorithm"],
            "key": f"0x{document.key:08X}",
            "input_hash": document.source_sha256,
            "output_hash": sha256_bytes(document.plain),
            "reversible": True,
        }] if document.encrypted else []),
        "toolchain": {
            "tool_version": TOOL_VERSION,
            "ir_version": IR_VERSION,
            "dialect_id": DIALECT["dialect_id"],
            "schema_version": DIALECT["schema_version"],
        },
    }


# --------------------------------------------------------------------------
# Projection 1: dual-line text
# --------------------------------------------------------------------------
def render_texts(document: Document, entries: list[TextEntry] | None = None,
                 target_encoding: str | None = None,
                 source_encoding: str | None = None) -> str:
    """Render the translator-facing editing surface.

    The translation row is pre-filled with the source, so "untranslated" means
    ``target == source`` and an empty row means the content was deleted.
    Only fields that import actually validates are written.
    """
    if entries is None:
        entries = extract_text_entries(document, source_encoding)
    encodings = DIALECT["encodings"]
    target = target_encoding or encodings["target"]
    source = source_encoding or encodings["source"]
    out: list[str] = [
        f"# TEXT/2 ir={IR_VERSION} tool={TOOL_VERSION} src_sha256={document.source_sha256}",
        f"# encoding source={source} target={target} file={encodings['text_file']}",
        "# scope kind=all range=ALL part=1/1",
        "# tags " + " ".join(sorted(
            {s["tag"] for s in DIALECT["entry_shapes"]} | set(DIALECT["extra_tags"])
        )),
        "",
    ]
    for entry in entries:
        meta = (
            f"# idx={entry.idx:08d} off=0x{entry.offsets[0]:08X} "
            f"inst={entry.instruction_index} tag={entry.tag}"
        )
        # With the name on its own row the speaker is already visible, so the
        # comment would just repeat it.  Keep it only where it is not.
        if entry.speaker and not entry.role:
            meta += f" speaker={entry.speaker}"
        if entry.role in ("speaker", "body") and entry.pair_idx is not None:
            meta += f" pair={entry.pair_idx:08d}"
        if entry.translate_policy == "frozen":
            meta += " frozen=1"
        out.append(meta)
        out.append(f"{WHITE_BULLET}{entry.idx:08d}{WHITE_BULLET}{entry.tag}{WHITE_BULLET}{entry.source}")
        out.append(f"{BLACK_BULLET}{entry.idx:08d}{BLACK_BULLET}{entry.tag}{BLACK_BULLET}{entry.source}")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Projection 2: asm listing
# --------------------------------------------------------------------------
def _render_token(token: Token, encodings: tuple[str, ...]) -> str:
    if token.tag == DIALECT["arg_token"]["string_tag"]:
        quote, inner = strip_literal_quotes(token.payload)
        display, _codec = render_display(inner, encodings)
        mark = quote.decode("ascii") if quote else ""
        return f'.string {mark}{display}{mark}'
    values = ", ".join(str(b) for b in token.payload)
    return f".{token.tag.decode('ascii', 'replace')} {values}" if values else \
           f".{token.tag.decode('ascii', 'replace')}"


def render_asm(document: Document, source_encoding: str | None = None) -> str:
    """Render the developer-facing structural view.

    Deterministic: identical input bytes always produce identical output, which
    is what lets the assembler diff a fresh projection against a user's file.
    No raw hex dumps and no byte sequences in comments.
    """
    encodings = encoding_candidates(source_encoding)
    out: list[str] = [
        f'.encoding "{encodings[0]}"',
        f'.dialect  "{DIALECT["dialect_id"]}" version "{DIALECT["schema_version"]}"',
        f'.tier     "T3"',
        f'.source   "{document.name}" sha256 {document.source_sha256}',
        f'.commands "{pathlib.Path(document.command_table.source).name}" count {len(document.command_table.commands)}',
        "",
    ]
    for instruction in document.instructions:
        out.append("")
        out.append(f"loc_{instruction.index:08d}:            ; line {instruction.line}")
        out.append(f"    {instruction.name}")
        for position, argument in enumerate(document.args_of(instruction)):
            head = (
                f"    .arg  slot={position} sid={argument.index} "
                f"class={DIALECT['meta_classes'][argument.meta_class]['id'] if argument.meta_class in DIALECT['meta_classes'] else argument.meta_class} "
                f"ordinal={argument.slot}"
            )
            if argument.is_branch_target:
                out.append(head + f" -> loc_{argument.length:08d}")
                continue
            if argument.length == 0:
                out.append(head + " empty")
                continue
            out.append(head + f" off=0x{argument.offset:08X} len={argument.length}")
            blob = document.blob(argument)
            if argument.meta_class == _RAW_TEXT_CLASS:
                display, _codec = render_display(blob, encodings)
                out.append(f"        .string {display}")
                continue
            tokens = split_tokens(blob)
            if tokens is None:
                out.append("        .opaque   ; payload does not frame as tokens")
                continue
            for token in tokens:
                out.append("        " + _render_token(token, encodings))
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Input discovery and output layout
# --------------------------------------------------------------------------
SCRIPT_SUFFIX = ".ybn"


def iter_sources(root: pathlib.Path) -> list[pathlib.Path]:
    """Find candidate script files.  Non-scripts are rejected by magic, not name."""
    if root.is_file():
        return [root]
    return sorted(
        path for path in root.rglob(f"*{SCRIPT_SUFFIX}")
        if path.is_file() and "output" not in path.parts
    )


def default_output_dir(inputs: list[pathlib.Path]) -> pathlib.Path:
    """``output/`` under the common parent of the inputs (§ output layout)."""
    if not inputs:
        raise DisassemblyError("no input files")
    first = inputs[0]
    base = first.parent if first.is_file() else first
    for path in inputs[1:]:
        candidate = path.parent if path.is_file() else path
        while not str(candidate).startswith(str(base)):
            base = base.parent
        _ = candidate
    return base / "output"


def mirror_path(source: pathlib.Path, root: pathlib.Path, out_dir: pathlib.Path,
                suffix: str) -> pathlib.Path:
    base = root if root.is_dir() else root.parent
    try:
        relative = source.relative_to(base)
    except ValueError:
        relative = pathlib.Path(source.name)
    return out_dir / (str(relative) + suffix)


@dataclass(slots=True)
class FileResult:
    name: str
    ok: bool
    entry_count: int = 0
    tags: dict = field(default_factory=dict)
    shapes: dict = field(default_factory=dict)
    encodings: dict = field(default_factory=dict)
    byte_coverage: float = 0.0
    roundtrip_identical: bool = False
    skipped: str = ""
    error: str = ""


def _self_check(document: Document) -> bool:
    """Zero-edit roundtrip: re-serialize the parsed IR and compare to the source.

    Always runs, regardless of which optional artifacts were requested.
    """
    import assembler
    return assembler.serialize(document, {}) == document.raw


def process_one(source: pathlib.Path, root: pathlib.Path, out_dir: pathlib.Path,
                want_texts: bool, want_asm: bool, want_certificate: bool,
                target_encoding: str | None, source_encoding: str | None = None,
                command_table: CommandTable | None = None) -> FileResult:
    try:
        document = parse(source, command_table=command_table)
    except NotAScriptError as exc:
        return FileResult(source.name, ok=True, skipped=str(exc))
    except DisassemblyError as exc:
        return FileResult(source.name, ok=False, error=str(exc))

    entries = extract_text_entries(document, source_encoding)
    certificate = coverage_certificate(document)
    identical = _self_check(document)

    if want_texts:
        target = mirror_path(source, root, out_dir / "texts", ".txt")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            render_texts(document, entries, target_encoding, source_encoding),
            encoding=DIALECT["encodings"]["text_file"],
        )
    if want_asm:
        target = mirror_path(source, root, out_dir / "asm", ".asm.txt")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_asm(document, source_encoding),
                          encoding=DIALECT["encodings"]["asm"])
    if want_certificate:
        target = mirror_path(source, root, out_dir / "reports" / "certificates", ".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(certificate, ensure_ascii=False, indent=1), encoding="utf-8")

    codecs: collections.Counter = collections.Counter()
    for entry in entries:
        for codec in entry.encodings:
            codecs[codec or "undecodable"] += 1
    return FileResult(
        name=source.name,
        ok=True,
        entry_count=len(entries),
        tags=dict(collections.Counter(e.tag for e in entries)),
        shapes=dict(document.shape_counts),
        encodings=dict(codecs),
        byte_coverage=certificate["byte_coverage"],
        roundtrip_identical=identical,
    )


def _worker(payload: tuple) -> FileResult:
    (source, root, out_dir, want_texts, want_asm, want_cert,
     target_encoding, source_encoding) = payload
    return process_one(source, root, out_dir, want_texts, want_asm, want_cert,
                       target_encoding, source_encoding)


def export(root: pathlib.Path, out_dir: pathlib.Path | None = None, *,
           texts: bool = True, asm: bool = False, certificates: bool = False,
           target_encoding: str | None = None, source_encoding: str | None = None,
           jobs: int | None = None, progress=None) -> dict:
    """Run the text/asm export over one file or a whole tree."""
    sources = iter_sources(root)
    if not sources:
        raise DisassemblyError(f"no {SCRIPT_SUFFIX} files found under {root}")
    if not texts and not asm:
        raise DisassemblyError("nothing to do: enable texts or asm")
    out_dir = out_dir or default_output_dir(sources)
    out_dir.mkdir(parents=True, exist_ok=True)

    workers = jobs if jobs is not None else min(os.cpu_count() or 1, len(sources))
    payloads = [
        (s, root, out_dir, texts, asm, certificates, target_encoding, source_encoding)
        for s in sources
    ]
    results: list[FileResult] = []
    if workers > 1 and len(sources) > 4:
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
            for index, result in enumerate(pool.map(_worker, payloads, chunksize=8), 1):
                results.append(result)
                if progress:
                    progress(index, len(sources), result.name)
    else:
        table = CommandTable.find(root)
        for index, (source, *_rest) in enumerate(payloads, 1):
            results.append(process_one(source, root, out_dir, texts, asm, certificates,
                                       target_encoding, source_encoding,
                                       command_table=table))
            if progress:
                progress(index, len(sources), source.name)

    # Sort by name so the summary is independent of completion order.
    results.sort(key=lambda item: item.name)
    tags: collections.Counter = collections.Counter()
    shapes: collections.Counter = collections.Counter()
    codecs: collections.Counter = collections.Counter()
    entry_total = 0
    processed = 0
    failures: list[dict] = []
    skipped: list[dict] = []
    roundtrip_failures: list[str] = []
    min_coverage = 1.0
    for result in results:
        if not result.ok:
            failures.append({"file": result.name, "error": result.error})
            continue
        if result.skipped:
            skipped.append({"file": result.name, "reason": result.skipped})
            continue
        processed += 1
        entry_total += result.entry_count
        tags.update(result.tags)
        shapes.update(result.shapes)
        codecs.update(result.encodings)
        min_coverage = min(min_coverage, result.byte_coverage)
        if not result.roundtrip_identical:
            roundtrip_failures.append(result.name)

    summary = {
        "tool_version": TOOL_VERSION,
        "dialect_id": DIALECT["dialect_id"],
        "input": str(root),
        "output": str(out_dir),
        "file_count": len(sources),
        "processed": processed,
        "entry_count": entry_total,
        "tags": dict(tags),
        "shapes": dict(shapes),
        "encodings": dict(codecs),
        "min_byte_coverage": min_coverage if processed else 0.0,
        "roundtrip_identical": not roundtrip_failures and processed > 0,
        "roundtrip_failures": roundtrip_failures,
        "skipped": skipped,
        "failures": failures,
        "artifacts": {"texts": texts, "asm": asm, "certificates": certificates},
    }
    reports = out_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "extract_report.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (reports / "shapes.json").write_text(
        json.dumps({"shape_signatures": dict(shapes), "unresolved": 0},
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Disassemble Yu-Ris YSTB scripts into dual-line text and/or an asm listing."
    )
    parser.add_argument("input", type=pathlib.Path, nargs="?", default=pathlib.Path("."),
                        help="script file or directory")
    parser.add_argument("-o", "--out-dir", type=pathlib.Path, default=None,
                        help="output directory (default: output/ beside the input)")
    parser.add_argument("--no-texts", action="store_true", help="skip the dual-line text export")
    parser.add_argument("--asm", action="store_true", help="also write the asm listing")
    parser.add_argument("--certificates", action="store_true",
                        help="write a per-file coverage certificate")
    parser.add_argument("--target-encoding", default=None,
                        help=f"encoding translations will be written back in "
                             f"(default {DIALECT['encodings']['target']})")
    parser.add_argument("--source-encoding", default=None,
                        help=f"encoding the script's text is stored in "
                             f"(default {DIALECT['encodings']['source']})")
    parser.add_argument("--jobs", type=int, default=None, help="worker processes")
    args = parser.parse_args(argv)

    try:
        summary = export(
            args.input, args.out_dir,
            texts=not args.no_texts, asm=args.asm, certificates=args.certificates,
            target_encoding=args.target_encoding, source_encoding=args.source_encoding,
            jobs=args.jobs,
        )
    except DisassemblyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"files={summary['processed']}/{summary['file_count']}")
    print(f"entries={summary['entry_count']}")
    for tag, count in sorted(summary["tags"].items()):
        print(f"  {tag}={count}")
    print(f"byte_coverage={summary['min_byte_coverage']:.6f}")
    print(f"roundtrip_identical={summary['roundtrip_identical']}")
    if summary["skipped"]:
        print(f"skipped={len(summary['skipped'])}")
    if summary["failures"]:
        for failure in summary["failures"]:
            print(f"FAILED {failure['file']}: {failure['error']}", file=sys.stderr)
        return 1
    print(f"output={summary['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
