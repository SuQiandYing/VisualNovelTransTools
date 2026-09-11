"""Declarative dialect for the Yu-Ris YSTB script container.

This module holds DATA ONLY: no parsing algorithms, no control flow beyond
literal construction.  Every engine-specific number, name and rule lives here so
that the structural logic in ``disassembler.py`` / ``assembler.py`` stays free of
engine literals (see scripts/check_no_literals.py).

Each entry that drives a decision carries ``evidence_refs`` pointing at a section
of ``vm_analysis.md`` and a ``confidence`` level:
``observed`` > ``derived`` > ``inferred`` > ``unresolved``.
"""

SCHEMA_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Container layout
# --------------------------------------------------------------------------
# YSTB: 32-byte header followed by four sections whose lengths are stored in the
# header.  file_size == header + sec1 + sec2 + sec3 + sec4 holds for every sample
# in every corpus (EV_CONTAINER).
#
# Versions are listed only after the whole structure was measured, never on the
# assumption that a nearby number behaves the same way:
#
#   300  77 (936 files), Nepgear2 (395 files)
#   553  G.I.B. (94 files) — same 32-byte header, same 4/12/4 cell sizes, same
#        count*4 scaling, same XOR cipher and key recovery, same argc-sum
#        invariant, and a byte-exact zero-edit roundtrip on all 94 files.
#
# A version outside this list is refused with its number rather than guessed at.
CONTAINER = {
    "magic_bytes": b"YSTB",
    "header_size": 32,
    "header_fields": [
        "magic", "version", "count",
        "inst_index_len", "arg_index_len", "arg_data_len", "line_index_len",
        "reserved",
    ],
    "supported_versions": [300, 553],
    "sections": [
        # name             length_field        cell   note
        ("inst_index", "inst_index_len", 4, "one 4-byte cell per instruction"),
        ("arg_index", "arg_index_len", 12, "one 12-byte cell per argument"),
        ("arg_data", "arg_data_len", 1, "argument payload pool"),
        ("line_index", "line_index_len", 4, "one 4-byte cell per instruction"),
    ],
    # inst_index_len == line_index_len == count * 4 for every sample.
    "count_scaled_sections": ["inst_index", "line_index"],
    "evidence_refs": ["EV_CONTAINER"],
    "confidence": "observed",
}

# 4-byte instruction cell: opcode, argument count, then two bytes that are zero
# in every sample of both corpora.
INSTRUCTION_CELL = {
    "size": 4,
    "fields": [
        {"name": "opcode", "offset": 0, "width": 1},
        {"name": "argc", "offset": 1, "width": 1},
        {"name": "reserved", "offset": 2, "width": 2, "expect_zero": True},
    ],
    # sum(argc) == arg_index_len / 12 for every sample: this is what proves the
    # instruction boundaries are complete and non-overlapping (T3).
    "argc_sums_to_arg_count": True,
    "evidence_refs": ["EV_INST_INDEX"],
    "confidence": "derived",
}

# 12-byte argument cell.  ``meta`` packs a value-class in the high word and a
# parameter slot ordinal in the low word.
ARGUMENT_CELL = {
    "size": 12,
    "fields": [
        {"name": "meta", "offset": 0, "width": 4},
        {"name": "length", "offset": 4, "width": 4},
        {"name": "offset", "offset": 8, "width": 4},
    ],
    "meta_class_shift": 16,
    "meta_ordinal_mask": 0xFFFF,
    "evidence_refs": ["EV_ARG_INDEX"],
    "confidence": "derived",
}

# Observed meta classes.  ``raw-text`` is the only class whose payload is a bare
# encoded string; every other class carries a tagged token stream.
META_CLASSES = {
    0: {"id": "raw-text", "framing": "bare", "evidence_refs": ["EV_META_CLASS"]},
    1: {"id": "expression", "framing": "token-stream", "evidence_refs": ["EV_META_CLASS"]},
    2: {"id": "expression-alt", "framing": "token-stream", "evidence_refs": ["EV_META_CLASS"]},
    3: {"id": "literal", "framing": "token-stream", "evidence_refs": ["EV_META_CLASS"]},
}

# Token stream inside a non-raw argument payload: 1-byte tag, 2-byte little
# endian length, then that many payload bytes.  420,363 arguments parse cleanly.
ARG_TOKEN = {
    "tag_width": 1,
    "length_width": 2,
    "string_tag": b"M",
    "evidence_refs": ["EV_ARG_TOKEN"],
    "confidence": "derived",
}

# Script-side string literals keep their original quote character; ` is used for
# strings that themselves contain Japanese quotation marks.
STRING_LITERAL_QUOTES = [b'"', b"'", b"`"]

# --------------------------------------------------------------------------
# Encryption
# --------------------------------------------------------------------------
# Repeating 4-byte XOR over the four sections; the header is never touched.
# Symmetric, so the same routine encrypts and decrypts.
CIPHER = {
    "algorithm": "xor-u32-repeating",
    "covers_sections": ["inst_index", "arg_index", "arg_data", "line_index"],
    "covers_header": False,
    "key_width": 4,
    "key_file_name": "Key.txt",
    # The first argument's arg_data offset decrypts to 0, so the stored 4 bytes
    # at that position are the key itself.
    "key_probe": {"section": "arg_index", "field": "offset", "arg_ordinal": 0},
    # The header is NOT encrypted, so the section lengths add up even for an
    # encrypted file.  The usable plaintext test is the argc-sum invariant:
    # sum(argc) == arg_index_len / 12 only holds once the payload is decrypted.
    "detect_plaintext_by": "argc_sum_invariant",
    "evidence_refs": ["EV_CIPHER"],
    "confidence": "observed",
}

# --------------------------------------------------------------------------
# Command table (YSCM) — opcode is an index into this table
# --------------------------------------------------------------------------
COMMAND_TABLE = {
    "file_name": "ysc.ybn",
    "magic_bytes": b"YSCM",
    "header_size": 16,
    "count_field_offset": 8,
    # entry: NUL-terminated name, 1-byte arg count, then per argument a
    # NUL-terminated name followed by 2 bytes of type/flags.
    "entry": {
        "name": "cstring",
        "arg_count_width": 1,
        "argument": {"name": "cstring", "trailer_width": 2},
    },
    "encoding": "cp932",
    "evidence_refs": ["EV_COMMAND_TABLE"],
    "confidence": "observed",
}

# Command names the structural logic refers to.  Values are names, never opcode
# numbers: the numeric opcode is resolved from the loaded command table.
COMMANDS = {
    "message": "WORD",           # 0x59 — the text-emitting instruction
    "line_break": "_",           # 0x54 — soft line break inside one message
    "message_end": "RETURNCODE",  # 0x3e — closes the current message
    "call": "GOSUB",             # 0x1c — engine call, slot 0 is the callee name
    "jump": "GO",                # 0x1b — jump; the target is a label NAME, not
                                 # an offset, so text relayout needs no fixups
    "conditional": "IF",         # 0x1d — carries a branch target (see anchors)
    "branch_else": "ELSE",       # 0x1f — likewise
    "block_end": "IFEND",        # 0x21 — branch targets resolve here
    "loop": "LOOP",              # carries a branch target like IF
    "loop_end": "LOOPEND",       # loop targets resolve here
}

# --------------------------------------------------------------------------
# Anchors
# --------------------------------------------------------------------------
ANCHORS = [
    {
        "id": "message_push",
        "kind": "push",
        "command": "message",
        "operand_slots": [{"meta_class": "raw-text", "name": "text"}],
        "evidence_refs": ["EV_MSG_WORD"],
        "confidence": "derived",
    },
    {
        "id": "engine_call",
        "kind": "call",
        "command": "call",
        "callee_slot": 0,
        "callee_meta_class": "literal",
        "evidence_refs": ["EV_CALL_GOSUB"],
        "confidence": "derived",
    },
    {
        "id": "branch_target",
        "kind": "table-slot",
        # IF / ELSE store a branch target in the argument's *length* field: the
        # instruction index of the matching block closer.  Verified on 473 IF
        # instructions, every resolved target is an IFEND (or ELSE for ELSE).
        # Such arguments address no arg_data bytes at all, so they must be
        # excluded from byte ownership and never relocated as data.
        "commands": ["conditional", "branch_else", "loop"],
        "target_in_field": "length",
        "target_kind": "instruction_index",
        # A target lives in a raw-text-class slot; the literal class never holds
        # one.  This is what identifies a target, NOT whether its range happens
        # to fall outside arg_data: that test only works in small files.
        # Measured across three corpora: 1,453 targets, none of which is used as
        # text anywhere, and every resolved target lands on a declared closer.
        "target_meta_class": "raw-text",
        "closer_commands": ["block_end", "branch_else", "loop_end"],
        "rewrite_policy": "preserve",
        "evidence_refs": ["EV_BRANCH_TARGET"],
        "confidence": "derived",
    },
]

# --------------------------------------------------------------------------
# Callee groups
# --------------------------------------------------------------------------
CALLEE_GROUPS = [
    {
        "id": "choice",
        "callees": ["es.SEL.SET"],
        "role": "choice",
        # Every literal slot after the callee holds one selectable option.
        "text_slots_after_callee": True,
        "evidence_refs": ["EV_CHOICE_SEL_SET"],
        "confidence": "derived",
    },
    {
        "id": "sound_name",
        "callees": ["es.SE"],
        "role": "misc",
        "subtype": "sound-name",
        "text_slot_ordinals": [2],
        # These name audio assets; translating them would break playback.
        "translate_policy": "frozen",
        "evidence_refs": ["EV_SOUND_NAME"],
        "confidence": "derived",
    },
    {
        # The character-name table.  Slot 1 is the label the engine matches on,
        # slot 2 the name it draws.  Brackets are engine syntax, so they are
        # stripped for editing and restored on whichever slot had them.
        #
        # Each slot gets its own row, including the ones that currently hold the
        # same string.  Collapsing equal slots into a single row was tried and
        # dropped: one row silently writing two stored locations hides what is
        # actually in the file, and the row count then depends on the data rather
        # than on the bytecode.  Two rows per call site is predictable, and an
        # `id＠display` slot is not a special case under that rule.
        "id": "character_name",
        "callees": ["es.CHAR.NAME"],
        "role": "name",
        "subtype": "character-name",
        "text_slot_ordinals": [1, 2],
        "wrap_delimiters": {"open": "【", "close": "】"},
        "evidence_refs": ["EV_CHAR_NAME"],
        "confidence": "derived",
    },
]

# --------------------------------------------------------------------------
# Entry shapes (§7.1.3) — declaration order is match order
# --------------------------------------------------------------------------
# A message is one WORD instruction, optionally continued by `_` + WORD pairs,
# closed by RETURNCODE.  Both observed shapes are listed; a message that matches
# neither is reported as an unknown shape rather than silently dropped.
ENTRY_SHAPES = [
    {
        "id": "message-single-part",
        "match": {"anchor": "message_push", "text_part_count": 1},
        "tag": "msg",
        "tag_source": "anchor",
        "evidence_refs": ["EV_SHAPE_MSG_1"],
    },
    {
        "id": "message-multi-part",
        "match": {"anchor": "message_push", "text_part_count_min": 2},
        "tag": "msg",
        "tag_source": "anchor",
        # Parts are joined for display with LINE_BREAK_MARKER and split back on
        # repack.  See that constant for why the marker is shared with EF F0.
        "evidence_refs": ["EV_SHAPE_MSG_N"],
    },
    {
        "id": "choice-option",
        "match": {"anchor": "engine_call", "callee_group": "choice"},
        "tag": "choice",
        "tag_source": "anchor",
        "evidence_refs": ["EV_CHOICE_SEL_SET"],
    },
    {
        "id": "sound-name",
        "match": {"anchor": "engine_call", "callee_group": "sound_name"},
        "tag": "misc",
        "tag_source": "anchor",
        "evidence_refs": ["EV_SOUND_NAME"],
    },
    {
        "id": "character-name",
        "match": {"anchor": "engine_call", "callee_group": "character_name"},
        "tag": "name",
        "tag_source": "anchor",
        # Not every game has a CHAR.NAME table; 77 does not.  Cross-corpus
        # "every shape is exercised" therefore skips optional shapes.
        "optional": True,
        "evidence_refs": ["EV_CHAR_NAME"],
    },
]

# --------------------------------------------------------------------------
# Line breaks inside one displayed message
# --------------------------------------------------------------------------
# A message can be broken across display lines two different ways, and both mean
# the same thing to the reader, so both are shown as this one marker:
#
#   * the `_` opcode between two WORD instructions (original Japanese build);
#   * the EF F0 byte pair inside a single WORD argument (Chinese patch build).
#
# Measured on both corpora: EF F0 occurs 23,854 times, never at the start or end
# of a string, and is followed by an ideographic space or a sentence-initial
# character — the same positions the `_` opcode occupies in the Japanese build.
# Showing it as a raw byte placeholder made translators treat a line break as an
# untouchable binary blob, so it is presented as an ordinary escape instead.
LINE_BREAK_MARKER = "\\n"
LINE_BREAK_BYTES = bytes.fromhex("EFF0")

# --------------------------------------------------------------------------
# Text rules — secondary disambiguation only, never discovery
# --------------------------------------------------------------------------
# Speaker names appear as a bracketed prefix inside an already-proven message
# argument.  The brackets are engine syntax, not part of the name, so they are
# stripped for editing and written back verbatim on repack.
TEXT_RULES = [
    {
        "id": "speaker-prefix",
        "requires_anchor_kind": "push",
        "predicates": [{"kind": "starts_with", "value": "【"}],
        # Emit the name as its own editable row rather than only a comment, so a
        # translator can change 【翔】 without touching the dialogue bytes around
        # it.  The two rows share one stored string and are rejoined on repack.
        "annotation": "speaker",
        "split_row": True,
        "row_tag": "name",
        "delimiters": {"open": "【", "close": "】"},
        "tag_source": "heuristic",
        "confidence": "inferred",
        "evidence_refs": ["EV_SPEAKER_PREFIX"],
    },
]

# `name` is emitted by the speaker-prefix rule above, so it is a real tag even
# though no entry shape declares it.
EXTRA_TAGS = ("name",)

# --------------------------------------------------------------------------
# Encodings
# --------------------------------------------------------------------------
ENCODINGS = {
    "source": "cp932",
    # No alternate codec list on purpose.  A byte string that fails to decode is
    # NOT retried with another codec: a Shift-JIS string very often also decodes
    # as GBK (and vice versa) into plausible-looking mojibake, so "first codec
    # that succeeds" silently produces wrong text.  The codec is a declared
    # parameter; undecodable bytes are surfaced, not guessed.
    "source_alternates": [],
    "target": "cp932",
    "text_file": "utf-8-sig",
    "asm": "utf-8",
    "common_choices": ["cp932", "gbk", "big5", "cp949", "utf-8"],
    "evidence_refs": ["EV_ENCODING"],
}

# Byte pairs the codec rejects but that the engine renders through a font-side
# character extension.  Any pair listed with role "line-break" is shown as
# LINE_BREAK_MARKER; the rest fall back to a byte placeholder so nothing is ever
# guessed.  All of them are written back byte-for-byte either way.
PRIVATE_USE_PAIRS = {
    "EFF0": {
        "role": "line-break",
        "note": "line break inside one message; the Chinese patch uses this where "
                "the Japanese build uses the `_` opcode",
        "evidence_refs": ["EV_PRIVATE_USE"],
        "confidence": "derived",
    },
    # 81 01 .. 81 0B also appear (about 85 times total) but their role is not
    # established, so they stay placeholders.
}

# String payloads are not NUL-terminated: the length is explicit.
TERMINATOR_LENGTH = 0

# --------------------------------------------------------------------------
# Window constants (§1.6)
# --------------------------------------------------------------------------
WINDOWS = [
    {
        "name": "message_scan",
        "value": 64,
        "measured_max": 5,
        "evidence": "longest observed WORD/_/RETURNCODE run across both corpora",
        "on_exceed": "blocked",
    },
    {
        "name": "choice_slot_scan",
        "value": 32,
        "measured_max": 9,
        "evidence": "widest observed es.SEL.SET argument list",
        "on_exceed": "blocked",
    },
]

# Files that share the .ybn extension but are not scripts.
NON_SCRIPT_MAGICS = {b"YSCM": "command table", b"YSCF": "engine config"}

DIALECT = {
    "schema_version": SCHEMA_VERSION,
    "engine_id": "yuris",
    "dialect_id": "ystb-v300",
    "endianness": "little",
    "container": CONTAINER,
    "instruction_cell": INSTRUCTION_CELL,
    "argument_cell": ARGUMENT_CELL,
    "meta_classes": META_CLASSES,
    "arg_token": ARG_TOKEN,
    "string_literal_quotes": STRING_LITERAL_QUOTES,
    "cipher": CIPHER,
    "command_table": COMMAND_TABLE,
    "commands": COMMANDS,
    "anchors": ANCHORS,
    "callee_groups": CALLEE_GROUPS,
    "entry_shapes": ENTRY_SHAPES,
    "text_rules": TEXT_RULES,
    "extra_tags": EXTRA_TAGS,
    "line_break_marker": LINE_BREAK_MARKER,
    "line_break_bytes": LINE_BREAK_BYTES,
    "encodings": ENCODINGS,
    "private_use_pairs": PRIVATE_USE_PAIRS,
    "terminator_length": TERMINATOR_LENGTH,
    "windows": WINDOWS,
    "non_script_magics": NON_SCRIPT_MAGICS,
}
