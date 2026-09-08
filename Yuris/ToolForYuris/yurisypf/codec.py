# -*- coding: utf-8 -*-
from __future__ import annotations

from collections import Counter
import codecs

from .constants import ENCODING_ALIASES, LENGTH_TABLES, LENGTH_TABLE_1F4, LENGTH_TABLE_OLD, YPF_VER_1F4

KNOWN_EXTENSIONS = (
    b".ybn", b".txt", b".bmp", b".png", b".jpg", b".jpeg", b".gif",
    b".wav", b".ogg", b".psd", b".ycg", b".ydg", b".psb", b".webp",
    b".avi", b".mpg", b".mpeg", b".vob",
)


def default_length_scheme(version: int) -> str:
    # For naked packing without metadata.  Extraction does not rely on this; it
    # tries every known table and validates the result.
    return "relirium_1f4" if version >= YPF_VER_1F4 else "swap00"


def length_table_by_name(name: str | None, version: int) -> bytes:
    key = (name or default_length_scheme(version)).lower()
    if key not in LENGTH_TABLES:
        key = default_length_scheme(version)
    return LENGTH_TABLES[key]


def convert_path_length(value: int, version: int, scheme: str | None = None) -> int:
    table = length_table_by_name(scheme, version)
    return table[value & 0xFF]


def encode_path_length(length: int, version: int, scheme: str | None = None) -> int:
    if not (0 <= length <= 0xFF):
        raise ValueError(f"YPF path length out of range: {length}")
    table = length_table_by_name(scheme, version)
    try:
        return table.index(length)
    except ValueError as exc:
        raise ValueError(f"Path length {length} cannot be represented by length scheme {scheme!r}") from exc


def encoding_name(encoding: str | None) -> str:
    """Normalize path text encoding.

    Use real Python codec names such as cp932/cp949/gbk/big5/utf-8.
    Old labels jap/kor/chs/ansi are still accepted as aliases.
    """
    key = (encoding or "cp932").strip().lower().replace("-", "_")
    key = ENCODING_ALIASES.get(key, key)
    try:
        return codecs.lookup(key).name
    except LookupError as exc:
        raise ValueError(
            f"Unsupported path encoding '{encoding}'. Use a Python codec name such as "
            "cp932, cp949, gbk, big5, cp1252, or utf-8."
        ) from exc


def encode_archive_path(path_text: str, encoding: str) -> bytes:
    # Original WideCharToMultiByte behavior replaces unsupported characters.
    return path_text.encode(encoding_name(encoding), errors="replace")


def decode_archive_path(path_bytes: bytes, encoding: str) -> str:
    return path_bytes.decode(encoding_name(encoding), errors="replace")


def xor_path_for_table(stored_path: bytes, path_key: int) -> bytes:
    key = path_key & 0xFF
    return bytes((b ^ key) for b in stored_path)


def unxor_path_from_table(encoded_path: bytes, path_key: int) -> bytes:
    key = path_key & 0xFF
    return bytes((b ^ key) for b in encoded_path)


def default_path_key(version: int, scheme: str | None = None) -> int:
    # These are fallbacks for naked folder packing.  Extraction/repack uses the
    # recovered key from .ypf_meta.json.
    if scheme in {"swap00", "swap04", "swap10", "identity"}:
        return 0xFF if version >= YPF_VER_1F4 else 0xC0
    if version >= YPF_VER_1F4:
        return 0xC9  # Relirium v500 samples.
    return 0xC0      # ToolForYuris old fallback.


def _candidate_score(raw_name: bytes, key: int) -> int:
    if not raw_name:
        return -1000
    decoded = bytes(b ^ (key & 0xFF) for b in raw_name)
    lower = decoded.lower()
    score = 0
    if any(lower.endswith(ext) for ext in KNOWN_EXTENSIONS):
        score += 20
    if b"\\" in decoded or b"/" in decoded:
        score += 3
    # Penalize ASCII control bytes.  Japanese multi-byte bytes are >= 0x80 and should not be penalized.
    controls = sum(1 for b in decoded if b < 0x20 and b not in (9, 10, 13))
    score -= controls * 5
    # Reward filename-like bytes.
    printable = sum(1 for b in decoded if b >= 0x20 or b >= 0x80)
    score += min(5, printable // 4)
    return score


def guess_path_key(raw_names: list[bytes], version: int) -> int:
    """Recover the per-archive filename XOR key.

    ArcYPF/GARbro stores path bytes as `name_byte ^ key` and guesses `key` from
    the dot before a 3-byte extension.  ToolForYuris v500 packages also fit this
    model because their old expression `byte ^ 0xFF ^ 0x36` is simply key 0xC9.
    """
    votes: Counter[int] = Counter()
    for raw in raw_names:
        if len(raw) < 4:
            continue
        # Most Yu-RIS asset names have a 3-letter extension, so the dot is at -4.
        for pos_weight, pos in ((10, -4), (5, -5), (3, -6)):
            if len(raw) >= abs(pos):
                cand = raw[pos] ^ ord('.')
                score = _candidate_score(raw, cand)
                if score > 0:
                    votes[cand & 0xFF] += score + pos_weight
    if votes:
        return votes.most_common(1)[0][0]
    return default_path_key(version)
