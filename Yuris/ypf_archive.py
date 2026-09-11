"""Yu-Ris resource archive (.ypf) reader and writer.

Merged from the standalone ``yurisypf`` package so the tool ships as flat files.
Section order follows the original dependency order:

  constants -> models -> codec -> hashers -> meta -> op -> archive

Compatibility model:
  * ``path_hash`` follows ToolForYuris: Murmur2 for version >= 0x1DF, CRC32 below.
  * The filename XOR key, path-length table and table layout are *recovered per
    archive* rather than assumed, because the version alone does not determine
    them (a v500 archive can use either the old or the new layout).
  * ``.ypf_meta.json``, written at extract time, is authoritative when repacking.
"""
from __future__ import annotations

import codecs
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple


# --------------------------------------------------------------------------
# Format constants, encoding aliases and path-length tables
# --------------------------------------------------------------------------

YPF_MAGIC = 0x00465059  # b"YPF\0" as little-endian dword
YPF_HEADER_SIZE = 0x20

# Extra bytes read past the declared table length, to survive an archive whose
# file_header_length is rounded down (see YpfArchive._read_file_table).
FILE_TABLE_SLACK = 0x1000

YPF_VER_1D2 = 0x1D2
YPF_VER_1DE = 0x1DE
YPF_VER_1DF = 0x1DF
YPF_VER_1F4 = 0x1F4

# Path text encoding aliases.  The GUI/CLI now uses real Python codec names
# such as cp932/cp949/gbk instead of old language labels.  The old labels are
# still accepted for backward compatibility with scripts and old metadata.
ENCODING_ALIASES = {
    "jap": "cp932",
    "jp": "cp932",
    "shift_jis": "cp932",
    "sjis": "cp932",
    "kor": "cp949",
    "kr": "cp949",
    "uhc": "cp949",
    "chs": "gbk",
    "cn": "gbk",
    "gb2312": "gbk",
    "ansi": "mbcs" if sys.platform.startswith("win") else "cp1252",
}

COMMON_ENCODINGS = (
    "cp932",
    "cp949",
    "gbk",
    "big5",
    "cp1252",
    "utf-8",
    "mbcs" if sys.platform.startswith("win") else "cp1252",
)

# Backward alias for code that imported ENCODINGS from older builds.
ENCODINGS = ENCODING_ALIASES

# Relirium / ToolForYuris v500 length-map recovered from the uploaded executable.
# This is a direct 0..255 mapping used as: real_len = table[encoded_len ^ 0xFF].
LENGTH_TABLE_RELIRIUM_1F4 = bytes([
    0x00, 0x01, 0x02, 0x0A, 0x04, 0x05, 0x35, 0x07, 0x08, 0x0B, 0x03, 0x09, 0x10, 0x13, 0x0E, 0x0F,
    0x0C, 0x18, 0x12, 0x0D, 0x2E, 0x1B, 0x16, 0x17, 0x11, 0x19, 0x1A, 0x15, 0x1E, 0x1D, 0x1C, 0x1F,
    0x23, 0x21, 0x22, 0x20, 0x24, 0x25, 0x29, 0x27, 0x28, 0x26, 0x2A, 0x2B, 0x2F, 0x2D, 0x14, 0x2C,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x06, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
])

# Swap tables from ArcYPF/GARbro. Convert to direct mapping used as above.
SWAP_TABLE_00 = bytes([
    0x03, 0x48, 0x06, 0x35,
    0x0C, 0x10, 0x11, 0x19, 0x1C, 0x1E,
    0x09, 0x0B, 0x0D, 0x13, 0x15, 0x1B, 0x20, 0x23, 0x26, 0x29, 0x2C, 0x2F, 0x2E, 0x32,
])
SWAP_TABLE_04 = bytes([
    0x0C, 0x10, 0x11, 0x19, 0x1C, 0x1E,
    0x09, 0x0B, 0x0D, 0x13, 0x15, 0x1B, 0x20, 0x23, 0x26, 0x29, 0x2C, 0x2F, 0x2E, 0x32,
])
SWAP_TABLE_10 = bytes([
    0x09, 0x0B, 0x0D, 0x13, 0x15, 0x1B, 0x20, 0x23, 0x26, 0x29, 0x2C, 0x2F, 0x2E, 0x32,
])


def _make_swap_length_table(swap_table: bytes) -> bytes:
    table = list(range(0x100))
    for i in range(0, len(swap_table), 2):
        a = swap_table[i]
        b = swap_table[i + 1]
        table[a] = b
        table[b] = a
    return bytes(table)


LENGTH_TABLE_SWAP00 = _make_swap_length_table(SWAP_TABLE_00)
LENGTH_TABLE_SWAP04 = _make_swap_length_table(SWAP_TABLE_04)
LENGTH_TABLE_SWAP10 = _make_swap_length_table(SWAP_TABLE_10)
LENGTH_TABLE_IDENTITY = bytes(range(0x100))

# Backward alias retained for old imports.
LENGTH_TABLE_1F4 = LENGTH_TABLE_RELIRIUM_1F4
LENGTH_TABLE_OLD = LENGTH_TABLE_SWAP00

LENGTH_TABLES = {
    "relirium_1f4": LENGTH_TABLE_RELIRIUM_1F4,
    "swap00": LENGTH_TABLE_SWAP00,
    "swap04": LENGTH_TABLE_SWAP04,
    "swap10": LENGTH_TABLE_SWAP10,
    "identity": LENGTH_TABLE_IDENTITY,
}

# --------------------------------------------------------------------------
# Header, entry and option records
# --------------------------------------------------------------------------

# Games ship unused update slots as a 16-byte "YPD " stub rather than deleting
# them.  Measured: 6 such files across two games.  They are empty by design, so
# reporting them as corrupt is wrong.
YPD_PLACEHOLDER_MAGIC = b"YPD "


class NotAnArchiveError(ValueError):
    """The file is readable, but it is not a YPF archive.

    Carries what the file actually is, so callers can say so instead of
    reporting a corrupt header.  Subclasses ValueError to stay compatible with
    existing handlers.
    """

    def __init__(self, message: str, kind: str = "") -> None:
        super().__init__(message)
        self.kind = kind


class EmptyArchiveError(NotAnArchiveError):
    """An intentionally empty archive slot; there is nothing to extract."""

    def __init__(self, message: str) -> None:
        super().__init__(message, kind="empty update slot")


@dataclass
class YpfHeader:
    magic: int
    version: int
    file_count: int
    file_header_length: int
    reserved: Tuple[int, int, int, int]

    @classmethod
    def from_bytes(cls, data: bytes) -> "YpfHeader":
        if len(data) < YPF_HEADER_SIZE:
            if data[:len(YPD_PLACEHOLDER_MAGIC)] == YPD_PLACEHOLDER_MAGIC:
                raise EmptyArchiveError(
                    "This .ypf is an empty update slot (a 16-byte 'YPD ' placeholder), "
                    "not an archive."
                )
            raise ValueError("File is too small to contain a YPF header.")
        values = struct.unpack("<IIII4I", data[:YPF_HEADER_SIZE])
        return cls(values[0], values[1], values[2], values[3], tuple(values[4:8]))

    def validate(self) -> None:
        if self.magic != YPF_MAGIC:
            raise ValueError("Not a YPF archive or header is broken.")
        if self.file_header_length < YPF_HEADER_SIZE:
            raise ValueError("Invalid YPF header table length.")

    def to_bytes(self) -> bytes:
        return struct.pack("<IIII4I", self.magic, self.version, self.file_count,
                           self.file_header_length, *self.reserved)


@dataclass
class YpfEntry:
    path_hash: int = 0
    path_len: int = 0
    path_bytes: bytes = b""        # real archive path bytes, for example b"cgsysf\\...\\x.ydg"
    stored_path_bytes: bytes = b"" # bytes stored in header table, .ycg may be written as .png
    path_text: str = ""
    file_type: int = 0
    compressed: int = 0
    org_length: int = 0
    comp_length: int = 0
    offset: int = 0
    reserved: int = 0
    extra_header: bytes = b""
    data_hash: int = 0
    real_path: Optional[Path] = None


@dataclass
class ArchiveInfo:
    header: YpfHeader
    entries: list[YpfEntry]
    has_reserved_field: bool
    detected_hash_mode: str = "auto"
    path_key: int = 0
    table_extra_field_size: int = 0
    length_scheme: str = "auto"
    path_hash_mode: str = "auto"


@dataclass
class ExtractOptions:
    ypf_file: Path | str
    output_dir: Path | str = "Output"
    language: str = "cp932"
    verify_hash: bool = False
    hash_mode: str = "auto"
    profile: str = "auto"
    sample_hash_detection: int = 128


@dataclass
class PackOptions:
    input_paths: Sequence[Path | str]
    output_ypf: Path | str
    language: str = "cp932"
    version: Optional[int] = None
    include_root_mode: str = "auto"  # auto/yes/no
    metadata_dir: Optional[Path | str] = None
    hash_mode: str = "auto"
    profile: str = "auto"
    sort_index: bool = True
    compression_level: int = 9
    pack_child_folders: bool = False
    length_scheme: str = "auto"
    path_hash_mode: str = "auto"

# --------------------------------------------------------------------------
# Path encoding, length tables and the filename XOR key
# --------------------------------------------------------------------------

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

# --------------------------------------------------------------------------
# Path and payload hashes (Murmur2 / XXH32 / Adler32 / CRC32)
# --------------------------------------------------------------------------

def u32(n: int) -> int:
    return n & 0xFFFFFFFF


class DataHashMode(str, Enum):
    AUTO = "auto"
    TOOLFORYURIS = "toolforyuris"
    RELIRIUM_V500 = "relirium_v500"
    XXH32 = "xxh32"
    MURMUR2 = "murmur2"
    ADLER32 = "adler32"
    CRC32 = "crc32"


class Profile(str, Enum):
    AUTO = "auto"
    TOOLFORYURIS = "toolforyuris"
    RELIRIUM_V500 = "relirium_v500"


def murmur_hash2_32(data: bytes) -> int:
    """32-bit MurmurHash2 variant used by ToolForYuris for YPF >= 0x1DF."""
    m = 0x5BD1E995
    result = len(data) & 0xFFFFFFFF
    loop_cnt = len(data) // 4

    for i in range(loop_cnt):
        tmp = struct.unpack_from("<I", data, i * 4)[0]
        tmp = u32(tmp * m)
        tmp ^= tmp >> 24
        result = u32(u32(result * m) ^ u32(tmp * m))

    tail = data[loop_cnt * 4:]
    xor_val = 0
    if len(tail) >= 3:
        xor_val += tail[2] << 16
    if len(tail) >= 2:
        xor_val += tail[1] << 8
    if len(tail) >= 1:
        xor_val += tail[0]
    result ^= xor_val
    if tail:
        result = u32(result * m)

    result ^= result >> 13
    result = u32(result * m)
    result ^= result >> 15
    return u32(result)


XXH32_PRIME1 = 0x9E3779B1
XXH32_PRIME2 = 0x85EBCA77
XXH32_PRIME3 = 0xC2B2AE3D
XXH32_PRIME4 = 0x27D4EB2F
XXH32_PRIME5 = 0x165667B1


def _rotl32(value: int, bits: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def xxh32(data: bytes, seed: int = 0) -> int:
    """Dependency-free XXH32(seed=0 compatible by default)."""
    data = bytes(data)
    length = len(data)
    index = 0
    seed &= 0xFFFFFFFF

    if length >= 16:
        v1 = (seed + XXH32_PRIME1 + XXH32_PRIME2) & 0xFFFFFFFF
        v2 = (seed + XXH32_PRIME2) & 0xFFFFFFFF
        v3 = seed
        v4 = (seed - XXH32_PRIME1) & 0xFFFFFFFF
        limit = length - 16
        while index <= limit:
            d1, d2, d3, d4 = struct.unpack_from("<IIII", data, index)
            v1 = (_rotl32((v1 + u32(d1 * XXH32_PRIME2)) & 0xFFFFFFFF, 13) * XXH32_PRIME1) & 0xFFFFFFFF
            v2 = (_rotl32((v2 + u32(d2 * XXH32_PRIME2)) & 0xFFFFFFFF, 13) * XXH32_PRIME1) & 0xFFFFFFFF
            v3 = (_rotl32((v3 + u32(d3 * XXH32_PRIME2)) & 0xFFFFFFFF, 13) * XXH32_PRIME1) & 0xFFFFFFFF
            v4 = (_rotl32((v4 + u32(d4 * XXH32_PRIME2)) & 0xFFFFFFFF, 13) * XXH32_PRIME1) & 0xFFFFFFFF
            index += 16
        result = (_rotl32(v1, 1) + _rotl32(v2, 7) + _rotl32(v3, 12) + _rotl32(v4, 18)) & 0xFFFFFFFF
    else:
        result = (seed + XXH32_PRIME5) & 0xFFFFFFFF

    result = (result + length) & 0xFFFFFFFF

    while index + 4 <= length:
        (chunk,) = struct.unpack_from("<I", data, index)
        result = (_rotl32((result + u32(chunk * XXH32_PRIME3)) & 0xFFFFFFFF, 17) * XXH32_PRIME4) & 0xFFFFFFFF
        index += 4

    while index < length:
        result = (_rotl32((result + u32(data[index] * XXH32_PRIME5)) & 0xFFFFFFFF, 11) * XXH32_PRIME1) & 0xFFFFFFFF
        index += 1

    result ^= result >> 15
    result = u32(result * XXH32_PRIME2)
    result ^= result >> 13
    result = u32(result * XXH32_PRIME3)
    result ^= result >> 16
    return u32(result)


def path_hash(data: bytes, version: int) -> int:
    if version >= YPF_VER_1DF:
        return murmur_hash2_32(data)
    return zlib.crc32(data) & 0xFFFFFFFF


def _normalize_profile(profile: str | Profile) -> Profile:
    if isinstance(profile, Profile):
        return profile
    return Profile(str(profile).lower())


def _normalize_mode_value(mode: str | DataHashMode | None) -> str:
    if mode is None:
        return DataHashMode.AUTO.value
    if isinstance(mode, DataHashMode):
        return mode.value
    text = str(mode).lower()
    if text.startswith("datahashmode."):
        text = text.split(".", 1)[1]
    return text


def default_data_hash_mode(version: int, profile: str | Profile = Profile.AUTO) -> DataHashMode:
    profile = _normalize_profile(profile)
    if profile == Profile.RELIRIUM_V500:
        return DataHashMode.XXH32
    if profile == Profile.TOOLFORYURIS:
        return DataHashMode.TOOLFORYURIS
    # Auto compatibility:
    #   v500 Relirium-style packages validate payloads with XXH32.
    #   v481 ToolForYuris-style packages use Murmur2.
    #   older GARbro/ArcYPF-style packages use Adler32 checksums.
    if version >= YPF_VER_1F4:
        return DataHashMode.XXH32
    if version >= YPF_VER_1DF:
        return DataHashMode.MURMUR2
    return DataHashMode.ADLER32


def normalize_data_hash_mode(mode: str | DataHashMode | None, version: int, profile: str | Profile = Profile.AUTO) -> DataHashMode:
    text = _normalize_mode_value(mode)
    if text == DataHashMode.AUTO.value:
        return default_data_hash_mode(version, profile)
    mode = DataHashMode(text)
    if mode == DataHashMode.RELIRIUM_V500:
        return DataHashMode.XXH32
    return mode


def data_hash(data: bytes, version: int, mode: str | DataHashMode | None = DataHashMode.AUTO,
              profile: str | Profile = Profile.AUTO) -> int:
    effective = normalize_data_hash_mode(mode, version, profile)
    if effective == DataHashMode.XXH32:
        return xxh32(data)
    if effective == DataHashMode.MURMUR2:
        return murmur_hash2_32(data)
    if effective == DataHashMode.ADLER32:
        return zlib.adler32(data) & 0xFFFFFFFF
    if effective == DataHashMode.CRC32:
        return zlib.crc32(data) & 0xFFFFFFFF
    if effective == DataHashMode.TOOLFORYURIS:
        if version >= YPF_VER_1DF:
            return murmur_hash2_32(data)
        if version >= YPF_VER_1D2:
            return zlib.adler32(data) & 0xFFFFFFFF
        return zlib.crc32(data) & 0xFFFFFFFF
    raise ValueError(f"Unsupported data hash mode: {mode}")


def possible_hash_modes(version: int) -> list[DataHashMode]:
    modes = [DataHashMode.XXH32, DataHashMode.MURMUR2, DataHashMode.ADLER32, DataHashMode.CRC32, DataHashMode.TOOLFORYURIS]
    result: list[DataHashMode] = []
    for m in modes:
        if m not in result:
            result.append(m)
    return result


def path_hash_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def path_hash_murmur2(data: bytes) -> int:
    return murmur_hash2_32(data)


def path_hash_by_mode(data: bytes, version: int, mode: str | None = None) -> int:
    text = (mode or "auto").lower()
    if text in ("crc32", "garbro", "arcypf"):
        return path_hash_crc32(data)
    if text in ("murmur2", "toolforyuris", "relirium_v500"):
        return path_hash_murmur2(data)
    return path_hash(data, version)


def detect_path_hash_mode(names: list[bytes], hashes: list[int], version: int) -> str:
    if not names:
        return "murmur2" if version >= YPF_VER_1DF else "crc32"
    modes = ["murmur2", "crc32"]
    scores = {}
    for mode in modes:
        scores[mode] = sum(1 for n, h in zip(names, hashes) if path_hash_by_mode(n, version, mode) == h)
    # Prefer the exact winner; ties keep historical default.
    if scores["crc32"] > scores["murmur2"]:
        return "crc32"
    if scores["murmur2"] > scores["crc32"]:
        return "murmur2"
    return "murmur2" if version >= YPF_VER_1DF else "crc32"

# --------------------------------------------------------------------------
# The .ypf_meta.json sidecar that makes repacking faithful
# --------------------------------------------------------------------------

META_FILENAME = ".ypf_meta.json"
META_FORMAT = "ToolForYuris_Py_YPF_Metadata"
META_SCHEMA_VERSION = 2


def load_metadata(directory: Path) -> dict:
    meta_path = Path(directory) / META_FILENAME
    if not meta_path.is_file():
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_metadata(directory: Path, meta: dict) -> Path:
    path = Path(directory) / META_FILENAME
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def common_parent(paths: Sequence[Path]) -> Optional[Path]:
    if not paths:
        return None
    normalized = []
    for p in paths:
        p = Path(p).resolve()
        normalized.append(str(p if p.is_dir() else p.parent))
    try:
        import os
        return Path(os.path.commonpath(normalized))
    except Exception:
        return None


def find_metadata_for_inputs(input_paths: Sequence[Path], metadata_dir: Optional[Path] = None) -> tuple[dict, Optional[Path]]:
    candidates: list[Path] = []
    if metadata_dir is not None:
        candidates.append(Path(metadata_dir))
    roots = [Path(p).resolve() for p in input_paths]
    if len(roots) == 1 and roots[0].is_dir():
        candidates.append(roots[0])
    cp = common_parent(roots)
    if cp is not None:
        candidates.append(cp)
    for root in roots:
        if root.is_dir():
            candidates.append(root)

    seen: set[str] = set()
    for candidate in candidates:
        try:
            key = str(candidate.resolve())
        except Exception:
            key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        meta = load_metadata(candidate)
        if meta:
            return meta, candidate / META_FILENAME
    return {}, None


def metadata_entry_map(meta: dict) -> dict[str, dict]:
    result: dict[str, dict] = {}
    if not isinstance(meta, dict):
        return result
    for item in meta.get("entries", []):
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if isinstance(path, str):
            result[path.replace("/", "\\").lower()] = item
    return result

# --------------------------------------------------------------------------
# Video files that carry a .ypf name but are not archives
# --------------------------------------------------------------------------
# Some games ship the opening movie as ``op.ypf`` with no YPF container at all:
# the file simply *is* the video.  The container differs per game, so it must be
# identified by magic bytes rather than by name.  Measured: `77` ships MPEG-PS
# (`00 00 01 BA`), Relirium ships WebM (`1A 45 DF A3`, DocType "webm").
# Recognising only MPEG-PS made the WebM one fall through to the archive parser
# and fail with a misleading "Not a YPF archive or header is broken".

MPEG_PS_HEADER = b"\x00\x00\x01\xBA"

# (magic at offset 0, label, extension to use when saving it out)
VIDEO_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"\x00\x00\x01\xBA", "MPEG program stream", ".mpg"),
    (b"\x00\x00\x01\xB3", "MPEG video elementary stream", ".m2v"),
    (b"\x1aE\xdf\xa3", "Matroska/WebM", ".webm"),
    (b"RIFF", "AVI", ".avi"),
    (b"OggS", "Ogg", ".ogv"),
    (b"FLV\x01", "FLV", ".flv"),
    (b"\x30\x26\xb2\x75", "ASF/WMV", ".wmv"),
)
# ISO base media (MP4/MOV) puts a size field first, so the brand sits at offset 4.
ISO_BRAND_OFFSET = 4
ISO_BRANDS = (b"ftyp",)

VIDEO_EXTENSIONS = {
    ".mpg", ".mpeg", ".mpe", ".vob", ".m2v", ".mp4", ".m4v",
    ".mkv", ".avi", ".mov", ".wmv", ".webm", ".ts", ".m2ts", ".ogv", ".flv",
}
MPEG_PS_EXTENSIONS = {".mpg", ".mpeg", ".mpe", ".vob"}


def identify_video(path: os.PathLike | str) -> tuple[str, str] | None:
    """Identify a video container by its magic bytes.

    Returns ``(label, extension)``, or None when the file is not a video this
    tool recognises.  Reads only the first 16 bytes.
    """
    try:
        with Path(path).open("rb") as handle:
            head = handle.read(16)
    except Exception:
        return None
    if len(head) < 8:
        return None
    for magic, label, extension in VIDEO_SIGNATURES:
        if head.startswith(magic):
            # WebM and Matroska share the EBML magic; distinguish by DocType.
            if magic == b"\x1aE\xdf\xa3":
                try:
                    with Path(path).open("rb") as handle:
                        probe = handle.read(256)
                except Exception:
                    probe = head
                if b"webm" in probe:
                    return "WebM", ".webm"
                return "Matroska", ".mkv"
            return label, extension
    if head[ISO_BRAND_OFFSET:ISO_BRAND_OFFSET + 4] in ISO_BRANDS:
        return "MP4/MOV", ".mp4"
    return None


def is_video_container(path: os.PathLike | str) -> bool:
    """True when the file content is a video, whatever it is named."""
    return identify_video(path) is not None


def is_mpeg_ps_file(path: os.PathLike | str) -> bool:
    """True only for a raw MPEG program stream.

    Kept narrow because packing uses it to decide whether a transcode is needed.
    Use ``is_video_container`` to ask "is this a video at all".
    """
    try:
        with Path(path).open("rb") as f:
            return f.read(4) == MPEG_PS_HEADER
    except Exception:
        return False


def is_video_file(path: os.PathLike | str) -> bool:
    path = Path(path)
    if not path.is_file():
        return False
    return path.suffix.lower() in VIDEO_EXTENSIONS or is_video_container(path)


def default_op_extract_output(input_path: os.PathLike | str, output: os.PathLike | str) -> Path:
    src = Path(input_path)
    out = Path(output)
    # When output looks like a file path, use it directly.  GUI normally supplies a folder.
    if out.suffix.lower() in MPEG_PS_EXTENSIONS or out.suffix.lower() in VIDEO_EXTENSIONS:
        return out
    out.mkdir(parents=True, exist_ok=True)
    # Name the output after what the content actually is, so a WebM does not get
    # saved as .mpg and refuse to open in a player.
    identified = identify_video(src)
    extension = identified[1] if identified else ".mpg"
    stem = "op_extracted" if src.stem.lower() == "op" else src.stem
    return out / (stem + extension)


def extract_op(input_ypf: os.PathLike | str, output: os.PathLike | str, log: Callable[[str], None] = print) -> dict:
    src = Path(input_ypf)
    if not src.is_file():
        raise FileNotFoundError(f"OP input not found: {src}")
    identified = identify_video(src)
    if identified is None:
        with src.open("rb") as f:
            head = f.read(8)
        log(f"warning: unrecognised video container, header={head.hex(' ')}")
        label = "unknown"
    else:
        label = identified[0]
        log(f"Video container: {label}")
    dst = default_op_extract_output(src, output)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    size = dst.stat().st_size
    log(f"OP video extracted: {dst} ({size / 1024 / 1024:.1f} MB)")
    return {
        "format": "op_video",
        "container": label,
        "version": None,
        "output": str(dst),
        "size": size,
    }


def _tool_root_candidates() -> list[Path]:
    here = Path(__file__).resolve()
    return [
        here.parent,
        here.parent.parent,
        Path(sys.argv[0]).resolve().parent if sys.argv and sys.argv[0] else Path.cwd(),
        Path.cwd(),
    ]


def find_ffmpeg() -> Optional[str]:
    names = ["ffmpeg.exe", "ffmpeg"] if os.name == "nt" else ["ffmpeg", "ffmpeg.exe"]
    for base in _tool_root_candidates():
        for name in names:
            candidate = base / name
            if candidate.is_file():
                return str(candidate)
    found = shutil.which("ffmpeg")
    if found:
        return found
    try:
        import imageio_ffmpeg  # type: ignore
        exe = imageio_ffmpeg.get_ffmpeg_exe()
        if exe and Path(exe).is_file():
            return str(exe)
    except Exception:
        pass
    return None


def locate_video_input(inputs: Sequence[os.PathLike | str]) -> Path:
    paths = [Path(p) for p in inputs]
    if len(paths) != 1:
        raise ValueError("OP video pack mode needs exactly one input video file or one folder containing a single video.")
    p = paths[0]
    if p.is_file():
        if not is_video_file(p):
            raise ValueError(f"Not a supported video file: {p}")
        return p
    if not p.is_dir():
        raise FileNotFoundError(f"Input not found: {p}")

    preferred_names = [
        "op_extracted.mpg", "op.mpg", "op.mpeg", "op.vob", "op.mp4", "op.mkv", "op.avi", "op.mov"
    ]
    lower_map = {child.name.lower(): child for child in p.iterdir() if child.is_file()}
    for name in preferred_names:
        if name in lower_map:
            return lower_map[name]

    videos = [child for child in p.iterdir() if is_video_file(child)]
    if len(videos) == 1:
        return videos[0]
    if not videos:
        raise ValueError(f"No video file found in folder: {p}")
    raise ValueError(f"Multiple video files found in folder, please select one directly: {p}")


def should_pack_as_op(inputs: Sequence[os.PathLike | str], output_ypf: os.PathLike | str) -> bool:
    out = Path(output_ypf)
    if out.suffix.lower() != ".ypf":
        return False
    try:
        video = locate_video_input(inputs)
    except Exception:
        return False
    # Explicit op.ypf output is always raw OP-video mode.  For dropped video files, this keeps
    # the GUI convenient without exposing a separate OP mode.
    return out.name.lower() == "op.ypf" or video.suffix.lower() in VIDEO_EXTENSIONS


def transcode_to_mpeg1_ps(input_path: os.PathLike | str, output_path: os.PathLike | str,
                          log: Callable[[str], None] = print, ffmpeg_path: Optional[str] = None) -> None:
    ffmpeg = ffmpeg_path or find_ffmpeg()
    if not ffmpeg:
        raise RuntimeError(
            "需要 FFmpeg 才能把非 MPEG-PS 视频转成 Yu-RIS 可读格式。"
            "把 ffmpeg.exe 放到工具同目录，或把 ffmpeg 加入 PATH，或安装 imageio-ffmpeg。"
        )
    src = Path(input_path)
    dst = Path(output_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        ffmpeg, "-y", "-i", str(src),
        "-c:v", "mpeg1video",
        "-b:v", "15000k",
        "-maxrate", "15000k",
        "-bufsize", "2000k",
        "-g", "15",
        "-bf", "2",
        "-s", "1280x720",
        "-r", "30",
        "-pix_fmt", "yuv420p",
        "-c:a", "mp2",
        "-b:a", "128k",
        "-ar", "48000",
        "-ac", "2",
        "-f", "vob",
        str(dst),
    ]
    log(f"OP video transcoding via FFmpeg: {src.name} -> {dst.name}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError("FFmpeg 转码失败：\n" + stderr[-2000:])


def pack_op(inputs: Sequence[os.PathLike | str], output_ypf: os.PathLike | str,
            log: Callable[[str], None] = print) -> dict:
    src = locate_video_input(inputs)
    dst = Path(output_ypf)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if is_mpeg_ps_file(src):
        log("OP input is MPEG Program Stream; copying directly.")
        shutil.copy2(src, dst)
    else:
        log("OP input is not MPEG Program Stream; transcoding to MPEG-1 Program Stream.")
        with tempfile.TemporaryDirectory(prefix="yuris_op_") as td:
            tmp = Path(td) / "op_transcoded.mpg"
            transcode_to_mpeg1_ps(src, tmp, log=log)
            shutil.copy2(tmp, dst)
    size = dst.stat().st_size
    log(f"OP video packed: {dst} ({size / 1024 / 1024:.1f} MB)")
    return {
        "format": "op_mpeg_ps",
        "version": None,
        "output": str(dst),
        "size": size,
    }

# --------------------------------------------------------------------------
# The archive itself: inspect / extract / pack
# --------------------------------------------------------------------------

class YpfArchive:
    """Unified YPF API.

    Public interface:
      - inspect(path, language="cp932") -> ArchiveInfo
      - extract(ExtractOptions(...))
      - pack(PackOptions(...))

    Compatibility model:
      - path_hash follows ToolForYuris: Murmur2 for >=0x1DF, CRC32 for older.
      - data_hash is profile/hash-mode controlled.
      - hash_mode="auto" uses metadata if available; otherwise v500+ defaults to XXH32,
        older versions use the public ToolForYuris rule.
    """

    def __init__(self, log: Optional[Callable[[str], None]] = None) -> None:
        self.log = log or (lambda msg: print(msg))

    def _log(self, msg: str) -> None:
        self.log(msg)

    @staticmethod
    def _read_u32(buf: bytes, offset: int) -> tuple[int, int]:
        if offset + 4 > len(buf):
            raise ValueError("Unexpected end of YPF file table.")
        return struct.unpack_from("<I", buf, offset)[0], offset + 4

    @staticmethod
    def _stored_path_for_header(archive_path_bytes: bytes, file_type: int) -> bytes:
        # ToolForYuris writes .ycg as .png in the header table when type == 0x8.
        if file_type == 0x8 and archive_path_bytes.lower().endswith(b".ycg"):
            return archive_path_bytes[:-4] + b".png"
        return archive_path_bytes

    @staticmethod
    def _default_table_extra_field_size(version: int) -> int:
        # GARbro/ArcYPF default: v>=0x1D9 has one extra u32 before checksum,
        # v0xDE has two extra u32 values, older versions have none.
        if version >= YPF_VER_1DE:
            return 4
        if version == 0xDE:
            return 8
        return 0

    def _parse_table_once(self, table: bytes, header: YpfHeader, lang: str, extra_field_size: int,
                          length_scheme: str) -> tuple[list[YpfEntry], int, int, str]:
        raw_items: list[dict] = []
        off = 0
        for _ in range(header.file_count):
            item: dict = {}
            item["path_hash"], off = self._read_u32(table, off)
            if off >= len(table):
                raise ValueError("Unexpected end of YPF file table while reading path length.")
            encoded_len = table[off]
            off += 1
            path_len = convert_path_length(encoded_len ^ 0xFF, header.version, length_scheme)
            item["path_len"] = path_len
            if path_len <= 0 or off + path_len > len(table):
                raise ValueError("Invalid YPF path length in file table.")
            item["raw_name"] = table[off:off + path_len]
            off += path_len

            if off + 1 + 1 + 4 + 4 + 4 + extra_field_size + 4 > len(table):
                raise ValueError("Unexpected end of YPF file table while reading entry metadata.")
            item["file_type"] = table[off]
            off += 1
            item["compressed"] = table[off]
            off += 1
            item["org_length"], off = self._read_u32(table, off)
            item["comp_length"], off = self._read_u32(table, off)
            item["offset"], off = self._read_u32(table, off)
            item["extra_header"] = table[off:off + extra_field_size]
            off += extra_field_size
            item["data_hash"], off = self._read_u32(table, off)
            raw_items.append(item)

        # The walk must land on the declared table end.  This exactness is what
        # tells a correct layout candidate from a wrong one, so it stays strict —
        # but the buffer now carries slack past the declared length (some archives
        # round file_header_length down), so compare against the declared size and
        # allow only an overshoot that stays inside the slack we deliberately read.
        declared = header.file_header_length - YPF_HEADER_SIZE
        overshoot = off - declared
        if overshoot < 0 or overshoot > FILE_TABLE_SLACK:
            raise ValueError(
                f"File table parse did not land on the table end: used {off}, declared {declared}."
            )

        path_key = guess_path_key([x["raw_name"] for x in raw_items], header.version)
        entries: list[YpfEntry] = []
        decoded_names_for_hash: list[bytes] = []
        stored_hashes: list[int] = []
        for item in raw_items:
            entry = YpfEntry()
            entry.path_hash = item["path_hash"]
            entry.path_len = item["path_len"]
            stored_path = unxor_path_from_table(item["raw_name"], path_key)
            entry.stored_path_bytes = stored_path
            raw_path = stored_path
            path_text = decode_archive_path(raw_path, lang)

            entry.file_type = item["file_type"]
            if entry.file_type == 0x8 and path_text.lower().endswith(".png"):
                path_text = path_text[:-4] + ".ycg"
                raw_path = raw_path[:-4] + b".ycg"
            entry.path_text = path_text
            entry.path_bytes = raw_path
            entry.compressed = item["compressed"]
            entry.org_length = item["org_length"]
            entry.comp_length = item["comp_length"]
            entry.offset = item["offset"]
            entry.extra_header = item["extra_header"]
            entry.reserved = struct.unpack("<I", entry.extra_header[:4])[0] if len(entry.extra_header) >= 4 else 0
            entry.data_hash = item["data_hash"]
            entries.append(entry)
            decoded_names_for_hash.append(stored_path)
            stored_hashes.append(entry.path_hash)

        path_hash_mode = detect_path_hash_mode(decoded_names_for_hash, stored_hashes, header.version)
        return entries, path_key, len([1 for n, h in zip(decoded_names_for_hash, stored_hashes)
                                      if path_hash_by_mode(n, header.version, path_hash_mode) == h]), path_hash_mode

    def _parse_table(self, table: bytes, header: YpfHeader, lang: str) -> tuple[list[YpfEntry], bool, int, int, str, str]:
        # Try every known length table and every supported table-tail layout.
        # Version alone is not enough: the uploaded se(1).ypf is v500 but uses
        # the ArcYPF/GARbro swap00 table, extra_size=0, key=0xFF, CRC32 names,
        # while Relirium v500 uses the custom length map, extra_size=4, key=0xC9.
        preferred_extra = self._default_table_extra_field_size(header.version)
        extra_candidates: list[int] = []
        for value in (preferred_extra, 0, 4, 8):
            if value not in extra_candidates:
                extra_candidates.append(value)

        scheme_candidates: list[str] = []
        for name in (default_length_scheme(header.version), "relirium_1f4", "swap00", "swap04", "swap10", "identity"):
            if name in LENGTH_TABLES and name not in scheme_candidates:
                scheme_candidates.append(name)

        best = None
        errors: list[str] = []
        for scheme_name in scheme_candidates:
            for extra_size in extra_candidates:
                try:
                    entries, path_key, path_hash_hits, path_hash_mode = self._parse_table_once(
                        table, header, lang, extra_size, scheme_name
                    )
                    # Basic placement validation.  Bad candidates can parse structurally but point
                    # outside the file or produce impossible compression flags.
                    bad_flags = sum(1 for e in entries if e.compressed not in (0, 1))
                    score = path_hash_hits * 1000 - bad_flags * 100
                    candidate = (score, path_hash_hits, scheme_name, extra_size, entries, path_key, path_hash_mode)
                    if best is None or candidate[:2] > best[:2]:
                        best = candidate
                except Exception as exc:
                    errors.append(f"length={scheme_name}, extra_field_size={extra_size}: {exc}")

        if best is None:
            raise ValueError("Could not parse YPF file table. " + " | ".join(errors))

        score, path_hash_hits, scheme_name, extra_size, entries, path_key, path_hash_mode = best
        self._log(
            f"Header table layout: length={scheme_name}, extra_field_size={extra_size}, "
            f"path_key=0x{path_key:02X}, path_hash={path_hash_mode}, matches={path_hash_hits}/{len(entries)}"
        )
        return entries, extra_size != 0, extra_size, path_key, scheme_name, path_hash_mode

    def inspect(self, ypf_file: os.PathLike | str, language: str = "cp932", detect_hash: bool = True,
                sample_hash_detection: int = 128) -> ArchiveInfo:
        ypf_path = Path(ypf_file)
        if not ypf_path.is_file():
            raise FileNotFoundError(f"YPF file not found: {ypf_path}")
        # Say what the file actually is instead of reporting a broken header.
        video = identify_video(ypf_path)
        if video is not None:
            raise NotAnArchiveError(
                f"This .ypf is not an archive: it is a {video[0]} video file.", video[0]
            )
        with ypf_path.open("rb") as f:
            header = YpfHeader.from_bytes(f.read(YPF_HEADER_SIZE))
            header.validate()
            table = self._read_file_table(f, header)
            entries, has_reserved, extra_size, path_key, length_scheme, path_hash_mode = self._parse_table(table, header, language)
            info = ArchiveInfo(header=header, entries=entries, has_reserved_field=has_reserved,
                               path_key=path_key, table_extra_field_size=extra_size,
                               length_scheme=length_scheme, path_hash_mode=path_hash_mode)
            if detect_hash:
                info.detected_hash_mode = self.detect_data_hash_mode(f, header.version, entries, sample_hash_detection)
            return info

    def detect_data_hash_mode(self, fp, version: int, entries: Sequence[YpfEntry], sample_limit: int = 128) -> str:
        """Infer the payload hash mode from stored table hashes.

        This is used only for compatibility metadata and verification.  It samples data as stored
        in the archive (compressed bytes when compressed flag is set), which is the value the
        YPF table hashes.
        """
        if not entries:
            return default_data_hash_mode(version).value
        counters = {m.value: 0 for m in possible_hash_modes(version)}
        tested = 0
        for entry in list(entries)[:max(1, sample_limit)]:
            try:
                fp.seek(entry.offset)
                payload = fp.read(entry.comp_length)
                if len(payload) != entry.comp_length:
                    continue
            except Exception:
                continue
            for mode in possible_hash_modes(version):
                try:
                    if data_hash(payload, version, mode=mode) == entry.data_hash:
                        counters[mode.value] += 1
                except Exception:
                    pass
            tested += 1
        if tested == 0:
            return default_data_hash_mode(version).value
        # Prefer explicit algorithms over the umbrella ToolForYuris mode when tied.
        preference = [DataHashMode.XXH32.value, DataHashMode.MURMUR2.value, DataHashMode.ADLER32.value,
                      DataHashMode.CRC32.value, DataHashMode.TOOLFORYURIS.value]
        best = max(preference, key=lambda m: (counters.get(m, 0), -preference.index(m)))
        if counters.get(best, 0) == 0:
            return default_data_hash_mode(version).value
        return best

    @staticmethod
    def safe_output_path(output_dir: Path, archive_path: str) -> Path:
        normalized = archive_path.replace("/", "\\")
        parts: list[str] = []
        for part in normalized.split("\\"):
            part = part.strip()
            if not part or part == ".":
                continue
            if part == "..":
                raise ValueError(f"Unsafe path in archive: {archive_path!r}")
            part = part.replace(":", "_")
            parts.append(part)
        if not parts:
            raise ValueError(f"Empty path in archive: {archive_path!r}")
        out = output_dir.joinpath(*parts)
        try:
            out.resolve().relative_to(output_dir.resolve())
        except Exception as exc:
            raise ValueError(f"Unsafe path in archive: {archive_path!r}") from exc
        return out

    @staticmethod
    def _read_file_table(handle, header: YpfHeader) -> bytes:
        """Read the entry table, tolerating an understated header length.

        ``file_header_length`` is normally exact, but at least one shipped archive
        rounds it down (measured: v292 update4.ypf declares 0x10030 while the
        table really ends 32 bytes later, so the final entry got truncated and the
        whole archive was rejected).  Reading a slack margin lets the parser walk
        the real entry count; the table walk itself stops at the declared count,
        so extra bytes are simply never consumed.
        """
        declared = header.file_header_length - YPF_HEADER_SIZE
        if declared < 0:
            raise ValueError("Invalid YPF header table length.")
        table = handle.read(declared + FILE_TABLE_SLACK)
        if len(table) < declared:
            raise ValueError("YPF file table is truncated.")
        return table

    def extract(self, options: ExtractOptions | os.PathLike | str, output_dir: os.PathLike | str = "Output",
                lang: str = "cp932", verify_hash: bool = False) -> None:
        # Backward-compatible shorthand: extract("a.ypf", "out", lang="cp932").
        if not isinstance(options, ExtractOptions):
            options = ExtractOptions(options, output_dir, lang, verify_hash)
        ypf_path = Path(options.ypf_file)
        out_dir = Path(options.output_dir)
        if not ypf_path.is_file():
            raise FileNotFoundError(f"YPF file not found: {ypf_path}")

        video = identify_video(ypf_path)
        if video is not None:
            self._log(f"Not an archive: this .ypf is a {video[0]} video; copying it out as-is.")
            return extract_op(ypf_path, out_dir, log=self._log)

        with ypf_path.open("rb") as f:
            header = YpfHeader.from_bytes(f.read(YPF_HEADER_SIZE))
            header.validate()
            table = self._read_file_table(f, header)

            self._log(f"YPF extracting: version {header.version}, files {header.file_count}")
            entries, has_reserved, extra_size, path_key, length_scheme, path_hash_mode = self._parse_table(table, header, options.language)
            detected_hash_mode = self.detect_data_hash_mode(f, header.version, entries, options.sample_hash_detection)
            effective_hash_mode = detected_hash_mode if options.hash_mode == "auto" else options.hash_mode
            self._log(f"Data hash mode: {effective_hash_mode} (detected: {detected_hash_mode})")

            entries_by_offset = sorted(entries, key=lambda e: e.offset)
            out_dir.mkdir(parents=True, exist_ok=True)
            meta_entries: list[dict] = []
            meta = {
                "format": META_FORMAT,
                "schema_version": META_SCHEMA_VERSION,
                "version": header.version,
                "file_count": header.file_count,
                "language": options.language,
                "reserved": list(header.reserved),
                "table_has_reserved_field": has_reserved,
                "table_extra_field_size": extra_size,
                "path_key": path_key,
                "length_scheme": length_scheme,
                "path_hash_mode": path_hash_mode,
                "data_hash_mode": effective_hash_mode,
                "detected_data_hash_mode": detected_hash_mode,
                "entries": meta_entries,
            }

            for idx, entry in enumerate(entries_by_offset, 1):
                self._log(f"[{idx}/{len(entries_by_offset)}] {entry.path_text}  type={entry.file_type} size=0x{entry.comp_length:08X} offset=0x{entry.offset:08X}")
                f.seek(entry.offset)
                comp_data = f.read(entry.comp_length)
                if len(comp_data) != entry.comp_length:
                    raise ValueError(f"Compressed/stored data is truncated for {entry.path_text}")

                if options.verify_hash:
                    actual = data_hash(comp_data, header.version, mode=effective_hash_mode, profile=options.profile)
                    if actual != entry.data_hash:
                        self._log(f"  warning: hash mismatch stored=0x{entry.data_hash:08X} actual=0x{actual:08X}")

                if entry.compressed:
                    try:
                        out_data = zlib.decompress(comp_data)
                    except zlib.error as exc:
                        raise ValueError(f"zlib decompress failed for {entry.path_text}: {exc}") from exc
                    if len(out_data) != entry.org_length:
                        self._log(f"  warning: decompressed length {len(out_data)} != header original length {entry.org_length}")
                else:
                    out_data = comp_data

                out_file = self.safe_output_path(out_dir, entry.path_text)
                out_file.parent.mkdir(parents=True, exist_ok=True)
                out_file.write_bytes(out_data)
                meta_entries.append({
                    "path": entry.path_text,
                    "path_raw_hex": entry.path_bytes.hex(),
                    "stored_path_raw_hex": entry.stored_path_bytes.hex(),
                    "path_hash": entry.path_hash,
                    "type": entry.file_type,
                    "compressed": entry.compressed,
                    "reserved": entry.reserved,
                    "extra_header_hex": entry.extra_header.hex(),
                    "org_length": entry.org_length,
                    "comp_length": entry.comp_length,
                    "data_hash": entry.data_hash,
                    "extracted_sha256": hashlib.sha256(out_data).hexdigest(),
                })

            meta_path = save_metadata(out_dir, meta)
            self._log(f"Metadata written: {meta_path}")
        self._log("YPF unpack complete.")
        return meta

    @staticmethod
    def archive_path_for_file(file_path: Path, root_dir: Path, include_root_mode: str) -> str:
        root_dir = root_dir.resolve()
        file_path = file_path.resolve()
        if include_root_mode == "yes":
            rel = Path(root_dir.name) / file_path.relative_to(root_dir)
        elif include_root_mode == "no":
            rel = file_path.relative_to(root_dir)
        elif include_root_mode == "auto":
            if root_dir.name.lower() == "output":
                rel = file_path.relative_to(root_dir)
            else:
                rel = Path(root_dir.name) / file_path.relative_to(root_dir)
        else:
            raise ValueError("include_root_mode must be auto, yes, or no.")
        return str(rel).replace("/", "\\")

    @staticmethod
    def archive_path_for_standalone_file(file_path: Path) -> str:
        return file_path.name.replace("/", "\\")

    @staticmethod
    def type_and_compression(path_for_type: str) -> tuple[int, int]:
        lower = path_for_type.lower()
        if lower.endswith(".txt") or lower.endswith(".ybn"):
            return 0x0, 0x1
        if lower.endswith(".bmp"):
            return 0x1, 0x1
        if lower.endswith(".png"):
            return 0x2, 0x0
        if lower.endswith(".jpg") or lower.endswith(".jpeg"):
            return 0x3, 0x1
        if lower.endswith(".ydg"):
            return 0x5, 0x0
        if lower.endswith(".wav"):
            return 0x5, 0x1
        if lower.endswith(".ogg"):
            return 0x6, 0x0
        if lower.endswith(".psd"):
            return 0x7, 0x0
        if lower.endswith(".ycg"):
            return 0x8, 0x0
        if lower.endswith(".psb"):
            return 0x9, 0x0
        if lower.endswith(".webp"):
            return 0xA, 0x0
        return 0x0, 0x0

    def collect_files_multi(self, input_paths: Sequence[Path], language: str, include_root_mode: str) -> list[YpfEntry]:
        roots = [Path(p).resolve() for p in input_paths]
        if not roots:
            raise ValueError("No input folders/files were provided.")
        if include_root_mode == "auto" and len(roots) > 1:
            include_root_mode = "yes"

        entries: list[YpfEntry] = []
        seen_archive_paths: dict[str, Path] = {}

        def add_entry(real_path: Path, archive_text: str) -> None:
            if real_path.name == META_FILENAME:
                return
            archive_text = archive_text.replace("/", "\\")
            archive_bytes = encode_archive_path(archive_text, language)
            if len(archive_bytes) > 0xFF:
                raise ValueError(f"Archive path is too long for YPF: {archive_text}")
            if b"?" in archive_bytes and "?" not in archive_text:
                self._log(f"warning: path has characters not representable in selected code page: {archive_text}")
            key = archive_text.lower()
            if key in seen_archive_paths:
                raise ValueError(
                    "Duplicate archive path after merging inputs: "
                    f"{archive_text}\n  first: {seen_archive_paths[key]}\n  second: {real_path}"
                )
            seen_archive_paths[key] = real_path
            entries.append(YpfEntry(path_len=len(archive_bytes), path_bytes=archive_bytes,
                                    stored_path_bytes=archive_bytes, path_text=archive_text, real_path=real_path))

        for root in roots:
            if root.is_dir():
                for dirpath, _dirnames, filenames in os.walk(root):
                    for name in filenames:
                        real_path = Path(dirpath) / name
                        archive_text = self.archive_path_for_file(real_path, root, include_root_mode)
                        add_entry(real_path, archive_text)
            elif root.is_file():
                add_entry(root, self.archive_path_for_standalone_file(root))
            else:
                raise FileNotFoundError(f"Input path not found: {root}")
        return entries

    @staticmethod
    def child_folders(paths: Sequence[Path | str]) -> list[Path]:
        expanded: list[Path] = []
        for raw in paths:
            root = Path(raw)
            if not root.is_dir():
                raise NotADirectoryError(f"Child-folder mode needs a folder input: {root}")
            for child in root.iterdir():
                if child.is_dir():
                    expanded.append(child)
        if not expanded:
            raise ValueError("No child folders were found under the selected input folder(s).")
        return expanded

    @staticmethod
    def entry_header_size(entry: YpfEntry, version: int, extra_field_size: int = 0) -> int:
        return 4 + 1 + len(entry.stored_path_bytes or entry.path_bytes) + 1 + 1 + 4 + 4 + 4 + extra_field_size + 4

    def _resolve_effective_include_root(self, roots: Sequence[Path], include_root_mode: str, has_meta: bool) -> str:
        if include_root_mode != "auto":
            return include_root_mode
        if len(roots) > 1:
            return "yes"
        if has_meta:
            return "no"
        return "auto"

    def pack(self, options: PackOptions | os.PathLike | str, output_ypf: os.PathLike | str | None = None,
             lang: str = "cp932", version: Optional[int] = None, include_root_mode: str = "auto") -> None:
        # Backward-compatible shorthand: pack("folder", "out.ypf", lang="cp932", version=500).
        if not isinstance(options, PackOptions):
            if output_ypf is None:
                raise ValueError("output_ypf is required when using shorthand pack().")
            options = PackOptions([options], output_ypf, language=lang, version=version, include_root_mode=include_root_mode)

        if should_pack_as_op(options.input_paths, options.output_ypf):
            self._log("Detected OP-video pack request; writing raw MPEG Program Stream .ypf.")
            return pack_op(options.input_paths, options.output_ypf, log=self._log)

        roots = [Path(p) for p in options.input_paths]
        if options.pack_child_folders:
            roots = self.child_folders(roots)
        if not roots:
            raise ValueError("No input folders/files were provided.")
        for root in roots:
            if not root.exists():
                raise FileNotFoundError(f"Input path not found: {root}")

        out_path = Path(options.output_ypf)
        meta, meta_path = find_metadata_for_inputs(
            roots,
            Path(options.metadata_dir) if options.metadata_dir is not None else None,
        )
        version_eff = options.version
        if version_eff is None:
            version_eff = int(meta.get("version", 481)) if isinstance(meta, dict) else 481

        effective_include_root = self._resolve_effective_include_root(roots, options.include_root_mode, bool(meta))
        meta_entries = metadata_entry_map(meta)
        entries = self.collect_files_multi(roots, options.language, effective_include_root)

        # Internal compatibility detection.  GUI intentionally does not expose these knobs.
        # Metadata is authoritative; naked folder packing falls back to a conservative
        # heuristic based on version and top-level directory names.
        archive_tops = {e.path_text.replace("/", "\\").split("\\", 1)[0].lower() for e in entries}

        if getattr(options, "length_scheme", "auto") != "auto":
            effective_length_scheme = options.length_scheme
        elif isinstance(meta, dict) and meta.get("length_scheme"):
            effective_length_scheme = str(meta.get("length_scheme"))
        elif version_eff >= YPF_VER_1F4 and ("se" in archive_tops or "sysse" in archive_tops):
            effective_length_scheme = "swap00"
        else:
            effective_length_scheme = default_length_scheme(version_eff)

        if isinstance(meta, dict) and meta.get("table_extra_field_size") is not None:
            table_extra_size = int(meta.get("table_extra_field_size", 0))
        elif version_eff >= YPF_VER_1F4 and effective_length_scheme in {"swap00", "swap04", "swap10", "identity"}:
            table_extra_size = 0
        else:
            table_extra_size = self._default_table_extra_field_size(version_eff)
        table_has_reserved = table_extra_size != 0

        if isinstance(meta, dict) and meta.get("path_key") is not None:
            path_key = int(meta.get("path_key", default_path_key(version_eff, effective_length_scheme))) & 0xFF
        else:
            path_key = default_path_key(version_eff, effective_length_scheme)

        if getattr(options, "path_hash_mode", "auto") != "auto":
            effective_path_hash_mode = options.path_hash_mode
        elif isinstance(meta, dict) and meta.get("path_hash_mode"):
            effective_path_hash_mode = str(meta.get("path_hash_mode"))
        elif version_eff >= YPF_VER_1F4 and effective_length_scheme in {"swap00", "swap04", "swap10", "identity"}:
            effective_path_hash_mode = "crc32"
        else:
            effective_path_hash_mode = "murmur2" if version_eff >= YPF_VER_1DF else "crc32"

        # Select data-hash mode: explicit option > metadata > inferred layout > profile/default.
        if options.hash_mode == "auto" and isinstance(meta, dict) and meta.get("data_hash_mode"):
            effective_hash_mode = str(meta.get("data_hash_mode"))
        elif options.hash_mode == "auto" and version_eff >= YPF_VER_1F4 and effective_length_scheme in {"swap00", "swap04", "swap10", "identity"}:
            effective_hash_mode = "adler32"
        else:
            effective_hash_mode = normalize_data_hash_mode(options.hash_mode, version_eff, options.profile).value

        for entry in entries:
            meta_item = meta_entries.get(entry.path_text.replace("/", "\\").lower())
            if meta_item:
                entry.file_type = int(meta_item.get("type", 0)) & 0xFF
                entry.compressed = int(meta_item.get("compressed", 0)) & 0xFF
                entry.reserved = int(meta_item.get("reserved", 0)) & 0xFFFFFFFF
                extra_hex = str(meta_item.get("extra_header_hex", ""))
                try:
                    entry.extra_header = bytes.fromhex(extra_hex) if extra_hex else b""
                except ValueError:
                    entry.extra_header = b""
            else:
                entry.file_type, entry.compressed = self.type_and_compression(entry.path_text)
            entry.stored_path_bytes = self._stored_path_for_header(entry.path_bytes, entry.file_type)
            entry.path_len = len(entry.stored_path_bytes)
            entry.path_hash = path_hash_by_mode(entry.stored_path_bytes, version_eff, effective_path_hash_mode)
            if len(entry.extra_header) < table_extra_size:
                if len(entry.extra_header) >= 4:
                    entry.extra_header = entry.extra_header[:table_extra_size].ljust(table_extra_size, b"\x00")
                elif table_extra_size >= 4:
                    entry.extra_header = struct.pack("<I", entry.reserved) + b"\x00" * (table_extra_size - 4)
                else:
                    entry.extra_header = b"\x00" * table_extra_size
            elif len(entry.extra_header) > table_extra_size:
                entry.extra_header = entry.extra_header[:table_extra_size]

        if options.sort_index:
            entries.sort(key=lambda e: (e.path_hash, e.stored_path_bytes))

        header_len = YPF_HEADER_SIZE + sum(self.entry_header_size(e, version_eff, table_extra_size) for e in entries)
        if isinstance(meta, dict) and isinstance(meta.get("reserved"), list):
            reserved_raw = list(meta.get("reserved", []))
        else:
            reserved_raw = []
        reserved = tuple(int(x) for x in (reserved_raw + [0, 0, 0, 0])[:4])
        header = YpfHeader(YPF_MAGIC, version_eff, len(entries), header_len, reserved)  # type: ignore[arg-type]

        if out_path.exists():
            out_path.unlink()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if meta_path:
            self._log(f"Using metadata: {meta_path}")
            self._log(f"  version {version_eff}, entries with saved type/compression {len(meta_entries)}")
        self._log(f"Input roots: {len(roots)}")
        for root in roots:
            self._log(f"  + {root}")
        self._log(f"Archive root mode: {effective_include_root}")
        self._log(f"Length scheme: {effective_length_scheme}")
        self._log(f"Path key: 0x{path_key:02X}")
        self._log(f"Path hash mode: {effective_path_hash_mode}")
        self._log(f"Data hash mode: {effective_hash_mode}")
        self._log(f"Index order: {'sorted by path_hash' if options.sort_index else 'input/filesystem order'}")
        self._log(f"YPF repacking: version {version_eff}, files {len(entries)}")

        with out_path.open("w+b") as out:
            out.write(header.to_bytes())
            out.seek(header.file_header_length)

            accum_offset = header.file_header_length
            for idx, entry in enumerate(entries, 1):
                if entry.real_path is None:
                    raise ValueError("Internal error: entry.real_path missing.")
                entry.offset = accum_offset
                org_data = entry.real_path.read_bytes()
                entry.org_length = len(org_data)
                if entry.compressed:
                    self._log(f"[{idx}/{len(entries)}] {entry.path_text}  type={entry.file_type} compressing...")
                    comp_data = zlib.compress(org_data, level=options.compression_level)
                else:
                    self._log(f"[{idx}/{len(entries)}] {entry.path_text}  type={entry.file_type}")
                    comp_data = org_data
                entry.comp_length = len(comp_data)

                saved_hash_used = False
                meta_item = meta_entries.get(entry.path_text.replace("/", "\\").lower())
                # Preserve stored hashes for unchanged extracted files.  This keeps old variants safe
                # even if their exact algorithm is not known yet.
                if meta_item and not entry.compressed and "data_hash" in meta_item:
                    same_size = (int(meta_item.get("org_length", -1)) == entry.org_length and
                                 int(meta_item.get("comp_length", -1)) == entry.comp_length)
                    saved_sha = meta_item.get("extracted_sha256")
                    same_sha = True
                    if saved_sha:
                        same_sha = hashlib.sha256(org_data).hexdigest().lower() == str(saved_sha).lower()
                    if same_size and same_sha:
                        entry.data_hash = int(meta_item.get("data_hash", 0)) & 0xFFFFFFFF
                        saved_hash_used = True
                if not saved_hash_used:
                    entry.data_hash = data_hash(comp_data, version_eff, mode=effective_hash_mode, profile=options.profile)

                out.write(comp_data)
                out.write(b"\x00\x00\x00\x00")
                accum_offset += entry.comp_length + 4

            self._log("YPF header table writing...")
            table = bytearray()
            for entry in entries:
                stored_path = entry.stored_path_bytes or self._stored_path_for_header(entry.path_bytes, entry.file_type)
                table += struct.pack("<I", entry.path_hash)
                table.append(encode_path_length(len(stored_path), version_eff, effective_length_scheme) ^ 0xFF)
                table += xor_path_for_table(stored_path, path_key)
                table.append(entry.file_type & 0xFF)
                table.append(entry.compressed & 0xFF)
                table += struct.pack("<III", entry.org_length, entry.comp_length, entry.offset)
                if table_extra_size:
                    table += (entry.extra_header or b"\x00" * table_extra_size)[:table_extra_size].ljust(table_extra_size, b"\x00")
                table += struct.pack("<I", entry.data_hash)

            if len(table) != header.file_header_length - YPF_HEADER_SIZE:
                raise ValueError("Internal error: generated header table size mismatch.")
            out.seek(YPF_HEADER_SIZE)
            out.write(table)

        self._log("YPF repack complete.")
        return {"format": "ypf", "version": version_eff, "output": str(out_path), "file_count": len(entries)}
