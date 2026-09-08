# -*- coding: utf-8 -*-
from __future__ import annotations

import struct
import zlib
from enum import Enum
from typing import Callable, Iterable, Optional

from .constants import YPF_VER_1D2, YPF_VER_1DF, YPF_VER_1F4


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
