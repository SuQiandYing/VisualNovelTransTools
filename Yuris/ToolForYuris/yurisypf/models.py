# -*- coding: utf-8 -*-
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple

from .constants import YPF_HEADER_SIZE, YPF_MAGIC


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
