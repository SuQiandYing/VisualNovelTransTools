# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
from pathlib import Path

from .archive import YpfArchive
from .constants import COMMON_ENCODINGS
from .models import ExtractOptions, PackOptions
from .op import is_mpeg_ps_file


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ToolForYuris/YU-RIS YPF Python toolkit")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    sub = parser.add_subparsers(dest="command")

    ins = sub.add_parser("info", help="Show archive header and auto-detected info")
    ins.add_argument("ypf_file")
    ins.add_argument("-e", "--encoding", "-l", "--language", dest="language", default="cp932", help="Path text encoding, e.g. cp932/cp949/gbk/big5/utf-8. Old labels jap/kor/chs still work.")
    ins.add_argument("--sample-hash-detection", type=int, default=128)

    ex = sub.add_parser("extract", help="Extract a .ypf archive; OP raw video .ypf is copied as .mpg")
    ex.add_argument("ypf_file")
    ex.add_argument("-o", "--output", default="Output")
    ex.add_argument("-e", "--encoding", "-l", "--language", dest="language", default="cp932", help="Path text encoding, e.g. cp932/cp949/gbk/big5/utf-8. Old labels jap/kor/chs still work.")
    ex.add_argument("--verify-hash", action="store_true")
    ex.add_argument("--sample-hash-detection", type=int, default=128)

    pk = sub.add_parser("pack", help="Pack folders/files into .ypf; video input auto-packs raw OP .ypf")
    pk.add_argument("input", help="Input folder/file. With --from-children, immediate child folders are packed as roots.")
    pk.add_argument("output_ypf")
    pk.add_argument("-a", "--add", action="append", default=[], help="Add another input folder/file to the same YPF. Can be repeated.")
    pk.add_argument("--from-children", action="store_true", help="Pack immediate child folders under input/--add folders as multiple roots.")
    pk.add_argument("-e", "--encoding", "-l", "--language", dest="language", default="cp932", help="Path text encoding, e.g. cp932/cp949/gbk/big5/utf-8. Old labels jap/kor/chs still work.")
    pk.add_argument("-v", "--version", default="auto", help="Version number, e.g. 481, 500, 0x1F4, or auto.")
    pk.add_argument("--include-root", default="auto", choices=["auto", "yes", "no"], help="Whether to include selected folder name in archive paths.")
    pk.add_argument("--metadata-dir", default=None, help="Directory containing .ypf_meta.json.")
    pk.add_argument("--no-sort-index", action="store_true", help="Do not sort file table by path_hash. Not recommended for Yu-RIS.")
    pk.add_argument("--compression-level", type=int, default=9, choices=list(range(10)))

    return parser


def parse_version(text: str) -> int | None:
    if text is None or str(text).strip().lower() in ("", "auto", "op"):
        return None
    return int(str(text), 0)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.gui or not args.command:
        from .gui import run_gui
        run_gui()
        return 0

    ypf = YpfArchive()
    if args.command == "info":
        p = Path(args.ypf_file)
        if is_mpeg_ps_file(p):
            print("format:     OP raw MPEG Program Stream video")
            print(f"size:       {p.stat().st_size}")
            return 0
        info = ypf.inspect(args.ypf_file, language=args.language, detect_hash=True,
                           sample_hash_detection=args.sample_hash_detection)
        print(f"magic:      0x{info.header.magic:08X}")
        print(f"version:    {info.header.version} / 0x{info.header.version:X}")
        print(f"files:      {info.header.file_count}")
        print(f"header_len: {info.header.file_header_length}")
        print(f"reserved:   {list(info.header.reserved)}")
        print(f"table extra field size: {info.table_extra_field_size}")
        print(f"length scheme: {info.length_scheme}")
        print(f"path key:   0x{info.path_key:02X}")
        print(f"path_hash_mode detected: {info.path_hash_mode}")
        print(f"reserved field in table: {info.has_reserved_field}")
        print(f"data_hash_mode detected: {info.detected_hash_mode}")
        return 0

    if args.command == "extract":
        ypf.extract(ExtractOptions(
            ypf_file=args.ypf_file,
            output_dir=args.output,
            language=args.language,
            verify_hash=args.verify_hash,
            sample_hash_detection=args.sample_hash_detection,
        ))
        return 0

    if args.command == "pack":
        input_paths = [args.input] + list(args.add or [])
        ypf.pack(PackOptions(
            input_paths=input_paths,
            output_ypf=args.output_ypf,
            language=args.language,
            version=parse_version(args.version),
            include_root_mode=args.include_root,
            metadata_dir=args.metadata_dir,
            sort_index=not args.no_sort_index,
            compression_level=args.compression_level,
            pack_child_folders=args.from_children,
        ))
        return 0

    parser.error("Unknown command")
    return 2
