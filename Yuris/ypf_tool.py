"""Command line for Yu-Ris resource archives (.ypf).

The GUI's 「解包封包」 tab calls the same functions in ``ypf_archive.py``, so a job
run here and a job run there produce the same output.

    python ypf_tool.py info    "D:\\Game\\pac\\cg.ypf"
    python ypf_tool.py extract "D:\\Game\\pac\\cg.ypf" -o cg_extract
    python ypf_tool.py extract "D:\\Game\\pac"         -o all_extract
    python ypf_tool.py pack    cg_extract cg_new.ypf --metadata-dir cg_extract
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from ypf_archive import (
    COMMON_ENCODINGS,
    EmptyArchiveError,
    ExtractOptions,
    PackOptions,
    YpfArchive,
    identify_video,
)


def parse_version(text: str | None) -> int | None:
    """``auto`` means "take it from the metadata"; otherwise accept 481 or 0x1F4."""
    if text is None or str(text).strip().lower() in ("", "auto", "op"):
        return None
    return int(str(text), 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Yu-Ris .ypf archive tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n", 2)[2],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encoding_help = (
        f"path text encoding (default cp932); common values: {', '.join(COMMON_ENCODINGS[:5])}"
    )

    info = subparsers.add_parser("info", help="show header and auto-detected layout")
    info.add_argument("archive", type=pathlib.Path)
    info.add_argument("-e", "--encoding", default="cp932", help=encoding_help)
    info.add_argument("--sample", type=int, default=128,
                      help="how many entries to sample when detecting the hash mode")

    extract = subparsers.add_parser(
        "extract", help="extract one archive, or every archive in a folder")
    extract.add_argument("archive", type=pathlib.Path)
    extract.add_argument("-o", "--output", type=pathlib.Path, default=pathlib.Path("Output"))
    extract.add_argument("-e", "--encoding", default="cp932", help=encoding_help)
    extract.add_argument("--verify-hash", action="store_true",
                         help="check each file against the hash stored in the archive")
    extract.add_argument("--sample", type=int, default=128)

    pack = subparsers.add_parser("pack", help="pack a folder into a .ypf archive")
    pack.add_argument("input", type=pathlib.Path,
                      help="folder to pack; its immediate subfolders become archive roots")
    pack.add_argument("output", type=pathlib.Path)
    pack.add_argument("-a", "--add", action="append", type=pathlib.Path, default=[],
                      help="add another folder or file to the same archive; repeatable")
    pack.add_argument("-e", "--encoding", default="cp932", help=encoding_help)
    pack.add_argument("-v", "--version", default="auto",
                      help="archive version, e.g. 481 or 0x1F4 (default: from metadata)")
    pack.add_argument("--include-root", default="auto", choices=["auto", "yes", "no"],
                      help="whether the selected folder's own name appears in archive paths")
    pack.add_argument("--metadata-dir", type=pathlib.Path, default=None,
                      help="folder holding .ypf_meta.json (usually the extract output)")
    pack.add_argument("--from-children", action="store_true",
                      help="treat each immediate subfolder as a separate archive root")
    pack.add_argument("--no-sort-index", action="store_true",
                      help="keep filesystem order instead of sorting by path hash "
                           "(not recommended: Yu-Ris expects sorted)")
    pack.add_argument("--compression-level", type=int, default=9, choices=list(range(10)))
    return parser


def cmd_info(args) -> int:
    video = identify_video(args.archive)
    if video is not None:
        label, extension = video
        print(f"format:         not an archive — {label} video")
        print(f"size:           {args.archive.stat().st_size:,}")
        print(f"extract saves:  {extension}")
        return 0
    try:
        info = YpfArchive().inspect(args.archive, language=args.encoding,
                                    detect_hash=True, sample_hash_detection=args.sample)
    except EmptyArchiveError:
        print("format:         empty update slot (16-byte 'YPD ' placeholder)")
        print(f"size:           {args.archive.stat().st_size:,}")
        print("files:          0")
        return 0
    print(f"magic:          0x{info.header.magic:08X}")
    print(f"version:        {info.header.version} / 0x{info.header.version:X}")
    print(f"files:          {info.header.file_count}")
    print(f"header length:  {info.header.file_header_length}")
    print(f"reserved:       {list(info.header.reserved)}")
    print(f"path key:       0x{info.path_key:02X}")
    print(f"length scheme:  {info.length_scheme}")
    print(f"path hash:      {info.path_hash_mode}")
    print(f"data hash:      {info.detected_hash_mode}")
    print(f"table extra:    {info.table_extra_field_size} bytes")
    return 0


def cmd_extract(args) -> int:
    archive = args.archive
    if archive.is_dir():
        archives = sorted(archive.glob("*.ypf"))
        if not archives:
            print(f"error: no .ypf files under {archive}", file=sys.stderr)
            return 1
        failures = 0
        skipped = 0
        for item in archives:
            print(f"==== {item.name}")
            try:
                # One archive per subfolder, so extracting a folder of archives
                # cannot make two of them overwrite each other.
                YpfArchive().extract(ExtractOptions(
                    ypf_file=item, output_dir=args.output / item.stem,
                    language=args.encoding, verify_hash=args.verify_hash,
                    sample_hash_detection=args.sample,
                ))
            except EmptyArchiveError:
                # An unused update slot is empty by design, not a failure.
                print(f"  empty update slot, nothing to extract")
                skipped += 1
            except Exception as exc:
                print(f"FAILED {item.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
                failures += 1
        extracted = len(archives) - failures - skipped
        tail = f", {skipped} empty slot(s) skipped" if skipped else ""
        print(f"\n{extracted}/{len(archives)} archives extracted into {args.output}{tail}")
        return 1 if failures else 0

    YpfArchive().extract(ExtractOptions(
        ypf_file=archive, output_dir=args.output, language=args.encoding,
        verify_hash=args.verify_hash, sample_hash_detection=args.sample,
    ))
    return 0


def cmd_pack(args) -> int:
    YpfArchive().pack(PackOptions(
        input_paths=[args.input, *args.add],
        output_ypf=args.output,
        language=args.encoding,
        version=parse_version(args.version),
        include_root_mode=args.include_root,
        metadata_dir=args.metadata_dir,
        sort_index=not args.no_sort_index,
        compression_level=args.compression_level,
        pack_child_folders=args.from_children,
    ))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = {"info": cmd_info, "extract": cmd_extract, "pack": cmd_pack}[args.command]
    try:
        return handler(args)
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
