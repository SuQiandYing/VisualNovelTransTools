# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import os
import struct
import zlib
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

from .codec import (
    convert_path_length,
    decode_archive_path,
    default_length_scheme,
    default_path_key,
    encode_archive_path,
    encode_path_length,
    guess_path_key,
    length_table_by_name,
    unxor_path_from_table,
    xor_path_for_table,
)
from .constants import LENGTH_TABLES, YPF_HEADER_SIZE, YPF_MAGIC, YPF_VER_1DE, YPF_VER_1DF, YPF_VER_1F4
from .hashers import DataHashMode, data_hash, default_data_hash_mode, normalize_data_hash_mode, path_hash, path_hash_by_mode, detect_path_hash_mode, possible_hash_modes
from .meta import META_FILENAME, META_FORMAT, META_SCHEMA_VERSION, find_metadata_for_inputs, metadata_entry_map, save_metadata
from .op import extract_op, is_mpeg_ps_file, pack_op, should_pack_as_op
from .models import ArchiveInfo, ExtractOptions, PackOptions, YpfEntry, YpfHeader


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

        if off != len(table):
            raise ValueError(f"File table parse did not consume all bytes: used {off}, total {len(table)}.")

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
        with ypf_path.open("rb") as f:
            header = YpfHeader.from_bytes(f.read(YPF_HEADER_SIZE))
            header.validate()
            table_len = header.file_header_length - YPF_HEADER_SIZE
            table = f.read(table_len)
            if len(table) != table_len:
                raise ValueError("YPF file table is truncated.")
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

    def extract(self, options: ExtractOptions | os.PathLike | str, output_dir: os.PathLike | str = "Output",
                lang: str = "cp932", verify_hash: bool = False) -> None:
        # Backward-compatible shorthand: extract("a.ypf", "out", lang="cp932").
        if not isinstance(options, ExtractOptions):
            options = ExtractOptions(options, output_dir, lang, verify_hash)
        ypf_path = Path(options.ypf_file)
        out_dir = Path(options.output_dir)
        if not ypf_path.is_file():
            raise FileNotFoundError(f"YPF file not found: {ypf_path}")

        if is_mpeg_ps_file(ypf_path):
            self._log("Detected raw OP-video .ypf (MPEG Program Stream).")
            return extract_op(ypf_path, out_dir, log=self._log)

        with ypf_path.open("rb") as f:
            header = YpfHeader.from_bytes(f.read(YPF_HEADER_SIZE))
            header.validate()
            table_len = header.file_header_length - YPF_HEADER_SIZE
            table = f.read(table_len)
            if len(table) != table_len:
                raise ValueError("YPF file table is truncated.")

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
