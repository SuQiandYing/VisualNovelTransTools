# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Sequence

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
