# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Optional, Sequence

MPEG_PS_HEADER = b"\x00\x00\x01\xBA"
VIDEO_EXTENSIONS = {
    ".mpg", ".mpeg", ".mpe", ".vob", ".m2v", ".mp4", ".m4v",
    ".mkv", ".avi", ".mov", ".wmv", ".webm", ".ts", ".m2ts",
}
MPEG_PS_EXTENSIONS = {".mpg", ".mpeg", ".mpe", ".vob"}


def is_mpeg_ps_file(path: os.PathLike | str) -> bool:
    try:
        with Path(path).open("rb") as f:
            return f.read(4) == MPEG_PS_HEADER
    except Exception:
        return False


def is_video_file(path: os.PathLike | str) -> bool:
    return Path(path).is_file() and Path(path).suffix.lower() in VIDEO_EXTENSIONS


def default_op_extract_output(input_path: os.PathLike | str, output: os.PathLike | str) -> Path:
    src = Path(input_path)
    out = Path(output)
    # When output looks like a file path, use it directly.  GUI normally supplies a folder.
    if out.suffix.lower() in MPEG_PS_EXTENSIONS or out.suffix.lower() in VIDEO_EXTENSIONS:
        return out
    out.mkdir(parents=True, exist_ok=True)
    if src.stem.lower() == "op":
        name = "op_extracted.mpg"
    else:
        name = src.stem + ".mpg"
    return out / name


def extract_op(input_ypf: os.PathLike | str, output: os.PathLike | str, log: Callable[[str], None] = print) -> dict:
    src = Path(input_ypf)
    if not src.is_file():
        raise FileNotFoundError(f"OP input not found: {src}")
    if not is_mpeg_ps_file(src):
        with src.open("rb") as f:
            head = f.read(4)
        log(f"warning: input is not standard MPEG Program Stream, header={head.hex()}")
    dst = default_op_extract_output(src, output)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    size = dst.stat().st_size
    log(f"OP video extracted: {dst} ({size / 1024 / 1024:.1f} MB)")
    return {
        "format": "op_mpeg_ps",
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
