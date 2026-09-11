"""Window for working with Yu-Ris game files.

Two separate jobs, one per tab, because they are different stages of the same
pipeline and share nothing but the window:

  「翻译脚本」  scripts (.ybn) -> editable text -> rebuilt scripts
  「解包封包」  archives (.ypf) -> loose files -> repacked archives

Deliberately small: this file only lays out widgets, collects paths, starts a
worker thread and shows results.  Every actual operation lives in
``disassembler.py`` / ``assembler.py`` / ``ypf_archive.py``, so running the same
job from the command line produces the same artifacts.
"""
from __future__ import annotations

import contextlib
import io
import pathlib
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import assembler
import disassembler as dis

DIALECT = dis.DIALECT
ENCODINGS = DIALECT["encodings"]["common_choices"]
PAD = 10

# The archive side is optional: the script translator must keep working even if
# ypf_archive.py is missing.
try:
    from ypf_archive import (
        COMMON_ENCODINGS as YPF_ENCODINGS,
        EmptyArchiveError,
        ExtractOptions,
        PackOptions,
        YpfArchive,
        identify_video,
    )
    YPF_AVAILABLE = True
except ImportError:
    YPF_AVAILABLE = False
    YPF_ENCODINGS = ("cp932",)


def _try_enable_drop(widget: tk.Misc, sink: queue.Queue) -> bool:
    """Enable drag-and-drop when a helper library is installed.

    ``windnd`` installs its own window procedure, so its callback runs inside the
    native WM_DROPFILES handler — on whichever thread the shell delivered the
    drop to, with no Python thread state attached.  Calling *any* Tk method from
    there kills the process outright:

        Fatal Python error: PyEval_RestoreThread: the function must be called
        with the GIL held, but the GIL is released

    Measured: both ``var.set(...)`` and ``after_idle(...)`` abort this way;
    ``after_idle`` is not a safe escape hatch, because scheduling the callback is
    itself a Tcl call.  The only reliable handoff is a plain ``queue.Queue``,
    which needs no interpreter state the handler does not have.  The Tk side
    already polls that queue, so the drop arrives as an ordinary event.
    """
    try:
        import windnd
    except ImportError:
        return False

    def on_native_drop(raw_paths) -> None:
        # Pure Python only.  No Tk, no logging, no exceptions escaping.
        try:
            sink.put([_decode_dropped_path(p) for p in raw_paths])
        except Exception:
            pass

    # force_unicode makes windnd call DragQueryFileW, which hands back real
    # UTF-16 and therefore survives characters the ANSI code page cannot express.
    # Without it the shell substitutes "?" for every such character *before*
    # Python sees the bytes, so no amount of decoding can recover the name:
    # on a cp936 system "ガールズ・イン" arrives as "ガールズ?イン" and the path
    # no longer exists.  Older windnd builds lack the flag, so fall back.
    try:
        windnd.hook_dropfiles(widget, func=on_native_drop, force_unicode=True)
        return True
    except TypeError:
        pass
    except Exception:
        return False
    try:
        windnd.hook_dropfiles(widget, func=on_native_drop)
        return True
    except Exception:
        return False


def _decode_dropped_path(raw) -> str:
    """Decode a path handed over by the shell.

    With ``force_unicode`` the path already arrives as ``str`` and is returned
    untouched.  The byte paths below only appear on older ``windnd`` builds that
    call the ANSI ``DragQueryFile``: those bytes are in the system code page, so
    UTF-8 must not be tried first — it mangles every non-ASCII path, which on a
    Chinese Windows means most game folders.
    """
    if isinstance(raw, str):
        return raw
    for encoding in ("mbcs", "utf-8"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("mbcs", "replace")


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Yu-Ris 脚本翻译工具")
        root.minsize(760, 620)

        self.input_var = tk.StringVar()
        self.text_out_var = tk.StringVar()
        self.rebuild_from_var = tk.StringVar()
        self.rebuild_out_var = tk.StringVar()
        self.source_encoding = tk.StringVar(value=DIALECT["encodings"]["source"])
        self.target_encoding = tk.StringVar(value=DIALECT["encodings"]["target"])
        self.want_texts = tk.BooleanVar(value=True)
        self.want_asm = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="把脚本文件夹拖进来，或点「浏览」选择")

        # Archive tab state.
        self.ypf_input_var = tk.StringVar()
        self.ypf_extract_out_var = tk.StringVar()
        self.ypf_pack_from_var = tk.StringVar()
        self.ypf_pack_out_var = tk.StringVar()
        self.ypf_encoding = tk.StringVar(value="cp932")
        self.ypf_verify = tk.BooleanVar(value=True)
        self._ypf_extract_out_manual = False
        self._ypf_pack_from_follows = True

        # The repack source follows the text output until the user overrides it.
        self._rebuild_from_follows = True
        self._text_out_manual = False
        self._rebuild_out_manual = False
        self._queue: queue.Queue = queue.Queue()
        # Dropped paths arrive on a native thread and must not touch Tk there,
        # so they come in through their own queue (see _try_enable_drop).
        self._drop_queue: queue.Queue = queue.Queue()
        self._busy = False
        self._active_tab = 0

        self._build()
        self.root.after(100, self._drain)

    # ---------------------------------------------------------------- layout
    def _build(self) -> None:
        shell = ttk.Frame(self.root, padding=PAD)
        shell.pack(fill="both", expand=True)

        self.tabs = ttk.Notebook(shell)
        self.tabs.pack(fill="both", expand=True)
        script_tab = ttk.Frame(self.tabs, padding=PAD)
        archive_tab = ttk.Frame(self.tabs, padding=PAD)
        self.tabs.add(script_tab, text="  翻译脚本  ")
        self.tabs.add(archive_tab, text="  解包封包  ")
        self.tabs.bind("<<NotebookTabChanged>>", self._tab_changed)

        self._build_script_tab(script_tab)
        self._build_archive_tab(archive_tab)

        # Progress, status and details are shared: only one job runs at a time.
        self.progress = ttk.Progressbar(shell, mode="determinate")
        self.progress.pack(fill="x", pady=(PAD, 4))
        ttk.Label(shell, textvariable=self.status, wraplength=720,
                  justify="left").pack(anchor="w")
        detail = ttk.LabelFrame(shell, text="详情", padding=PAD)
        detail.pack(fill="both", expand=True, pady=(PAD, 0))
        self.detail_box = tk.Text(detail, height=9, wrap="word")
        self.detail_box.pack(fill="both", expand=True)
        self.detail_box.configure(state="disabled")

        self._refresh_buttons()

    def _tab_changed(self, _event=None) -> None:
        self._active_tab = self.tabs.index(self.tabs.select())
        self.status.set(
            "把脚本文件夹拖进来，或点「浏览」选择" if self._active_tab == 0
            else "选择 .ypf 归档文件，或装了游戏资源的文件夹"
        )
        self._refresh_buttons()

    def _build_script_tab(self, outer: ttk.Frame) -> None:
        box = ttk.LabelFrame(outer, text="游戏脚本文件夹", padding=PAD)
        box.pack(fill="x")
        row = ttk.Frame(box)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.input_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self._pick_input).pack(side="left", padx=(6, 0))
        self.input_hint = ttk.Label(box, text="", foreground="#555")
        self.input_hint.pack(anchor="w", pady=(4, 0))
        self.input_var.trace_add("write", lambda *_: self._input_changed())

        if not _try_enable_drop(self.root, self._drop_queue):
            ttk.Label(
                box, foreground="#888",
                text="（未安装拖放支持，请用「浏览」选择；pip install windnd 可启用拖放）",
            ).pack(anchor="w")

        enc = ttk.Frame(outer)
        enc.pack(fill="x", pady=(PAD, 0))
        ttk.Label(enc, text="原文编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.source_encoding, values=ENCODINGS,
                     width=10).pack(side="left", padx=(4, PAD))
        ttk.Label(enc, text="译文编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.target_encoding, values=ENCODINGS,
                     width=10).pack(side="left", padx=(4, 0))

        export_box = ttk.LabelFrame(outer, text="输 出 文 本", padding=PAD)
        export_box.pack(fill="x", pady=(PAD, 0))
        row = ttk.Frame(export_box)
        row.pack(fill="x")
        ttk.Label(row, text="到").pack(side="left")
        ttk.Entry(row, textvariable=self.text_out_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self._pick_text_out).pack(side="left")
        self.text_out_var.trace_add("write", lambda *_: self._text_out_changed())
        checks = ttk.Frame(export_box)
        checks.pack(fill="x", pady=(6, 0))
        ttk.Checkbutton(checks, text="双行文本（翻译用）", variable=self.want_texts,
                        command=self._refresh_buttons).pack(side="left")
        ttk.Checkbutton(checks, text="ASM 清单（改逻辑用）", variable=self.want_asm,
                        command=self._refresh_buttons).pack(side="left", padx=(PAD, 0))
        self.export_button = ttk.Button(export_box, text="输出文本", command=self._do_export)
        self.export_button.pack(anchor="w", pady=(8, 0))

        repack_box = ttk.LabelFrame(outer, text="回 封 文 本", padding=PAD)
        repack_box.pack(fill="x", pady=(PAD, 0))
        row = ttk.Frame(repack_box)
        row.pack(fill="x")
        ttk.Label(row, text="从").pack(side="left")
        ttk.Entry(row, textvariable=self.rebuild_from_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self._pick_rebuild_from).pack(side="left")
        self.rebuild_from_var.trace_add("write", lambda *_: self._rebuild_from_changed())
        row = ttk.Frame(repack_box)
        row.pack(fill="x", pady=(6, 0))
        ttk.Label(row, text="到").pack(side="left")
        ttk.Entry(row, textvariable=self.rebuild_out_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self._pick_rebuild_out).pack(side="left")
        self.rebuild_out_var.trace_add("write", lambda *_: self._refresh_buttons())
        self.repack_button = ttk.Button(repack_box, text="回封文本", command=self._do_repack)
        self.repack_button.pack(anchor="w", pady=(8, 0))

    # ------------------------------------------------------- archive tab
    def _build_archive_tab(self, outer: ttk.Frame) -> None:
        if not YPF_AVAILABLE:
            ttk.Label(
                outer, foreground="#a00", wraplength=680, justify="left",
                text="找不到 ypf_archive.py，解包功能不可用。\n"
                     "请确认它和本程序放在同一目录下。",
            ).pack(anchor="w", pady=PAD)
            return

        box = ttk.LabelFrame(outer, text="归档文件（.ypf）", padding=PAD)
        box.pack(fill="x")
        row = ttk.Frame(box)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.ypf_input_var).pack(
            side="left", fill="x", expand=True)
        ttk.Button(row, text="选文件…", command=self._pick_ypf_file).pack(side="left", padx=(6, 0))
        ttk.Button(row, text="选文件夹…", command=self._pick_ypf_dir).pack(side="left", padx=(4, 0))
        self.ypf_hint = ttk.Label(box, text="", foreground="#555")
        self.ypf_hint.pack(anchor="w", pady=(4, 0))
        self.ypf_input_var.trace_add("write", lambda *_: self._ypf_input_changed())

        enc = ttk.Frame(outer)
        enc.pack(fill="x", pady=(PAD, 0))
        ttk.Label(enc, text="路径编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.ypf_encoding, values=list(YPF_ENCODINGS),
                     width=10).pack(side="left", padx=(4, PAD))
        ttk.Checkbutton(enc, text="校验文件哈希", variable=self.ypf_verify).pack(side="left")

        extract_box = ttk.LabelFrame(outer, text="解 包", padding=PAD)
        extract_box.pack(fill="x", pady=(PAD, 0))
        row = ttk.Frame(extract_box)
        row.pack(fill="x")
        ttk.Label(row, text="到").pack(side="left")
        ttk.Entry(row, textvariable=self.ypf_extract_out_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self._pick_ypf_extract_out).pack(side="left")
        self.ypf_extract_out_var.trace_add("write", lambda *_: self._ypf_extract_out_changed())
        buttons = ttk.Frame(extract_box)
        buttons.pack(anchor="w", pady=(8, 0))
        self.ypf_info_button = ttk.Button(buttons, text="查看信息", command=self._do_ypf_info)
        self.ypf_info_button.pack(side="left")
        self.ypf_extract_button = ttk.Button(buttons, text="解包", command=self._do_ypf_extract)
        self.ypf_extract_button.pack(side="left", padx=(6, 0))

        pack_box = ttk.LabelFrame(outer, text="封 包", padding=PAD)
        pack_box.pack(fill="x", pady=(PAD, 0))
        row = ttk.Frame(pack_box)
        row.pack(fill="x")
        ttk.Label(row, text="从").pack(side="left")
        ttk.Entry(row, textvariable=self.ypf_pack_from_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self._pick_ypf_pack_from).pack(side="left")
        self.ypf_pack_from_var.trace_add("write", lambda *_: self._ypf_pack_from_changed())
        row = ttk.Frame(pack_box)
        row.pack(fill="x", pady=(6, 0))
        ttk.Label(row, text="到").pack(side="left")
        ttk.Entry(row, textvariable=self.ypf_pack_out_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self._pick_ypf_pack_out).pack(side="left")
        self.ypf_pack_out_var.trace_add("write", lambda *_: self._refresh_buttons())
        self.ypf_pack_button = ttk.Button(pack_box, text="封包", command=self._do_ypf_pack)
        self.ypf_pack_button.pack(anchor="w", pady=(8, 0))

    # ------------------------------------------------------------- path glue
    def _input_changed(self) -> None:
        raw = self.input_var.get().strip()
        if not raw:
            self.input_hint.configure(text="")
            self._refresh_buttons()
            return
        path = pathlib.Path(raw)
        base = path if path.is_dir() else path.parent
        stem = path.name if path.is_dir() else path.stem
        # Defaults sit beside the input, never inside it, so a second run cannot
        # pick up the previous run's output as new input.
        if not self._text_out_manual:
            self.text_out_var.set(str(base.parent / f"{stem}_text"))
            self._text_out_manual = False
        if not self._rebuild_out_manual:
            self.rebuild_out_var.set(str(base.parent / f"{stem}_rebuilt"))
            self._rebuild_out_manual = False
        try:
            found = len(dis.iter_sources(path)) if path.exists() else 0
        except Exception:
            found = 0
        self.input_hint.configure(
            text=f"已找到 {found} 个脚本文件" if found else "这个位置没有找到脚本文件"
        )
        self._refresh_buttons()

    def _text_out_changed(self) -> None:
        if self._rebuild_from_follows:
            self.rebuild_from_var.set(self.text_out_var.get())
            self._rebuild_from_follows = True
        self._refresh_buttons()

    def _rebuild_from_changed(self) -> None:
        if self.rebuild_from_var.get() != self.text_out_var.get():
            self._rebuild_from_follows = False
        self._refresh_buttons()

    def _pick_input(self) -> None:
        chosen = filedialog.askdirectory(title="选择脚本文件夹")
        if chosen:
            self._text_out_manual = False
            self._rebuild_out_manual = False
            self.input_var.set(chosen)

    def _pick_text_out(self) -> None:
        chosen = filedialog.askdirectory(title="文本输出到")
        if chosen:
            self._text_out_manual = True
            self.text_out_var.set(chosen)

    def _pick_rebuild_from(self) -> None:
        chosen = filedialog.askdirectory(title="译文所在位置")
        if chosen:
            self._rebuild_from_follows = False
            self.rebuild_from_var.set(chosen)

    def _pick_rebuild_out(self) -> None:
        chosen = filedialog.askdirectory(title="回封输出到")
        if chosen:
            self._rebuild_out_manual = True
            self.rebuild_out_var.set(chosen)

    def _on_drop(self, raw_paths: list[str]) -> None:
        """Route a dropped path to whichever tab is in front.

        Called from ``_drain``, i.e. on the Tk event loop — never straight from
        the drop hook (see ``_try_enable_drop``).
        """
        if not raw_paths:
            return
        if self._busy:
            self.status.set("正在处理，请等当前任务结束后再拖入")
            return
        target = str(raw_paths[0])
        if self._active_tab == 1 and YPF_AVAILABLE:
            self._ypf_extract_out_manual = False
            self.ypf_input_var.set(target)
            return
        self._text_out_manual = False
        self._rebuild_out_manual = False
        self.input_var.set(target)

    # ------------------------------------------------------ archive path glue
    def _ypf_archives(self, raw: str) -> list[pathlib.Path]:
        """The .ypf files a given input refers to (one file, or all in a folder)."""
        if not raw.strip():
            return []
        path = pathlib.Path(raw.strip())
        if path.is_file():
            return [path]
        if path.is_dir():
            return sorted(path.glob("*.ypf"))
        return []

    def _ypf_input_changed(self) -> None:
        raw = self.ypf_input_var.get().strip()
        if not raw:
            self.ypf_hint.configure(text="")
            self._refresh_buttons()
            return
        path = pathlib.Path(raw)
        found = self._ypf_archives(raw)
        stem = path.stem if path.is_file() else path.name
        base = path.parent if path.is_file() else path.parent
        if not self._ypf_extract_out_manual:
            self.ypf_extract_out_var.set(str(base / f"{stem}_extract"))
            self._ypf_extract_out_manual = False
        if not self.ypf_pack_out_var.get().strip():
            self.ypf_pack_out_var.set(str(base / f"{stem}_repacked"))
        if path.is_file():
            if not path.exists():
                self.ypf_hint.configure(text="文件不存在")
            else:
                video = identify_video(path) if YPF_AVAILABLE else None
                if video is not None:
                    label, extension = video
                    self.ypf_hint.configure(
                        text=f"这不是归档，是 {label} 视频文件，"
                             f"解包会原样另存为 {extension}"
                    )
                else:
                    self.ypf_hint.configure(
                        text=f"已选择 1 个归档文件（{path.stat().st_size:,} 字节）"
                    )
        else:
            self.ypf_hint.configure(
                text=f"已找到 {len(found)} 个 .ypf 归档" if found
                else "这个位置没有找到 .ypf 文件"
            )
        self._refresh_buttons()

    def _ypf_extract_out_changed(self) -> None:
        if self._ypf_pack_from_follows:
            self.ypf_pack_from_var.set(self.ypf_extract_out_var.get())
            self._ypf_pack_from_follows = True
        self._refresh_buttons()

    def _ypf_pack_from_changed(self) -> None:
        if self.ypf_pack_from_var.get() != self.ypf_extract_out_var.get():
            self._ypf_pack_from_follows = False
        self._refresh_buttons()

    def _pick_ypf_file(self) -> None:
        chosen = filedialog.askopenfilename(
            title="选择 .ypf 归档", filetypes=[("Yu-Ris 归档", "*.ypf"), ("所有文件", "*.*")])
        if chosen:
            self._ypf_extract_out_manual = False
            self.ypf_input_var.set(chosen)

    def _pick_ypf_dir(self) -> None:
        chosen = filedialog.askdirectory(title="选择含 .ypf 的文件夹")
        if chosen:
            self._ypf_extract_out_manual = False
            self.ypf_input_var.set(chosen)

    def _pick_ypf_extract_out(self) -> None:
        chosen = filedialog.askdirectory(title="解包输出到")
        if chosen:
            self._ypf_extract_out_manual = True
            self.ypf_extract_out_var.set(chosen)

    def _pick_ypf_pack_from(self) -> None:
        chosen = filedialog.askdirectory(title="要封包的文件夹")
        if chosen:
            self._ypf_pack_from_follows = False
            self.ypf_pack_from_var.set(chosen)

    def _pick_ypf_pack_out(self) -> None:
        chosen = filedialog.asksaveasfilename(
            title="封包另存为", defaultextension=".ypf",
            filetypes=[("Yu-Ris 归档", "*.ypf")])
        if chosen:
            self.ypf_pack_out_var.set(chosen)

    def _refresh_buttons(self) -> None:
        has_input = bool(self.input_var.get().strip())
        wants_output = self.want_texts.get() or self.want_asm.get()
        self.export_button.configure(
            state="normal" if has_input and wants_output and not self._busy else "disabled"
        )
        source = pathlib.Path(self.rebuild_from_var.get().strip() or ".")
        has_edits = (source / "texts").is_dir() or (source / "asm").is_dir()
        self.repack_button.configure(
            state="normal" if has_input and has_edits and not self._busy else "disabled"
        )
        if YPF_AVAILABLE:
            archives = self._ypf_archives(self.ypf_input_var.get())
            ready = bool(archives) and not self._busy
            self.ypf_info_button.configure(state="normal" if ready else "disabled")
            self.ypf_extract_button.configure(
                state="normal" if ready and self.ypf_extract_out_var.get().strip()
                else "disabled"
            )
            pack_from = pathlib.Path(self.ypf_pack_from_var.get().strip() or ".")
            self.ypf_pack_button.configure(
                state="normal" if pack_from.is_dir() and self.ypf_pack_out_var.get().strip()
                and not self._busy else "disabled"
            )
        if self._active_tab != 0:
            return
        if has_input and not wants_output:
            self.status.set("请至少选择一种输出")
        elif has_input and not has_edits:
            self.status.set("先输出文本，翻译后再回封")

    # ------------------------------------------------------------ operations
    def _do_export(self) -> None:
        root = pathlib.Path(self.input_var.get().strip())
        out = pathlib.Path(self.text_out_var.get().strip())
        if out.exists() and any(out.iterdir()):
            if not messagebox.askyesno("目标已存在", f"{out}\n里已经有文件，覆盖吗？"):
                return
        self._start(self._export_worker, (root, out))

    def _export_worker(self, root: pathlib.Path, out: pathlib.Path) -> None:
        summary = dis.export(
            root, out,
            texts=self.want_texts.get(), asm=self.want_asm.get(), certificates=True,
            target_encoding=self.target_encoding.get(),
            source_encoding=self.source_encoding.get(),
            progress=lambda done, total, name: self._queue.put(
                ("progress", (done, total, name))),
        )
        self._queue.put(("export_done", summary))

    def _do_repack(self) -> None:
        root = pathlib.Path(self.input_var.get().strip())
        texts = pathlib.Path(self.rebuild_from_var.get().strip())
        out = pathlib.Path(self.rebuild_out_var.get().strip())
        # Preview first; nothing is written until the user confirms.
        self._start(self._preview_worker, (root, texts, out))

    def _preview_worker(self, root: pathlib.Path, texts: pathlib.Path,
                        out: pathlib.Path) -> None:
        summary = assembler.repack(
            root, texts, out,
            target_encoding=self.target_encoding.get(),
            source_encoding=self.source_encoding.get(),
            dry_run=True,
            progress=lambda done, total, name: self._queue.put(
                ("progress", (done, total, name))),
        )
        self._queue.put(("preview_done", (summary, root, texts, out)))

    def _repack_worker(self, root: pathlib.Path, texts: pathlib.Path,
                       out: pathlib.Path) -> None:
        summary = assembler.repack(
            root, texts, out,
            target_encoding=self.target_encoding.get(),
            source_encoding=self.source_encoding.get(),
            progress=lambda done, total, name: self._queue.put(
                ("progress", (done, total, name))),
        )
        self._queue.put(("repack_done", summary))

    # -------------------------------------------------------- archive actions
    def _do_ypf_info(self) -> None:
        archives = self._ypf_archives(self.ypf_input_var.get())
        self._start(self._ypf_info_worker, (archives,))

    def _ypf_info_worker(self, archives: list[pathlib.Path]) -> None:
        lines: list[str] = []
        for index, path in enumerate(archives, 1):
            self._queue.put(("progress", (index, len(archives), path.name)))
            video = identify_video(path)
            if video is not None:
                lines.append(
                    f"{path.name}  不是归档，是 {video[0]} 视频，"
                    f"{path.stat().st_size:,} 字节（解包会另存为 {video[1]}）"
                )
                continue
            # inspect() prints a layout line; capture it so it lands in 详情
            # rather than a console the user cannot see.
            buffer = io.StringIO()
            try:
                with contextlib.redirect_stdout(buffer):
                    info = YpfArchive().inspect(
                        path, language=self.ypf_encoding.get(),
                        detect_hash=True, sample_hash_detection=32,
                    )
            except EmptyArchiveError:
                lines.append(f"{path.name}  空的更新槽，里面没有文件（正常，跳过即可）")
                continue
            except Exception as exc:
                lines.append(f"{path.name}  读取失败：{type(exc).__name__}: {exc}")
                continue
            lines.append(
                f"{path.name}  版本 {info.header.version}  文件 {info.header.file_count} 个  "
                f"路径密钥 0x{info.path_key:02X}  路径哈希 {info.path_hash_mode}  "
                f"数据哈希 {info.detected_hash_mode}"
            )
            for note in buffer.getvalue().splitlines():
                if note.strip():
                    lines.append(f"    {note.strip()}")
        self._queue.put(("ypf_info_done", (archives, lines)))

    def _do_ypf_extract(self) -> None:
        archives = self._ypf_archives(self.ypf_input_var.get())
        out = pathlib.Path(self.ypf_extract_out_var.get().strip())
        if out.exists() and any(out.iterdir()):
            if not messagebox.askyesno("目标已存在", f"{out}\n里已经有文件，覆盖吗？"):
                return
        self._start(self._ypf_extract_worker, (archives, out))

    def _ypf_extract_worker(self, archives: list[pathlib.Path], out: pathlib.Path) -> None:
        done: list[tuple[str, int]] = []
        skipped: list[tuple[str, str]] = []
        failed: list[tuple[str, str]] = []
        for index, path in enumerate(archives, 1):
            self._queue.put(("progress", (index, len(archives), path.name)))
            # One archive per subfolder, so extracting a whole folder of
            # archives cannot make two of them overwrite each other.
            target = out / path.stem if len(archives) > 1 else out
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    YpfArchive().extract(ExtractOptions(
                        ypf_file=path, output_dir=target,
                        language=self.ypf_encoding.get(),
                        verify_hash=self.ypf_verify.get(),
                    ))
                count = sum(1 for p in target.rglob("*") if p.is_file())
                done.append((path.name, count))
            except EmptyArchiveError:
                # An unused update slot is empty by design, not a failure.
                skipped.append((path.name, "空的更新槽，里面没有文件"))
            except Exception as exc:
                failed.append((path.name, f"{type(exc).__name__}: {exc}"))
        self._queue.put(("ypf_extract_done", (done, skipped, failed, out)))

    def _ypf_pack_roots(self, source: pathlib.Path) -> tuple[list[pathlib.Path], str]:
        """Decide what to pack and whether the folder's own name goes into paths.

        The extractor writes ``<out>/<top>/...`` where ``<top>`` is the archive's
        own root directory, so packing that output should pass the subfolders and
        keep their names.  If the user points at a folder holding loose files
        instead, its name is theirs, not the archive's, and must be left out —
        otherwise every path silently gains a wrong leading directory.
        """
        subdirectories = [d for d in sorted(source.iterdir()) if d.is_dir()]
        if subdirectories:
            return subdirectories, "yes"
        return [source], "no"

    def _do_ypf_pack(self) -> None:
        source = pathlib.Path(self.ypf_pack_from_var.get().strip())
        out = pathlib.Path(self.ypf_pack_out_var.get().strip())
        roots, root_mode = self._ypf_pack_roots(source)
        if out.exists():
            if not messagebox.askyesno("文件已存在", f"{out}\n已存在，覆盖吗？"):
                return
        scope = (f"{len(roots)} 个目录" if root_mode == "yes"
                 else f"{source.name} 里的文件（不含目录名）")
        message = (
            f"将把 {scope} 封包成\n  {out}\n\n"
            f"路径编码 {self.ypf_encoding.get()}\n\n"
            "封包结果和原始归档不会逐字节相同（压缩实现不同），\n"
            "但解包后的文件内容一致。是否继续？"
        )
        if messagebox.askokcancel("封包确认", message):
            self._start(self._ypf_pack_worker, (source, roots, root_mode, out))

    def _ypf_pack_worker(self, source: pathlib.Path, roots: list[pathlib.Path],
                         root_mode: str, out: pathlib.Path) -> None:
        self._queue.put(("progress", (0, 1, out.name)))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            YpfArchive().pack(PackOptions(
                input_paths=roots, output_ypf=out,
                language=self.ypf_encoding.get(),
                include_root_mode=root_mode,
                # Reuse the metadata the extractor saved, so file types and
                # compression flags match the original archive.
                metadata_dir=source,
            ))
        self._queue.put(("progress", (1, 1, out.name)))
        self._queue.put(("ypf_pack_done", (out, roots, buffer.getvalue())))

    def _start(self, worker, arguments: tuple) -> None:
        self._busy = True
        self._refresh_buttons()
        self.progress.configure(value=0)

        def run() -> None:
            try:
                worker(*arguments)
            except (dis.DisassemblyError, assembler.RepackError) as exc:
                self._queue.put(("error", str(exc)))
            except Exception as exc:  # surfaced, never swallowed
                self._queue.put(("error", f"{type(exc).__name__}: {exc}"))
            finally:
                self._queue.put(("idle", None))

        threading.Thread(target=run, daemon=True).start()

    # --------------------------------------------------------------- results
    def _drain(self) -> None:
        # Dropped paths first: they were parked by the native drop hook, which
        # cannot safely call into Tk itself.
        while True:
            try:
                dropped = self._drop_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._on_drop(dropped)
            except Exception as exc:
                self.status.set(f"无法读取拖入的路径：{type(exc).__name__}: {exc}")

        while True:
            try:
                kind, payload = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "progress":
                done, total, name = payload
                self.progress.configure(maximum=total, value=done)
                self.status.set(f"正在处理 {name}  {done}/{total}")
            elif kind == "export_done":
                self._show_export(payload)
            elif kind == "preview_done":
                self._show_preview(*payload)
            elif kind == "repack_done":
                self._show_repack(payload)
            elif kind == "ypf_info_done":
                self._show_ypf_info(*payload)
            elif kind == "ypf_extract_done":
                self._show_ypf_extract(*payload)
            elif kind == "ypf_pack_done":
                self._show_ypf_pack(*payload)
            elif kind == "error":
                self.status.set(f"失败：{payload.splitlines()[0]}")
                self._detail(payload)
            elif kind == "idle":
                self._busy = False
                self._refresh_buttons()
        self.root.after(100, self._drain)

    def _detail(self, text: str) -> None:
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("1.0", text)
        self.detail_box.configure(state="disabled")

    def _show_export(self, summary: dict) -> None:
        pairs = lambda mapping: " / ".join(f"{k} {v}" for k, v in sorted(mapping.items()))
        lines = [
            f"文件      {summary['processed']}/{summary['file_count']}",
            f"条目      {pairs(summary['tags'])}",
            f"覆盖      byte {summary['min_byte_coverage'] * 100:.2f}%   "
            f"往返 {'逐字节一致' if summary['roundtrip_identical'] else '不一致'}",
            f"结构      {pairs(summary['shapes'])}",
            f"编码      {pairs(summary['encodings'])}",
            f"内部产物  {summary['output']}\\reports",
        ]
        lines += [f"跳过      {i['file']}：{i['reason']}" for i in summary["skipped"]]
        lines += [f"失败      {i['file']}：{i['error']}" for i in summary["failures"]]
        self._detail("\n".join(lines))

        if not summary["roundtrip_identical"]:
            self.status.set("这个游戏暂不支持回封：自检未通过，详情见下方")
        elif summary["failures"]:
            self.status.set(f"有 {len(summary['failures'])} 个文件失败，详情见下方")
        else:
            self.status.set(f"已导出 {summary['entry_count']} 条到 {summary['output']}")

    def _show_preview(self, summary: dict, root: pathlib.Path,
                      texts: pathlib.Path, out: pathlib.Path) -> None:
        if summary["failures"]:
            self.status.set(f"有 {len(summary['failures'])} 个文件无法回封，请先处理")
            self._detail("\n".join(
                f"{i['file']}：{i['error']}" for i in summary["failures"]
            ))
            return
        if messagebox.askokcancel("回封预览", (
            f"将回封 {summary['repacked']} 个文件\n\n"
            f"  改动    {summary['changed_entries']} 条译文"
            f"（其中 {summary['grown_parts']} 处变长，共 {summary['byte_delta']:+d} 字节）\n"
            f"  文件    {summary['files_changed']} 个会改变\n"
            f"  输出到  {out}\n\n是否执行？"
        )):
            self._start(self._repack_worker, (root, texts, out))
        else:
            self.status.set("已取消，未写出任何文件")

    def _show_repack(self, summary: dict) -> None:
        self._detail("\n".join([
            f"改动      {summary['changed_entries']} 条（未改 {summary['unchanged_entries']} 条）",
            f"长度变化  {summary['byte_delta']:+d} 字节，{summary['files_changed']} 个文件改变",
            f"输出      {summary['output']}",
        ] + [f"失败      {i['file']}：{i['error']}" for i in summary["failures"]]))
        if summary["failures"]:
            self.status.set(f"有 {len(summary['failures'])} 个文件失败，详情见下方")
        else:
            self.status.set(
                f"已回封 {summary['repacked']} 个文件到 {summary['output']}，"
                "把里面的文件复制回游戏目录即可"
            )

    # ------------------------------------------------------- archive results
    def _show_ypf_info(self, archives: list[pathlib.Path], lines: list[str]) -> None:
        self.status.set(f"已读取 {len(archives)} 个归档的信息，详情见下方")
        self._detail("\n".join(lines))

    def _show_ypf_extract(self, done: list[tuple[str, int]],
                          skipped: list[tuple[str, str]],
                          failed: list[tuple[str, str]], out: pathlib.Path) -> None:
        total = sum(count for _name, count in done)
        lines = [f"{name}  取出 {count} 个文件" for name, count in done]
        lines += [f"{name}  跳过：{reason}" for name, reason in skipped]
        lines += [f"{name}  失败：{error}" for name, error in failed]
        lines.append(f"输出      {out}")
        self._detail("\n".join(lines))
        tail = f"，{len(skipped)} 个空槽跳过" if skipped else ""
        if failed:
            self.status.set(
                f"{len(done)} 个归档解包完成，{len(failed)} 个失败{tail}，详情见下方"
            )
        else:
            self.status.set(
                f"已解包 {len(done)} 个归档，共 {total} 个文件到 {out}{tail}"
            )

    def _show_ypf_pack(self, out: pathlib.Path, roots: list[pathlib.Path],
                       log: str) -> None:
        size = out.stat().st_size if out.exists() else 0
        lines = [
            f"目录      {len(roots)} 个",
            f"输出      {out}（{size:,} 字节）",
            "",
            "封包日志：",
        ]
        # The packer's own log is long; keep the tail, which is where failures show.
        entries = [l for l in log.splitlines() if l.strip()]
        lines += entries[:6]
        if len(entries) > 14:
            lines.append(f"    …（省略 {len(entries) - 12} 行）")
        lines += entries[-6:] if len(entries) > 6 else []
        self._detail("\n".join(lines))
        self.status.set(f"封包完成：{out}（{size:,} 字节）")


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
