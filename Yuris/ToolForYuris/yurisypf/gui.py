# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import queue
import threading
import traceback
from pathlib import Path
from typing import List, Sequence

from .archive import YpfArchive
from .constants import YPF_HEADER_SIZE, COMMON_ENCODINGS
from .meta import find_metadata_for_inputs, load_metadata
from .models import ExtractOptions, PackOptions, YpfHeader
from .op import VIDEO_EXTENSIONS, is_mpeg_ps_file


def run_gui() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore
        BaseTk = TkinterDnD.Tk
        dnd_available = True
    except Exception:
        DND_FILES = None  # type: ignore
        BaseTk = tk.Tk
        dnd_available = False

    class App:
        def __init__(self, root: tk.Tk) -> None:
            self.root = root
            self.root.title("ToolForYuris / YU-RIS YPF GUI")
            self.root.geometry("1040x700")
            self.input_paths: List[str] = []
            self.current_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.lang = tk.StringVar(value="cp932")
            self.version = tk.StringVar(value="auto")
            self.mode = tk.StringVar(value="auto")
            self.include_root = tk.StringVar(value="auto")
            self.pack_children = tk.BooleanVar(value=False)
            self.verify_hash = tk.BooleanVar(value=False)
            self.task_queue: "queue.Queue[object]" = queue.Queue()
            self._build_ui(dnd_available)
            self._poll_log_queue()

        def _build_ui(self, dnd_available: bool) -> None:
            main = ttk.Frame(self.root, padding=12)
            main.pack(fill=tk.BOTH, expand=True)

            title = ttk.Label(main, text="YPF / OP 解包与打包", font=("Segoe UI", 16, "bold"))
            title.pack(anchor="w")

            hint = (
                "拖入 .ypf 解包；拖入一个或多个资源文件夹打包；拖入 OP 视频文件可直接回封 op.ypf。\n"
                "程序会从原包或 .ypf_meta.json 自动识别版本、hash、表结构和 OP 视频格式。"
                if dnd_available else
                "当前环境未安装 tkinterdnd2；可用按钮添加文件/文件夹。pip install tkinterdnd2 后支持拖拽。"
            )
            self.drop = tk.Label(main, text=hint, relief=tk.GROOVE, borderwidth=2, height=5,
                                 bg="#f7f7f7", fg="#333333", justify="center")
            self.drop.pack(fill=tk.X, pady=(10, 8))
            if dnd_available:
                self.drop.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
                self.drop.dnd_bind("<<Drop>>", self._on_drop)  # type: ignore[attr-defined]

            row_path = ttk.Frame(main)
            row_path.pack(fill=tk.X, pady=4)
            ttk.Label(row_path, text="输入：", width=8).pack(side=tk.LEFT)
            ttk.Entry(row_path, textvariable=self.current_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Button(row_path, text="选 YPF", command=self.select_ypf).pack(side=tk.LEFT, padx=4)
            ttk.Button(row_path, text="添加文件", command=self.add_file).pack(side=tk.LEFT)
            ttk.Button(row_path, text="添加文件夹", command=self.add_folder).pack(side=tk.LEFT, padx=4)
            ttk.Button(row_path, text="清空", command=self.clear_inputs).pack(side=tk.LEFT)

            row_out = ttk.Frame(main)
            row_out.pack(fill=tk.X, pady=4)
            ttk.Label(row_out, text="输出：", width=8).pack(side=tk.LEFT)
            ttk.Entry(row_out, textvariable=self.output_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Button(row_out, text="选择", command=self.select_output).pack(side=tk.LEFT, padx=4)

            opts = ttk.Frame(main)
            opts.pack(fill=tk.X, pady=6)
            ttk.Label(opts, text="编码：").pack(side=tk.LEFT)
            enc_values = tuple(dict.fromkeys(COMMON_ENCODINGS))
            ttk.Combobox(opts, textvariable=self.lang, values=enc_values, width=10, state="normal").pack(side=tk.LEFT, padx=(0, 12))
            ttk.Label(opts, text="版本：").pack(side=tk.LEFT)
            ttk.Entry(opts, textvariable=self.version, width=8).pack(side=tk.LEFT, padx=(0, 12))
            ttk.Label(opts, text="模式：").pack(side=tk.LEFT)
            ttk.Combobox(opts, textvariable=self.mode, values=("auto", "extract", "pack"), width=8, state="readonly").pack(side=tk.LEFT, padx=(0, 12))
            ttk.Label(opts, text="根目录：").pack(side=tk.LEFT)
            ttk.Combobox(opts, textvariable=self.include_root, values=("auto", "yes", "no"), width=7, state="readonly").pack(side=tk.LEFT, padx=(0, 12))
            ttk.Checkbutton(opts, text="校验 hash", variable=self.verify_hash).pack(side=tk.LEFT)

            opts2 = ttk.Frame(main)
            opts2.pack(fill=tk.X, pady=(0, 8))
            ttk.Checkbutton(
                opts2,
                text="打包输入目录下的直接子文件夹（选择一个父目录时，把里面多个子文件夹作为多个根目录打入同一个 YPF）",
                variable=self.pack_children,
                command=self._on_pack_children_changed,
            ).pack(side=tk.LEFT)

            actions = ttk.Frame(main)
            actions.pack(fill=tk.X, pady=4)
            ttk.Button(actions, text="自动执行", command=self.run_auto).pack(side=tk.LEFT)
            ttk.Button(actions, text="解包", command=lambda: self.run_task("extract")).pack(side=tk.LEFT, padx=6)
            ttk.Button(actions, text="打包", command=lambda: self.run_task("pack")).pack(side=tk.LEFT)
            ttk.Button(actions, text="查看信息", command=self.show_info).pack(side=tk.LEFT, padx=6)
            ttk.Button(actions, text="清空日志", command=lambda: self.log_text.delete("1.0", tk.END)).pack(side=tk.RIGHT)

            self.log_text = tk.Text(main, height=24, wrap="word")
            self.log_text.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
            self.log("准备就绪。")
            self.log("隐藏兼容参数，核心自动识别 YPF/OP 格式；编码直接使用 cp932/cp949/gbk 等 codec 名称。")
            if not dnd_available:
                self.log("提示：安装 tkinterdnd2 后可以拖拽多个文件夹/文件到窗口。")

        def _set_inputs(self, paths: Sequence[str]) -> None:
            self.input_paths = [str(Path(p)) for p in paths if str(p).strip()]
            self.current_path.set(" ; ".join(self.input_paths))
            p_list = [Path(p) for p in self.input_paths]
            self._suggest_output_from_paths(p_list)
            self._refresh_version_from_selection(p_list)

        def _get_input_paths(self) -> list[Path]:
            text = self.current_path.get().strip()
            if not text:
                return []
            if ";" in text:
                return [Path(x.strip()) for x in text.split(";") if x.strip()]
            if self.input_paths and text == " ; ".join(self.input_paths):
                return [Path(x) for x in self.input_paths]
            return [Path(text)]

        def log(self, msg: str) -> None:
            self.log_text.insert(tk.END, msg.rstrip() + "\n")
            self.log_text.see(tk.END)

        def qlog(self, msg: str) -> None:
            self.task_queue.put(msg)

        def qset_version(self, value: str) -> None:
            self.task_queue.put(("set_version", value))

        def _poll_log_queue(self) -> None:
            try:
                while True:
                    item = self.task_queue.get_nowait()
                    if isinstance(item, tuple) and len(item) == 2 and item[0] == "set_version":
                        self.version.set(str(item[1]))
                    else:
                        self.log(str(item))
            except queue.Empty:
                pass
            self.root.after(100, self._poll_log_queue)

        def _on_drop(self, event) -> None:  # type: ignore[no-untyped-def]
            paths = list(self.root.tk.splitlist(event.data))
            if paths:
                self._set_inputs(paths)

        def _on_pack_children_changed(self) -> None:
            paths = self._get_input_paths()
            if paths:
                self._suggest_output_from_paths(paths)
                self._refresh_version_from_selection(paths)

        def _read_ypf_header_version(self, path: Path) -> int | None:
            try:
                with path.open("rb") as f:
                    head = f.read(YPF_HEADER_SIZE)
                header = YpfHeader.from_bytes(head)
                header.validate()
                return header.version
            except Exception:
                return None

        def _refresh_version_from_selection(self, paths: Sequence[Path]) -> None:
            if not paths:
                return
            if len(paths) == 1 and paths[0].is_file() and paths[0].suffix.lower() == ".ypf":
                if is_mpeg_ps_file(paths[0]):
                    self.version.set("op")
                    return
                ver = self._read_ypf_header_version(paths[0])
                if ver is not None:
                    self.version.set(str(ver))
                    return
            try:
                meta_paths = [Path(p) for p in paths]
                if self.pack_children.get():
                    meta, _ = find_metadata_for_inputs(meta_paths, meta_paths[0] if len(meta_paths) == 1 and meta_paths[0].is_dir() else None)
                else:
                    meta, _ = find_metadata_for_inputs(meta_paths, None)
                if isinstance(meta, dict) and meta.get("version") is not None:
                    self.version.set(str(int(meta.get("version"))))
            except Exception:
                pass

        def _is_video_path(self, p: Path) -> bool:
            return p.is_file() and p.suffix.lower() in VIDEO_EXTENSIONS

        def _suggest_output_from_paths(self, paths: Sequence[Path]) -> None:
            if not paths:
                return
            if len(paths) == 1:
                p = paths[0]
                if p.is_file() and p.suffix.lower() == ".ypf":
                    self.output_path.set(str(p.with_suffix("") if p.stem else p.parent / "Output"))
                elif self._is_video_path(p):
                    self.output_path.set(str(p.parent / "op.ypf"))
                elif p.is_file():
                    self.output_path.set(str(p.with_suffix(".ypf")))
                elif p.is_dir():
                    if self.pack_children.get():
                        self.output_path.set(str(p / "update1.ypf"))
                    else:
                        self.output_path.set(str(p.with_suffix(".ypf")))
                return
            parents = [p.parent if p.is_file() else p.parent for p in paths]
            try:
                base = Path(os.path.commonpath([str(x.resolve()) for x in parents]))
            except Exception:
                base = paths[0].parent
            self.output_path.set(str(base / "update1.ypf"))

        def select_ypf(self) -> None:
            filename = filedialog.askopenfilename(title="选择 YPF 文件", filetypes=[("YPF archive", "*.ypf"), ("All files", "*.*")])
            if filename:
                self.pack_children.set(False)
                self._set_inputs([filename])

        def add_file(self) -> None:
            filename = filedialog.askopenfilename(title="选择输入文件", filetypes=[("Supported", "*.ypf *.mpg *.mpeg *.vob *.mp4 *.mkv *.avi *.mov *.wmv *.webm"), ("All files", "*.*")])
            if filename:
                paths = self._get_input_paths()
                if len(paths) == 1 and paths[0].is_file() and paths[0].suffix.lower() == ".ypf":
                    paths = []
                paths.append(Path(filename))
                self._set_inputs([str(p) for p in paths])

        def add_folder(self) -> None:
            folder = filedialog.askdirectory(title="选择资源文件夹，可重复点击添加多个")
            if folder:
                paths = self._get_input_paths()
                if len(paths) == 1 and paths[0].is_file() and paths[0].suffix.lower() == ".ypf":
                    paths = []
                paths.append(Path(folder))
                self._set_inputs([str(p) for p in paths])

        def clear_inputs(self) -> None:
            self.input_paths = []
            self.current_path.set("")
            self.output_path.set("")
            self.version.set("auto")

        def select_output(self) -> None:
            paths = self._get_input_paths()
            mode = self._detect_mode() if paths else self.mode.get()
            if mode == "extract":
                folder = filedialog.askdirectory(title="选择输出文件夹")
                if folder:
                    self.output_path.set(folder)
            else:
                filename = filedialog.asksaveasfilename(title="保存 YPF", defaultextension=".ypf", filetypes=[("YPF archive", "*.ypf")])
                if filename:
                    self.output_path.set(filename)

        def _detect_mode(self) -> str:
            mode = self.mode.get()
            if mode != "auto":
                return mode
            paths = self._get_input_paths()
            if len(paths) == 1 and paths[0].is_file() and paths[0].suffix.lower() == ".ypf":
                return "extract"
            if paths:
                return "pack"
            return "extract"

        def parse_version(self) -> int | None:
            text = self.version.get().strip().lower()
            if text in ("", "auto", "op"):
                return None
            return int(text, 0)

        def run_auto(self) -> None:
            self.run_task(self._detect_mode())

        def show_info(self) -> None:
            paths = self._get_input_paths()
            if len(paths) != 1 or not paths[0].is_file() or paths[0].suffix.lower() != ".ypf":
                messagebox.showwarning("需要 YPF", "查看信息需要选择一个 .ypf 文件。")
                return

            def worker() -> None:
                try:
                    if is_mpeg_ps_file(paths[0]):
                        self.qlog("--- OP 信息 ---")
                        self.qlog("format: raw MPEG Program Stream video")
                        self.qlog(f"size: {paths[0].stat().st_size / 1024 / 1024:.1f} MB")
                        self.qset_version("op")
                        return
                    ypf = YpfArchive(log=self.qlog)
                    info = ypf.inspect(paths[0], language=self.lang.get())
                    self.qlog("--- YPF 信息 ---")
                    self.qlog(f"version: {info.header.version} / 0x{info.header.version:X}")
                    self.qlog(f"files: {info.header.file_count}")
                    self.qlog(f"header_len: {info.header.file_header_length}")
                    self.qlog(f"table_extra_size: {info.table_extra_field_size}")
                    self.qlog(f"path_key: 0x{info.path_key:02X}")
                    self.qlog(f"reserved_field: {info.has_reserved_field}")
                    self.qlog(f"detected data_hash: {info.detected_hash_mode}")
                    self.qset_version(str(info.header.version))
                except Exception:
                    self.qlog("错误：\n" + traceback.format_exc())

            threading.Thread(target=worker, daemon=True).start()

        def run_task(self, mode: str) -> None:
            paths = self._get_input_paths()
            out = self.output_path.get().strip()
            if not paths:
                messagebox.showwarning("缺少输入", "请先选择或拖入 .ypf 文件/文件夹/视频文件。")
                return
            if not out:
                self._suggest_output_from_paths(paths)
                out = self.output_path.get().strip()
            if not out:
                messagebox.showwarning("缺少输出", "请设置输出路径。")
                return
            try:
                version = self.parse_version()
            except ValueError:
                messagebox.showerror("版本错误", "版本必须是整数，例如 481、500、0x1F4，或 auto。")
                return

            def worker() -> None:
                try:
                    ypf = YpfArchive(log=self.qlog)
                    if mode == "extract":
                        if len(paths) != 1:
                            raise ValueError("解包模式一次只能选择一个 .ypf；多个文件夹请用打包模式。")
                        result = ypf.extract(ExtractOptions(
                            ypf_file=paths[0],
                            output_dir=out,
                            language=self.lang.get(),
                            verify_hash=self.verify_hash.get(),
                        ))
                        if isinstance(result, dict) and result.get("version") is not None:
                            self.qset_version(str(result.get("version")))
                        elif isinstance(result, dict) and result.get("format") == "op_mpeg_ps":
                            self.qset_version("op")
                    else:
                        metadata_dir = paths[0] if self.pack_children.get() and len(paths) == 1 and paths[0].is_dir() else None
                        result = ypf.pack(PackOptions(
                            input_paths=paths,
                            output_ypf=out,
                            language=self.lang.get(),
                            version=version,
                            include_root_mode=self.include_root.get(),
                            metadata_dir=metadata_dir,
                            pack_child_folders=self.pack_children.get(),
                        ))
                        if isinstance(result, dict) and result.get("version") is not None:
                            self.qset_version(str(result.get("version")))
                    self.qlog("完成。")
                except Exception:
                    self.qlog("错误：\n" + traceback.format_exc())

            threading.Thread(target=worker, daemon=True).start()

    root = BaseTk()
    App(root)
    root.mainloop()
