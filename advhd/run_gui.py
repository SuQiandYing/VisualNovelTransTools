# -*- coding: utf-8 -*-
"""两按钮图形界面：输出文本 / 回封文本。

面向「拿到游戏文件 → 翻译 → 装回去」的使用者，不是逆向工程师的控制台
（SKILL.md §11）。界面不暴露 decode_tier / unpack_mode / repack_strategy 等
内部概念，策略由 probe 自动协商。

本文件**不自行解析二进制**，只调用 disassembler / assembler / repack 暴露的
函数，因此经 GUI 与经命令行必须产出相同的产物与证书（§11.9）。

标准库 Tkinter，双击即用；拖放依赖缺失时降级为「选择文件」，不阻止启动。
"""

from __future__ import annotations

import queue
import sys
import threading
import traceback
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

import opcodelist as O
from disassembler import iter_sources
from repack import export_all, plan_repack, run_repack

ENCODINGS = ["cp932", "gbk", "big5", "cp949", "utf-8"]
APP_TITLE = "WS2 文本工具"


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(APP_TITLE)
        root.geometry("720x620")
        root.minsize(660, 580)

        self.input_var = tk.StringVar()
        self.text_out_var = tk.StringVar()
        self.rebuild_from_var = tk.StringVar()
        self.rebuild_out_var = tk.StringVar()
        self.src_enc = tk.StringVar(value=O.DIALECT["encoding"]["source"])
        self.tgt_enc = tk.StringVar(value=O.DIALECT["encoding"]["target"])
        self.want_texts = tk.BooleanVar(value=True)
        self.want_asm = tk.BooleanVar(value=False)
        self.with_ir = tk.BooleanVar(value=False)
        self.emit_plain = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="把脚本文件夹拖进来，或点「浏览」选择")
        self.found = tk.StringVar(value="")

        #: 使用者是否手动改过「回封来源」；改过之后不再自动跟随（§11.4）
        self._from_pinned = False
        self._queue: queue.Queue = queue.Queue()
        self._busy = False
        self._sources: list[Path] = []

        self._build()
        self._enable_dnd()
        self.root.after(100, self._drain)

    # -- 布局 ---------------------------------------------------------------

    def _build(self) -> None:
        pad = dict(padx=10, pady=6)

        top = ttk.LabelFrame(self.root, text="游戏脚本文件夹")
        top.pack(fill="x", **pad)
        row = ttk.Frame(top)
        row.pack(fill="x", padx=10, pady=8)
        ttk.Entry(row, textvariable=self.input_var).pack(
            side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self._pick_input).pack(side="left", padx=(6, 0))
        ttk.Label(top, textvariable=self.found, foreground="#357").pack(
            anchor="w", padx=10, pady=(0, 8))

        enc = ttk.Frame(self.root)
        enc.pack(fill="x", **pad)
        ttk.Label(enc, text="原文编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.src_enc, values=ENCODINGS,
                     width=10).pack(side="left", padx=(4, 18))
        ttk.Label(enc, text="译文编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.tgt_enc, values=ENCODINGS,
                     width=10).pack(side="left", padx=4)

        # ---- 输出文本 ----
        box1 = ttk.LabelFrame(self.root, text="输 出 文 本")
        box1.pack(fill="x", **pad)
        r1 = ttk.Frame(box1)
        r1.pack(fill="x", padx=10, pady=(8, 2))
        ttk.Label(r1, text="到").pack(side="left")
        ttk.Entry(r1, textvariable=self.text_out_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(r1, text="浏览…",
                   command=lambda: self._pick_dir(self.text_out_var, sync=True)
                   ).pack(side="left")
        r2 = ttk.Frame(box1)
        r2.pack(fill="x", padx=10, pady=(0, 4))
        ttk.Checkbutton(r2, text="双行文本（翻译用）", variable=self.want_texts,
                        command=self._refresh_buttons).pack(side="left")
        ttk.Checkbutton(r2, text="ASM 清单（改逻辑用）", variable=self.want_asm,
                        command=self._refresh_buttons).pack(side="left", padx=18)
        self.btn_export = ttk.Button(box1, text="输 出 文 本", command=self._do_export)
        self.btn_export.pack(anchor="e", padx=10, pady=(0, 10))

        # ---- 回封文本 ----
        box2 = ttk.LabelFrame(self.root, text="回 封 文 本")
        box2.pack(fill="x", **pad)
        r3 = ttk.Frame(box2)
        r3.pack(fill="x", padx=10, pady=(8, 2))
        ttk.Label(r3, text="从").pack(side="left")
        ttk.Entry(r3, textvariable=self.rebuild_from_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(r3, text="浏览…", command=self._pick_from).pack(side="left")
        r4 = ttk.Frame(box2)
        r4.pack(fill="x", padx=10, pady=(0, 2))
        ttk.Label(r4, text="到").pack(side="left")
        ttk.Entry(r4, textvariable=self.rebuild_out_var).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(r4, text="浏览…",
                   command=lambda: self._pick_dir(self.rebuild_out_var)
                   ).pack(side="left")
        ttk.Label(box2, text="产物为**加密**脚本，可直接放回游戏；"
                            "同时另存一份明文副本便于比对",
                  foreground="#357").pack(anchor="w", padx=10)
        self.btn_repack = ttk.Button(box2, text="回 封 文 本", command=self._do_repack)
        self.btn_repack.pack(anchor="e", padx=10, pady=(4, 10))

        self.bar = ttk.Progressbar(self.root, mode="determinate")
        self.bar.pack(fill="x", padx=10)
        ttk.Label(self.root, textvariable=self.status, wraplength=680,
                  justify="left").pack(anchor="w", padx=10, pady=6)

        adv = ttk.LabelFrame(self.root, text="详情")
        adv.pack(fill="both", expand=True, **pad)
        ttk.Checkbutton(adv, text="同时导出 IR（排查用）",
                        variable=self.with_ir).pack(anchor="w", padx=10, pady=(6, 0))
        ttk.Checkbutton(adv, text="回封时另存明文副本",
                        variable=self.emit_plain).pack(anchor="w", padx=10)
        self.detail = tk.Text(adv, height=8, wrap="word")
        self.detail.pack(fill="both", expand=True, padx=10, pady=8)
        self.detail.configure(state="disabled")

    # -- 拖放 ---------------------------------------------------------------

    def _enable_dnd(self) -> None:
        try:
            import windnd                              # type: ignore
            windnd.hook_dropfiles(
                self.root,
                func=lambda files: self._set_input(
                    Path(files[0].decode("gbk", "replace"))))
            return
        except Exception:
            pass
        try:
            from tkinterdnd2 import DND_FILES          # type: ignore
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>",
                               lambda e: self._set_input(Path(e.data.strip("{}"))))
        except Exception:
            # 缺依赖时不阻止启动，只提示改用「浏览」（§11.9）
            self.found.set("（未装拖放支持，请用「浏览…」选择文件夹）")

    # -- 路径 ---------------------------------------------------------------

    def _pick_input(self) -> None:
        p = filedialog.askdirectory(title="选择脚本文件夹")
        if p:
            self._set_input(Path(p))

    def _pick_dir(self, var: tk.StringVar, sync: bool = False) -> None:
        p = filedialog.askdirectory(title="选择输出文件夹")
        if not p:
            return
        var.set(p)
        if sync and not self._from_pinned:
            self.rebuild_from_var.set(p)

    def _pick_from(self) -> None:
        p = filedialog.askdirectory(title="选择译文所在文件夹")
        if p:
            self._from_pinned = True          # 手动指定后不再自动跟随
            self.rebuild_from_var.set(p)

    def _set_input(self, path: Path) -> None:
        if path.is_file():
            path = path.parent
        self.input_var.set(str(path))
        # 默认输出与输入**同级**，不在输入目录内部（§11.4）
        self.text_out_var.set(str(path.parent / (path.name + "_text")))
        self.rebuild_out_var.set(str(path.parent / (path.name + "_rebuilt")))
        if not self._from_pinned:
            self.rebuild_from_var.set(self.text_out_var.get())
        try:
            self._sources = iter_sources([path])
        except Exception:
            self._sources = []
        self.found.set("已找到 %d 个脚本文件" % len(self._sources))
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        has_input = bool(self._sources)
        # 两项都不勾时按钮禁用：不产出任何东西的操作不应可点（§11.5.1）
        any_output = self.want_texts.get() or self.want_asm.get()
        self.btn_export.configure(
            state="normal" if (has_input and any_output and not self._busy)
            else "disabled")
        src = Path(self.rebuild_from_var.get() or ".")
        can_repack = has_input and not self._busy and (
            (src / "texts").exists() or (src / "asm").exists())
        self.btn_repack.configure(state="normal" if can_repack else "disabled")
        if has_input and not any_output:
            self.status.set("请至少选择一种输出")

    # -- 后台任务 -----------------------------------------------------------

    def _log(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.insert("end", text + "\n")
        self.detail.see("end")
        self.detail.configure(state="disabled")

    def _progress(self, done: int, total: int, name: str) -> None:
        self._queue.put(("progress", (done, total, name)))

    def _spawn(self, fn) -> None:
        self._busy = True
        self._refresh_buttons()
        self.btn_export.configure(state="disabled")
        self.btn_repack.configure(state="disabled")

        def work() -> None:
            try:
                self._queue.put(("done", fn()))
            except Exception:
                self._queue.put(("error", traceback.format_exc()))

        threading.Thread(target=work, daemon=True).start()

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    done, total, name = payload
                    self.bar.configure(maximum=max(total, 1), value=done)
                    if name:
                        self.status.set("正在处理 %s  (%d/%d)" % (name, done, total))
                elif kind == "done":
                    self._busy = False
                    self._finish(payload)
                    self._refresh_buttons()
                elif kind == "error":
                    self._busy = False
                    self.status.set("出错了，详情见下方")
                    self._log(payload)
                    self._refresh_buttons()
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _finish(self, result: dict) -> None:
        s = result.get("summary", {})
        if result.get("kind") == "export":
            self.status.set(
                "已导出 %s 条到 %s（%d 个文件，往返自检全部通过）"
                % (f"{s.get('texts', 0):,}", s.get("output"), s.get("files_ok", 0)))
            self._log("文件 %d / 失败 %d｜字节 %s｜条目 %s｜分类 %s"
                      % (s.get("files_ok", 0), s.get("files_failed", 0),
                         f"{s.get('bytes', 0):,}", f"{s.get('texts', 0):,}",
                         s.get("tags")))
        else:
            self.status.set("已回封 %d 个文件到 %s（加密产物）"
                            % (s.get("files_written", 0), s.get("output")))
            self._log("改动 %d 条（其中 %d 条变长，共 %+d 字节）｜方式 %s"
                      % (s.get("changed_entries", 0), s.get("longer_entries", 0),
                         s.get("delta_bytes", 0), "、".join(s.get("strategies", []))))
        for e in result.get("errors", [])[:20]:
            self._log("  ! %s %s" % (e.get("file", ""), e.get("detail", "")))

    # -- 两个按钮 -----------------------------------------------------------

    def _do_export(self) -> None:
        root_dir = Path(self.input_var.get())
        out = Path(self.text_out_var.get())
        if out.exists() and any(out.iterdir()):
            if not messagebox.askyesno(
                    APP_TITLE, "输出目录已有内容：\n%s\n\n覆盖？" % out):
                return
        srcs = self._sources

        def job() -> dict:
            r = export_all(srcs, root_dir, out,
                           want_texts=self.want_texts.get(),
                           want_asm=self.want_asm.get(),
                           source_encoding=self.src_enc.get(),
                           target_encoding=self.tgt_enc.get(),
                           with_ir=self.with_ir.get(),
                           progress=self._progress)
            r["kind"] = "export"
            return r

        self._spawn(job)

    def _do_repack(self) -> None:
        root_dir = Path(self.input_var.get())
        text_dir = Path(self.rebuild_from_var.get())
        out = Path(self.rebuild_out_var.get())
        srcs = self._sources

        # 点击后先出预览，可取消；取消后无任何产物写出（§11.5.3）
        self.status.set("正在检查译文…")

        def preview() -> dict:
            p = plan_repack(srcs, root_dir, text_dir,
                            source_encoding=self.src_enc.get(),
                            target_encoding=self.tgt_enc.get(),
                            progress=self._progress)
            p["kind"] = "preview"
            return p

        def after(plan: dict) -> None:
            if plan["conflicts"]:
                self._log("发现 %d 处冲突，已停止：" % len(plan["conflicts"]))
                for c in plan["conflicts"][:20]:
                    self._log("  第 %d 条：文本侧=%r  ASM 侧=%s"
                              % (c["idx"], c["texts_value"], c["asm_line"]))
                messagebox.showerror(APP_TITLE,
                                     "两处编辑对同一条给出不同内容，请先处理冲突。")
                return
            if plan["errors"]:
                self._log("译文有 %d 处问题，已停止：" % len(plan["errors"]))
                for e in plan["errors"][:25]:
                    self._log("  %s：%s" % (e.get("file", ""), e.get("detail", "")))
                messagebox.showerror(APP_TITLE, "译文校验未通过，详情见「详情」。")
                return
            msg = ("将回封 %d 个文件\n\n"
                   "  改动    %s 条译文（其中 %d 条变长，共 %+d 字节）\n"
                   "  方式    %s（自动选择）\n"
                   "  冲突    0\n"
                   "  输出到  %s\n\n产物为加密脚本。执行？"
                   % (plan["files"], f"{plan['changed_entries']:,}",
                      plan["longer_entries"], plan["delta_bytes"],
                      "、".join(plan["strategies"]) or "无改动",
                      out))
            if not messagebox.askokcancel(APP_TITLE, msg):
                self.status.set("已取消，未写出任何文件")
                return

            def job() -> dict:
                r = run_repack(srcs, root_dir, text_dir, out,
                               source_encoding=self.src_enc.get(),
                               target_encoding=self.tgt_enc.get(),
                               emit_plain=self.emit_plain.get(),
                               progress=self._progress)
                r["kind"] = "repack"
                return r

            self._spawn(job)

        def work() -> None:
            try:
                plan = preview()
                self.root.after(0, lambda: (setattr(self, "_busy", False),
                                            self._refresh_buttons(), after(plan)))
            except Exception:
                tb = traceback.format_exc()
                self.root.after(0, lambda: (setattr(self, "_busy", False),
                                            self._refresh_buttons(),
                                            self._log(tb)))

        self._busy = True
        self._refresh_buttons()
        threading.Thread(target=work, daemon=True).start()


def main() -> int:
    try:
        from tkinterdnd2 import TkinterDnD             # type: ignore
        root = TkinterDnD.Tk()
    except Exception:
        root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
