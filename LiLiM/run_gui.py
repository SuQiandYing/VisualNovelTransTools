# -*- coding: utf-8 -*-
"""两按钮图形界面（§11）。

界面服务于「拿到游戏文件 → 翻译 → 装回去」的使用者，不是逆向工程师的控制台：
- 不出现 decode_tier / unpack_mode / repack_strategy / collision_class 等内部概念（§11.1）
- 拖入即推导全部路径，不填任何参数即可运行（§11.1 零配置）
- 回封前先出一次可取消的预览（§11.5.3）
- 不设「全量反汇编」按钮；往返自检在按钮内部照常执行（§11.2）
- 自身不解析二进制，只调用 disassembler / assembler 的函数（§11.9）
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

import assembler as ASM
import disassembler as DIS
import opcodelist as D

ENCODINGS = ["cp932", "gbk", "big5", "cp949", "utf-8"]

# 内部概念 → 界面说法（§11.1：策略由 probe 自动协商，界面只显示结果）
STRATEGY_LABEL = {
    "identity": "原样重建",
    "in_place": "等长覆写",
    "pointer-rewrite": "引用回填（自动选择）",
    "full-layout": "重排布局",
}


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("游戏文本提取 / 装回")
        root.geometry("900x620")
        root.minsize(760, 560)

        self.src = tk.StringVar()
        self.found = tk.StringVar(value="把游戏的 .aos 文件拖进来，或点右侧选择")
        self.text_out = tk.StringVar()
        self.rebuilt_out = tk.StringVar()
        self.repack_from = tk.StringVar()
        self.enc_src = tk.StringVar(value=D.SCRIPT["source_encoding"])
        self.enc_dst = tk.StringVar(value=D.SCRIPT["target_encoding"])
        self.want_texts = tk.BooleanVar(value=True)
        self.want_asm = tk.BooleanVar(value=False)
        self.want_ir = tk.BooleanVar(value=False)

        # 「从」是否被使用者单独改过：改过之后不再跟随文本输出（§11.4 第三条）
        self.from_pinned = False
        self.text_out.trace_add("write", self._text_out_changed)
        self.want_texts.trace_add("write", lambda *_: self._sync_buttons())
        self.want_asm.trace_add("write", lambda *_: self._sync_buttons())

        self.log_q: queue.Queue[tuple[str, object]] = queue.Queue()
        self.busy = False
        self.cancel = threading.Event()
        self.details: dict[str, str] = {}

        self._build()
        self._pump()
        self._sync_buttons()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        pad = {"padx": 10, "pady": 6}

        # --- 输入 ---
        f_in = ttk.LabelFrame(self.root, text="游戏脚本文件")
        f_in.pack(fill="x", **pad)
        row = ttk.Frame(f_in)
        row.pack(fill="x", padx=8, pady=(6, 0))
        ttk.Entry(row, textvariable=self.src).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self._pick_src).pack(side="left", padx=(6, 0))
        ttk.Label(f_in, textvariable=self.found, foreground="#555").pack(
            anchor="w", padx=8, pady=(2, 6))

        # --- 编码 ---
        f_enc = ttk.Frame(self.root)
        f_enc.pack(fill="x", **pad)
        ttk.Label(f_enc, text="原文编码").pack(side="left")
        ttk.Combobox(f_enc, textvariable=self.enc_src, values=ENCODINGS,
                     width=12).pack(side="left", padx=(4, 20))
        ttk.Label(f_enc, text="译文编码").pack(side="left")
        ttk.Combobox(f_enc, textvariable=self.enc_dst, values=ENCODINGS,
                     width=12).pack(side="left", padx=4)

        # --- 操作一：输出文本 ---
        f_out = ttk.LabelFrame(self.root, text="输 出 文 本")
        f_out.pack(fill="x", **pad)
        r1 = ttk.Frame(f_out)
        r1.pack(fill="x", padx=8, pady=(6, 2))
        ttk.Label(r1, text="到").pack(side="left")
        ttk.Entry(r1, textvariable=self.text_out).pack(side="left", fill="x",
                                                      expand=True, padx=4)
        ttk.Button(r1, text="浏览…",
                   command=lambda: self._pick_dir(self.text_out)).pack(side="left")
        r2 = ttk.Frame(f_out)
        r2.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Checkbutton(r2, text="双行文本（翻译用）",
                        variable=self.want_texts).pack(side="left")
        ttk.Checkbutton(r2, text="ASM 清单（改逻辑用）",
                        variable=self.want_asm).pack(side="left", padx=18)
        self.b_out = ttk.Button(r2, text="输 出 文 本", command=self._do_extract)
        self.b_out.pack(side="right", ipadx=14, ipady=3)
        self.hint_out = ttk.Label(f_out, text="", foreground="#a00")
        self.hint_out.pack(anchor="w", padx=8, pady=(0, 5))

        # --- 操作二：回封文本 ---
        f_rp = ttk.LabelFrame(self.root, text="装 回 游 戏")
        f_rp.pack(fill="x", **pad)
        r3 = ttk.Frame(f_rp)
        r3.pack(fill="x", padx=8, pady=(6, 2))
        ttk.Label(r3, text="从").pack(side="left")
        ttk.Entry(r3, textvariable=self.repack_from).pack(side="left", fill="x",
                                                         expand=True, padx=4)
        ttk.Button(r3, text="浏览…",
                   command=self._pick_from).pack(side="left")
        r4 = ttk.Frame(f_rp)
        r4.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Label(r4, text="到").pack(side="left")
        ttk.Entry(r4, textvariable=self.rebuilt_out).pack(side="left", fill="x",
                                                         expand=True, padx=4)
        ttk.Button(r4, text="浏览…",
                   command=lambda: self._pick_dir(self.rebuilt_out)).pack(side="left")
        self.b_rp = ttk.Button(r4, text="装 回 游 戏", command=self._do_repack)
        self.b_rp.pack(side="right", ipadx=14, ipady=3, padx=(6, 0))
        self.hint_rp = ttk.Label(f_rp, text="", foreground="#a00")
        self.hint_rp.pack(anchor="w", padx=8, pady=(0, 5))

        # --- 进度 ---
        f_pg = ttk.Frame(self.root)
        f_pg.pack(fill="x", **pad)
        self.prog = ttk.Progressbar(f_pg, mode="determinate", maximum=100)
        self.prog.pack(side="left", fill="x", expand=True)
        self.status = ttk.Label(f_pg, text="就绪", width=42)
        self.status.pack(side="left", padx=8)
        self.b_cancel = ttk.Button(f_pg, text="取消", command=self._do_cancel)
        self.b_cancel.pack(side="left")
        self.b_cancel.state(["disabled"])

        # --- 详情折叠区（§11.8）---
        self.show_details = tk.BooleanVar(value=False)
        self.b_det = ttk.Checkbutton(self.root, text="▸ 详情",
                                     variable=self.show_details,
                                     command=self._toggle_details)
        self.b_det.pack(anchor="w", padx=12)
        self.f_det = ttk.Frame(self.root)
        ttk.Checkbutton(self.f_det, text="同时导出 IR（排查用）",
                        variable=self.want_ir).pack(anchor="w", padx=8, pady=2)
        self.txt = tk.Text(self.f_det, height=16, wrap="none",
                          font=("Consolas", 9), state="disabled")
        self.txt.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def _toggle_details(self) -> None:
        if self.show_details.get():
            self.b_det.configure(text="▾ 详情")
            self.f_det.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        else:
            self.b_det.configure(text="▸ 详情")
            self.f_det.forget()

    # -- 路径与自动推导（§11.4）------------------------------------------
    def _pick_src(self) -> None:
        p = filedialog.askopenfilename(
            title="选择游戏脚本文件",
            filetypes=[("游戏归档", "*.aos"), ("全部文件", "*.*")])
        if p:
            self.set_source(Path(p))

    def set_source(self, p: Path) -> None:
        """设置输入并推导两个输出路径。默认与输入**同级**，不在输入目录内部。"""
        p = p.resolve()
        self.src.set(str(p))
        base = p.parent / p.stem
        self.text_out.set(f"{base}_text")
        self.rebuilt_out.set(f"{base}_rebuilt")
        self.from_pinned = False
        self.repack_from.set(self.text_out.get())
        try:
            n = DIS.count_entries(p)
            self.found.set(f"已找到 {n} 个脚本文件")
        except Exception as exc:
            self.found.set(f"无法读取：{exc}")
        self._sync_buttons()

    def _text_out_changed(self, *_: object) -> None:
        # 回封的「从」默认跟随文本输出；单独改过之后不再跟随
        if not self.from_pinned:
            self.repack_from.set(self.text_out.get())

    def _pick_from(self) -> None:
        p = filedialog.askdirectory(title="选择译文所在目录")
        if p:
            self.from_pinned = True
            self.repack_from.set(p)

    def _pick_dir(self, var: tk.StringVar) -> None:
        p = filedialog.askdirectory(title="选择目录")
        if p:
            var.set(p)

    def _sync_buttons(self) -> None:
        ok_src = bool(self.src.get().strip()) and Path(self.src.get().strip()).is_file()
        # 两项都不勾时按钮禁用并提示（§11.5.1）
        any_kind = self.want_texts.get() or self.want_asm.get()
        if not any_kind:
            self.hint_out.configure(text="请至少选择一种输出")
        else:
            self.hint_out.configure(text="")
        self.b_out.state(["!disabled"] if (ok_src and any_kind and not self.busy)
                         else ["disabled"])

        # 回封需要「从」目录里确实有可读的产物（§11.5.2）
        src_dir = Path(self.repack_from.get().strip() or ".")
        has = (src_dir / "texts").is_dir() or (src_dir / "asm").is_dir()
        if ok_src and not has:
            self.hint_rp.configure(text="先输出文本")
        else:
            self.hint_rp.configure(text="")
        self.b_rp.state(["!disabled"] if (ok_src and has and not self.busy)
                        else ["disabled"])

    def _overwrite_ok(self, d: Path, what: str) -> bool:
        """目标目录已有同名产物时提示，不静默覆盖（§11.4 第四条）。"""
        if not d.exists() or not any(d.iterdir()):
            return True
        return messagebox.askyesno(
            "目录已有内容",
            f"{d}\n\n里面已经有{what}。\n\n覆盖？（选「否」请先改上面的输出路径）")

    # -- 日志与进度 ------------------------------------------------------
    def log(self, s: str = "") -> None:
        self.log_q.put(("log", s))

    def progress(self, done: int, total: int, name: str) -> None:
        self.log_q.put(("prog", (done, total, name)))

    def _pump(self) -> None:
        try:
            while True:
                kind, payload = self.log_q.get_nowait()
                if kind == "log":
                    self.txt.configure(state="normal")
                    self.txt.insert("end", str(payload) + "\n")
                    self.txt.see("end")
                    self.txt.configure(state="disabled")
                elif kind == "prog":
                    done, total, name = payload           # type: ignore[misc]
                    pct = (done / total * 100) if total else 0
                    self.prog.configure(value=pct)
                    self.status.configure(
                        text=f"正在处理 {name}  {pct:.0f}%" if name else "完成")
                elif kind == "status":
                    self.status.configure(text=str(payload))
        except queue.Empty:
            pass
        self.root.after(70, self._pump)

    def _run_bg(self, fn) -> None:
        if self.busy:
            return
        self.busy = True
        self.cancel.clear()
        self._sync_buttons()
        self.b_cancel.state(["!disabled"])

        def wrap() -> None:
            try:
                fn()
            except Exception as exc:
                self.log_q.put(("status", "失败，详情见下方"))
                self.log("")
                for line in self._humanize(exc).splitlines():
                    self.log(line)
                self.details["last_error"] = traceback.format_exc()
                self.log("")
                self.log("（完整技术信息已记入详情，可贴给开发者）")
                self.log(self.details["last_error"])
                if not self.show_details.get():
                    self.root.after(0, lambda: (self.show_details.set(True),
                                                self._toggle_details()))
            finally:
                self.busy = False
                self.root.after(0, lambda: (self.b_cancel.state(["disabled"]),
                                            self._sync_buttons()))

        threading.Thread(target=wrap, daemon=True).start()

    @staticmethod
    def _humanize(exc: Exception) -> str:
        """错误用自然语言呈现，不抛 reason_code（§11.1）。"""
        if isinstance(exc, ASM.ConflictError):
            return ("同一句话在「双行文本」和「ASM 清单」里被改成了两个不同的样子，\n"
                    "无法判断该用哪个。请先改成一致，或只保留一处修改。\n\n"
                    + str(exc))
        if isinstance(exc, ASM.ImportError_):
            return "译文文件没通过检查：\n" + str(exc)
        if isinstance(exc, A_ParseError):
            return "这个文件读不出来，可能不是本工具支持的格式：\n" + str(exc)
        return f"{type(exc).__name__}：{exc}"

    def _do_cancel(self) -> None:
        self.cancel.set()
        self.log_q.put(("status", "正在取消…"))

    # -- 按钮一：输出文本 ------------------------------------------------
    def _do_extract(self) -> None:
        src = Path(self.src.get().strip())
        out = Path(self.text_out.get().strip())
        if not self._overwrite_ok(out, "上次导出的文本"):
            return
        want_t, want_a = self.want_texts.get(), self.want_asm.get()
        enc = (self.enc_src.get().strip(), self.enc_dst.get().strip())

        def job() -> None:
            self.log(f"读取 {src.name} …")
            r = DIS.run_extract(
                src, out, want_texts=want_t, want_asm=want_a,
                with_ir=self.want_ir.get(),
                source_encoding=enc[0], target_encoding=enc[1],
                progress=self.progress, cancelled=self.cancel.is_set)
            if r is None:
                self.log_q.put(("status", "已取消，未写出产物"))
                self.log("已取消。原文件与已通过验证的产物均未改动。")
                return
            self.log(f"  共 {r['entries']} 个脚本文件")
            if want_t:
                self.log(f"  可翻译 {r['policy_counts']['translatable']} 条，"
                         f"需确认 {r['policy_counts']['review-required']} 条，"
                         f"锁定 {r['policy_counts']['frozen']} 条")
            self.log_q.put(("status", f"已导出 {r['text_entries']} 条"))
            self.log(f"完成 → {out}")
            self.log("翻译时只改 ● 开头那行，改完点「装 回 游 戏」。")
            self._record_details(r)
            self.root.after(0, self._sync_buttons)

        self._run_bg(job)

    # -- 按钮二：装回游戏（先预览，§11.5.3）------------------------------
    def _do_repack(self) -> None:
        src = Path(self.src.get().strip())
        frm = Path(self.repack_from.get().strip())
        dst = Path(self.rebuilt_out.get().strip())

        def job() -> None:
            self.log_q.put(("status", "正在检查译文…"))
            pv = ASM.probe(src, frm)
            self.root.after(0, lambda: self._preview(pv, src, frm, dst))

        self._run_bg(job)

    def _preview(self, pv: dict, src: Path, frm: Path, dst: Path) -> None:
        win = tk.Toplevel(self.root)
        win.title("确认")
        win.transient(self.root)
        win.grab_set()
        body = tk.Text(win, height=13, width=76, font=("Consolas", 10))
        body.pack(padx=12, pady=12, fill="both", expand=True)

        d = pv["estimated_text_delta"]
        lines = [f"将装回 {src.name}", ""]
        if pv["conflicts"]:
            lines += ["发现冲突，无法继续：", ""]
            for c in pv["conflicts"][:20]:
                lines.append(f"  第 {c['idx']} 条（{c['source']}）")
                lines.append(f"    双行文本： {c['texts']}")
                lines.append(f"    ASM 清单： {c['asm']}")
            lines += ["", "同一句被改成两个样子，请先改成一致。"]
        else:
            lines += [
                f"  改动    {pv['changed_entries']} 条译文"
                f"（其中 {pv['grew_entries']} 条变长，共 {d:+d} 字节）",
                f"  涉及    {pv['changed_files']} 个脚本文件",
                f"  方式    {STRATEGY_LABEL.get(pv['strategy'], pv['strategy'])}",
                f"  冲突    {len(pv['conflicts'])}",
                f"  输出到  {dst}",
            ]
            if pv.get("widened_chars"):
                lines.append(
                    f"  全角化  {pv['widened_entries']} 条里的 {pv['widened_chars']} 个半角字符"
                    f"（游戏按 2 字节显示正文，半角会把后面的字切断）")
            if pv.get("cell_width_errors"):
                lines += ["", "以下条目含无法转成全角的字符，无法装回："]
                for e in pv["cell_width_errors"][:10]:
                    lines.append(f"  {e['source']} 第 {e['idx']} 条："
                                 f"{'、'.join(repr(c) for c in e['chars'][:6])}")
            if pv["changed_entries"] == 0:
                lines += ["", "没有检测到任何改动，装回后的文件与原件完全相同。"]
        body.insert("1.0", "\n".join(lines))
        body.configure(state="disabled")

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=12, pady=(0, 12))

        def go() -> None:
            win.destroy()
            if not self._overwrite_ok(dst, "上次装回的文件"):
                return

            def job() -> None:
                self.log_q.put(("status", "正在装回…"))
                rep = ASM.repack(src, frm, verdict=pv, rebuilt_dir=dst)
                v = rep["verdict"]
                self.log(f"  方式 {STRATEGY_LABEL.get(rep['selected_strategy'])}"
                         f"，改动 {rep['changed_text_entries']} 条，"
                         f"长度 {rep['length_delta']:+d} 字节")
                for c in v["checks"]:
                    if not c["ok"]:
                        self.log(f"  检查未通过：{c['check']} {c['detail']}")
                if v["ok"]:
                    self.log_q.put(("status", "装回完成"))
                    self.log(f"完成 → {rep['output']}")
                    self.log("把这个文件复制回游戏目录即可（建议先备份原件）。")
                else:
                    self.log_q.put(("status", "校验未通过，未产出文件"))
                    self.log("装回后的文件没通过自检，已保留在临时目录供排查，"
                             "未放进输出目录。原文件未改动。")
                self._record_details(rep)

            self._run_bg(job)

        if not pv["conflicts"] and not pv.get("cell_width_errors"):
            ttk.Button(bar, text="执 行", command=go).pack(side="right", ipadx=12)
        ttk.Button(bar, text="取 消", command=win.destroy).pack(side="right", padx=8)

    # -- 详情（§11.8）----------------------------------------------------
    def _record_details(self, r: dict) -> None:
        for k, v in r.items():
            if not isinstance(v, (dict, list)):
                self.details[k] = str(v)


try:
    from aoslib import ParseError as A_ParseError
except Exception:                                    # pragma: no cover
    A_ParseError = Exception                         # type: ignore[assignment,misc]


def parse_drop(data: str) -> Path | None:
    """从 <<Drop>> 事件的 data 取出第一个路径。

    tkdnd 用 Tcl 列表传路径：含空格的路径会被 {} 包起来，多文件以空格分隔。
    本工具一次只处理一个归档，故取第一个存在的文件。
    """
    # 先把整串当单个路径试：部分 tkdnd 版本对含空格的路径不加花括号，
    # 此时按空白切开会把路径碎掉。
    whole = Path(data.strip().strip("{}").strip('"'))
    if whole.is_file():
        return whole

    items: list[str] = []
    if "{" in data:
        # 逐个取出 {…} 分组，再把剩下的按空白切开
        rest = data
        while "{" in rest:
            i, j = rest.index("{"), rest.index("}")
            items.append(rest[i + 1:j])
            rest = rest[:i] + " " + rest[j + 1:]
        items += rest.split()
    else:
        items = data.split()
    for s in items:
        p = Path(s.strip().strip('"'))
        if p.is_file():
            return p
    return None


def make_root() -> tuple[tk.Tk, str]:
    """建根窗口。能用拖放就用支持拖放的那种，否则回落普通 Tk（§11.9：不阻止启动）。

    必须在**建根窗口时**决定：drop_target_register 是 TkinterDnD.Tk 才有的方法，
    普通 tk.Tk() 建好之后再想注册是不可能的。
    """
    try:
        from tkinterdnd2 import TkinterDnD
        return TkinterDnD.Tk(), "dnd"
    except Exception as exc:
        root = tk.Tk()
        # 库缺失与初始化失败是两回事，分别记录——否则装了库却用不上时，
        # 界面会谎称「未安装」，使用者只能去查自己的环境。
        root._dnd_error = f"{type(exc).__name__}: {exc}"   # type: ignore[attr-defined]
        return root, "none"


def main() -> int:
    root, mode = make_root()
    app = App(root)

    if mode == "dnd":
        try:
            from tkinterdnd2 import DND_FILES
            root.drop_target_register(DND_FILES)         # type: ignore[attr-defined]

            def on_drop(event: object) -> None:
                p = parse_drop(getattr(event, "data", ""))
                if p is None:
                    app.found.set("拖进来的不是文件，请拖 .aos 归档")
                else:
                    app.set_source(p)

            root.dnd_bind("<<Drop>>", on_drop)           # type: ignore[attr-defined]
        except Exception as exc:
            app.found.set(f"拖放不可用（{type(exc).__name__}），"
                          f"请点「浏览…」选择文件")
    else:
        why = getattr(root, "_dnd_error", "")
        app.found.set("请点「浏览…」选择文件"
                      + ("（未安装拖放组件，不影响使用）" if "ModuleNotFound" in why
                         else f"（拖放初始化失败：{why[:60]}）" if why
                         else ""))

    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        app.set_source(Path(sys.argv[1]))
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
