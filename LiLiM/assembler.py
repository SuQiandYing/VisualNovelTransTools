# -*- coding: utf-8 -*-
"""源归档 + texts/ 与 asm/ 的改动 → 重建归档（§2.6 / §6）。

不解析完整 asm 语法：重新解析源二进制得到新鲜投影，只 diff 用户实际改动的行
（§2.6），因此无需 ASM 解析器，冲突检出是集合交集的自然结果。

命令行：
    python assembler.py OUTDIR                 从 OUTDIR/texts 回封
    python assembler.py OUTDIR --archive A.aos 显式指定源归档
拖放：把 output 目录拖到本文件图标上。
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aoslib as A
import disassembler as DIS
import opcodelist as D

_ERR_PREVIEW = 80  # dialect-literal-ok: 报错信息的截断长度，不参与解析

ORIG_RE = re.compile(r"^○(?P<idx>\d{8})○(?P<tag>[a-z_]+)○(?P<text>.*)$")
TRAN_RE = re.compile(r"^●(?P<idx>\d{8})●(?P<tag>[a-z_]+)●(?P<text>.*)$")
ASM_LINE_RE = re.compile(r'^L(?P<lineno>\d{6})\s+\.line\s+(?P<shape>\S+)\s+"(?P<body>.*)"'
                         r'(?:\s+;\s*(?P<cmt>.*))?$')


class ImportError_(Exception):
    """导入校验失败，拒绝整个文件（§4.9）。"""


class ConflictError(Exception):
    """两个编辑面改同一对象且取值不同（§2.6）。"""


# --------------------------------------------------------------------------
# 文本编辑面：解析双行文件并逐条校验（§4.9 的 13 条）
# --------------------------------------------------------------------------
def load_dsat(path: Path, ir: A.ScriptIR) -> dict[int, str]:
    text = path.read_text(encoding=D.SCRIPT["text_encoding"])
    lines = text.splitlines()
    if len(lines) < 4:
        raise ImportError_(f"{path.name} 文件头不足 4 行")

    m = re.match(r"^# TEXT/(\d+)\s", lines[0])
    if not m:
        raise ImportError_(f"{path.name} 第 1 行不是 '# TEXT/N …'")
    hdr = dict(re.findall(r"(\w+)=(\S+)", lines[0]))
    if hdr.get("src_sha256") != ir.src_sha256:
        raise ImportError_(
            f"{path.name} src_sha256 与当前 IR 不符（用旧 dump 导入？）\n"
            f"    文件: {hdr.get('src_sha256')}\n    IR  : {ir.src_sha256}")
    enc = dict(re.findall(r"(\w+)=(\S+)", lines[1]))
    if enc.get("target") != D.SCRIPT["target_encoding"]:
        raise ImportError_(f"{path.name} target 编码 {enc.get('target')} 与方言不符")
    scope = dict(re.findall(r"(\w+)=(\S+)", lines[2]))
    part = scope.get("part", "1/1")
    k, n = (int(x) for x in part.split("/"))
    if (k, n) != (1, 1):
        raise ImportError_(f"{path.name} 分片 {part}：本工具只导出整片，缺片必须拒绝")

    by_idx = {s.idx: s for s in ir.slots}
    edits: dict[int, str] = {}
    seen: set[int] = set()
    pending: dict[str, Any] = {}
    i = 4
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith("#"):
            pending = dict(re.findall(r"(\w+)=(\S+)", line))
            i += 1
            continue
        mo = ORIG_RE.match(line)
        if not mo:
            raise ImportError_(f"{path.name}:{i+1} 不是合法原文行（分隔符混用或行被改坏）")
        if i + 1 >= len(lines):
            raise ImportError_(f"{path.name}:{i+1} 原文行后缺译文行")
        mt = TRAN_RE.match(lines[i + 1])
        if not mt:
            raise ImportError_(f"{path.name}:{i+2} 不是合法译文行")

        idx = int(mo.group("idx"))
        if idx in seen:
            raise ImportError_(f"{path.name} idx={idx} 重复")
        seen.add(idx)
        if int(mt.group("idx")) != idx:
            raise ImportError_(f"{path.name}:{i+2} 两行 idx 不一致")
        if mo.group("tag") != mt.group("tag"):
            raise ImportError_(f"{path.name} idx={idx} 两行 tag 不一致")
        slot = by_idx.get(idx)
        if slot is None:
            raise ImportError_(f"{path.name} idx={idx} 不存在于该源")
        if pending.get("idx") and int(pending["idx"]) != idx:
            raise ImportError_(f"{path.name} idx={idx} 注释块与条目错位")
        if mo.group("tag") != slot.tag:
            raise ImportError_(f"{path.name} idx={idx} tag 与 IR 不符")
        if mo.group("text") != DIS.to_display(slot.source):
            raise ImportError_(
                f"{path.name} idx={idx} 原文行与 IR 不一致（错位/误改/旧文件/编辑器替换）\n"
                f"    IR  : {DIS.to_display(slot.source)[:_ERR_PREVIEW]!r}\n"
                f"    文件: {mo.group('text')[:_ERR_PREVIEW]!r}")
        dst = mt.group("text")
        if not dst:
            raise ImportError_(f"{path.name} idx={idx} 译文行为空（预填原文后空行即误删）")
        if slot.translate_policy == "frozen" and dst != mo.group("text"):
            raise ImportError_(f"{path.name} idx={idx} 标记 frozen 却被改动")
        if dst != mo.group("text"):
            # 转义先于其他校验：写错的转义必须当场报错，不能当普通字符放过（铁律 4）
            try:
                plain = DIS.from_display(dst)
            except A.BadEscape as exc:
                raise ImportError_(f"{path.name} idx={idx} {exc}") from None
            try:
                plain.encode(D.SCRIPT["target_encoding"])
            except UnicodeEncodeError as exc:
                raise ImportError_(
                    f"{path.name} idx={idx} 译文含 {D.SCRIPT['target_encoding']} "
                    f"不可表示的字符：{exc.object[exc.start]!r}") from None
            if re.findall(r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}", dst) != \
               re.findall(r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}", mo.group("text")):
                raise ImportError_(f"{path.name} idx={idx} 占位符集合被改动")
            # 折行条目的换行数必须与原文一致：少一个 \n 就无法判断新的断行落在哪。
            # 按**还原后**的真实换行计数，不按显示串——显示串里的 `\\n`
            # （字面反斜杠 + n）含有 `\n` 子串，按串计数会误判。
            term = D.SCRIPT["line_terminator"]
            n_old = slot.source.count(term)
            n_new = plain.count(term)
            if n_old != n_new:
                raise ImportError_(
                    f"{path.name} idx={idx} 换行数被改动：原文有 {n_old} 处换行，"
                    f"译文有 {n_new} 处。" + r"请保留原来的 \n，数量与位置不变")
            # 正文格子宽度（EV_TEXT_CELL）的全角化统一在 probe 里做，不在此处——
            # 两处都转会让 probe 数不到半角字符，预览显示的全角化条数恒为 0。
            edits[idx] = plain
        i += 2
    return edits


# --------------------------------------------------------------------------
# 结构编辑面：对新鲜投影做 diff（§2.6）
# --------------------------------------------------------------------------
def load_asm_edits(path: Path, ir: A.ScriptIR) -> dict[int, str]:
    """只取用户实际改动的行。改字符串按文本处理；改结构需 T3，本方言不足即拒绝。"""
    fresh = DIS.render_asm_text(ir).splitlines()
    user = path.read_text(encoding=D.SCRIPT["asm_encoding"]).splitlines()
    if fresh == user:
        return {}
    if len(fresh) != len(user):
        raise ImportError_(
            f"{path.name} 行数与新鲜投影不同（增删行属结构改动，需 "
            f"T3，当前申报 {D.DECODE_TIER['script']}）")

    slots_by_line: dict[int, list[A.TextSlot]] = {}
    for s in ir.slots:
        slots_by_line.setdefault(s.lineno, []).append(s)

    edits: dict[int, str] = {}
    for lineno_asm, (fl, ul) in enumerate(zip(fresh, user)):
        if fl == ul:
            continue
        fm, um = ASM_LINE_RE.match(fl), ASM_LINE_RE.match(ul)
        if not fm or not um:
            raise ImportError_(f"{path.name}:{lineno_asm+1} 改动了非 .line 记录"
                              f"（头部/伪指令属结构改动，需 T3）")
        if fm.group("shape") != um.group("shape") or fm.group("lineno") != um.group("lineno"):
            raise ImportError_(f"{path.name}:{lineno_asm+1} 改动了形态或行号")
        src_line = ir.lines[int(fm.group("lineno"))]
        new_line = DIS.from_display(um.group("body"))
        group = slots_by_line.get(int(fm.group("lineno")), [])
        if not group:
            raise ImportError_(f"{path.name}:{lineno_asm+1} 该行无文本槽位，"
                              f"改动属结构改动，需 T3")
        # 只允许槽位内容变化：槽位外的字符必须逐字相同
        rebuilt = src_line
        ok = False
        for s in sorted(group, key=lambda x: x.col_start, reverse=True):
            prefix, suffix = src_line[:s.col_start], src_line[s.col_end:]
            if new_line.startswith(prefix) and new_line.endswith(suffix) and \
               len(new_line) >= len(prefix) + len(suffix):
                cand = new_line[len(prefix):len(new_line) - len(suffix) or None]
                if len(group) == 1 or cand != s.source:
                    edits[s.idx] = cand
                    ok = True
                    break
        if not ok:
            raise ImportError_(f"{path.name}:{lineno_asm+1} 改动落在文本槽位之外，"
                              f"属结构改动，需 T3")
    return edits


# --------------------------------------------------------------------------
# 重建（§6.0.3 传播；容器首尾相接故为纯 pointer-rewrite）
# --------------------------------------------------------------------------
def rebuild_archive(arc: A.Archive, new_content: dict[int, bytes]) -> tuple[bytes, list[dict]]:
    """new_content: entry.index -> 解封装后的新内容。返回 (新归档字节, 重定位日志)。"""
    v2 = D.CONTAINER["v2"]
    ef = v2["entry"]
    stride = v2["index"]["stride"]
    idx_off = v2["index"]["offset"]

    stored: dict[int, bytes] = {}
    for e in arc.entries:
        if e.index in new_content:
            stored[e.index] = A.pack_entry(e, new_content[e.index])
        else:
            stored[e.index] = arc.data[e.offset:e.offset + e.size]

    out = bytearray(arc.data[:idx_off + arc.index_size])
    reloc: list[dict] = []
    cursor = 0  # 相对 base_offset；条目首尾相接（EV_AOSV2_CONTIGUOUS）
    body = bytearray()
    for e in arc.entries:
        blob = stored[e.index]
        for slot, old, new in (("offset", e.rel_offset, cursor),
                               ("size", e.size, len(blob))):
            site = e.index_offset + ef[slot]["offset"]
            struct.pack_into(A._FMT_U32, out, site, new)
            if old != new:
                reloc.append({"join_id": f"IDX{e.index:04d}_{slot}",
                              "site_offset": site, "length": 4,
                              "old_value": old, "new_value": new,
                              "owner": e.name})
        body += blob
        cursor += len(blob)
    return bytes(out) + bytes(body), reloc


def probe(src: Path, outdir: Path, texts_dir: Path | None = None,
          asm_dir: Path | None = None, verify_only: bool = False,
          ir_bundle=None) -> dict[str, Any]:
    """只读收集改动与裁决，不写任何文件（§6.1：probe 必须无副作用）。

    GUI 的回封预览与 run 共用本函数，因此预览显示的策略与条数即实际执行的那一份。
    ir_bundle 可复用调用方已解析的 IR——解析是确定的，同一源字节必得同一份 IR，
    重算只是把 3.2 秒的解析做第二遍（§12.8）。
    """
    paths = DIS.layout(outdir)
    arc, scripts, _ = ir_bundle or DIS.build_ir(src)

    all_edits: dict[str, dict[int, str]] = {}
    conflicts: list[dict] = []
    cell_width_errors: list[dict] = []
    surfaces = {"texts": 0, "asm": 0}
    if not verify_only:
        for ir in scripts:
            tedits: dict[int, str] = {}
            aedits: dict[int, str] = {}
            tp = (texts_dir or paths["texts"]) / f"{ir.name}.txt"
            if tp.exists():
                tedits = load_dsat(tp, ir)
            ap = (asm_dir or paths["asm"]) / f"{ir.name}.asm.txt"
            if ap.exists():
                aedits = load_asm_edits(ap, ir)
            surfaces["texts"] += len(tedits)
            surfaces["asm"] += len(aedits)
            for idx in set(tedits) & set(aedits):
                if tedits[idx] != aedits[idx]:
                    conflicts.append({"source": ir.name, "idx": idx,
                                      "texts": tedits[idx], "asm": aedits[idx]})
            merged = dict(aedits)
            merged.update(tedits)
            if merged:
                all_edits[ir.name] = merged

    # 正文格子宽度：半角 ASCII 在统计之前转全角，使预览的长度差与实际写入一致。
    # 转换幂等（全角再转仍是全角），load_dsat 里已经转过一遍的条目再走一次无副作用。
    by_name = {ir.name: ir for ir in scripts}
    widened_chars = 0
    widened_entries = 0
    enc = D.SCRIPT["target_encoding"]
    for name, edits in all_edits.items():
        slots = {s.idx: s for s in by_name[name].slots}
        for idx, new in list(edits.items()):
            if slots[idx].tag not in D.TEXT_CELL["tags"]:
                continue
            widened, chs = A.widen_ascii(new)
            leftover = A.check_cell_width(widened, slots[idx].tag, enc)
            if leftover:
                cell_width_errors.append({
                    "source": name, "idx": idx,
                    "chars": [c for _, c, _ in leftover],
                })
                continue
            if chs:
                edits[idx] = widened
                widened_entries += 1
                widened_chars += len(chs)

    # 变长统计：按 target_encoding 计算，占位符按展开后字节计（§6.0.2）
    grew = 0
    delta_bytes = 0
    for name, edits in all_edits.items():
        slots = {s.idx: s for s in by_name[name].slots}
        for idx, new in edits.items():
            d = len(new.encode(enc)) - len(slots[idx].source.encode(enc))
            delta_bytes += d
            if d > 0:
                grew += 1

    strategy = "identity" if not all_edits else "pointer-rewrite"
    return {
        "applicable": not conflicts and not cell_width_errors,
        "reason_code": ("OK" if not conflicts and not cell_width_errors
                        else "EDIT_CONFLICT" if conflicts else "CELL_WIDTH"),
        "strategy": strategy, "edits": all_edits, "conflicts": conflicts,
        "cell_width_errors": cell_width_errors,
        "changed_files": len(all_edits),
        "changed_entries": sum(len(v) for v in all_edits.values()),
        "grew_entries": grew, "estimated_text_delta": delta_bytes,
        "widened_entries": widened_entries, "widened_chars": widened_chars,
        "edit_surfaces": surfaces,
    }


def repack(src: Path, outdir: Path, texts_dir: Path | None = None,
           asm_dir: Path | None = None, verify_only: bool = False,
           verdict: dict[str, Any] | None = None, ir_bundle=None,
           rebuilt_dir: Path | None = None) -> dict[str, Any]:
    """执行回封。

    verdict    可传入已算好的 probe 结果，避免 GUI 预览后重算。
    rebuilt_dir 独立的回封输出目录（§11.4 的第三个路径）；缺省为 outdir/rebuilt。
    """
    paths = DIS.layout(outdir)
    if rebuilt_dir is not None:
        paths["rebuilt"] = Path(rebuilt_dir)
    bundle = ir_bundle or DIS.build_ir(src)
    arc, scripts, _ = bundle
    by_name = {ir.name: ir for ir in scripts}
    by_index = {e.name: e.index for e in arc.entries}

    pv = verdict or probe(src, outdir, texts_dir, asm_dir, verify_only, bundle)
    all_edits = pv["edits"]
    if pv["conflicts"]:
        raise ConflictError(
            "两个编辑面改同一条且取值不同，拒绝执行：\n" +
            "\n".join(f"  {c['source']} idx={c['idx']} texts={c['texts']!r} "
                      f"asm={c['asm']!r}" for c in pv["conflicts"]))
    if pv.get("cell_width_errors"):
        raise ImportError_(
            "译文含宿主无法按 2 字节显示的字符，已拒绝装回：\n" +
            "\n".join(f"  {e['source']} idx={e['idx']}  "
                      f"{'、'.join(repr(c) for c in e['chars'][:6])}"
                      for e in pv["cell_width_errors"][:20]))

    new_content: dict[int, bytes] = {}
    changed_entries = 0
    for name, edits in all_edits.items():
        ir = by_name[name]
        blob = A.render_script(ir, edits)
        new_content[by_index[name]] = blob
        changed_entries += 1

    strategy = pv["strategy"]
    rebuilt, reloc = rebuild_archive(arc, new_content)

    # 事务：写 tmp → 重新解析验证 → 原子改名（§6.5）
    paths["tmp"].mkdir(parents=True, exist_ok=True)
    paths["reports"].mkdir(parents=True, exist_ok=True)
    if not verify_only:
        paths["rebuilt"].mkdir(parents=True, exist_ok=True)
    tmp = paths["tmp"] / src.name
    tmp.write_bytes(rebuilt)

    verdict = verify_rebuild(arc, tmp, new_content, strategy)
    final: Path | None = paths["rebuilt"] / src.name
    if not verdict["ok"]:
        # 失败样本留 tmp/failed/ 供诊断，**不进** rebuilt/（§6.5）。
        # final 必须置 None：否则报告里的 output 指向一个不存在的路径，
        # 或者更糟——指向上一次成功回封留下的旧文件，使用者会误以为本次已成功。
        failed = paths["tmp"] / "failed"
        failed.mkdir(parents=True, exist_ok=True)
        tmp.replace(failed / src.name)
        final = None
    elif verify_only:
        # 自检模式（「输出文本」内部调用）：验证完即弃。使用者点的是导出文本，
        # 不该在回封输出位置凭空多出一个文件。
        tmp.unlink()
        final = None
    else:
        if final.exists():
            final.unlink()
        tmp.replace(final)

    # 事务区用完即收。空的 tmp/ 对使用者是纯噪声——点「输出文本」只该拿到译文，
    # 多出一个空目录会让人以为有东西没清干净。
    # 只在**确实为空**时删：验证失败时 tmp/failed/ 里的诊断样本必须保留（§6.5）。
    _prune_empty(paths["tmp"])

    (paths["reports"] / "relocation_log.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in reloc),
        encoding="utf-8", newline="\n")
    report = {
        "src_sha256": arc.src_sha256, "rebuilt_sha256": A.sha256(rebuilt),
        "identical": rebuilt == arc.data,
        "selected_strategy": strategy,
        "selection_rule": "minimum-capability-among-applicable",
        "changed_entries": changed_entries,
        "grew_entries": pv["grew_entries"],
        "edit_surfaces": pv["edit_surfaces"],
        "changed_text_entries": sum(len(v) for v in all_edits.values()),
        "length_delta": len(rebuilt) - len(arc.data),
        "relocation_sites": len(reloc),
        "verdict": verdict,
        "output": (str(final) if final is not None
                   else str(paths["tmp"] / "failed" / src.name) if not verdict["ok"]
                   else "(自检模式，未保留产物)"),
    }
    # 自检模式不覆盖真实回封的报告：两者语义不同，混写会让上一次回封的裁决被冲掉。
    if not verify_only:
        (paths["reports"] / "relocation_log.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in reloc),
            encoding="utf-8", newline="\n")
        (paths["reports"] / "repack_verdicts.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=1),
            encoding="utf-8", newline="\n")
    return report


def _prune_empty(d: Path) -> None:
    """删除确实为空的目录。非空则原样保留，不递归、不强删。"""
    try:
        if d.is_dir() and not any(d.iterdir()):
            d.rmdir()
    except OSError:
        pass          # 被占用或无权限时保留原状，不影响已通过验证的产物


def verify_rebuild(arc: A.Archive, rebuilt_path: Path,
                   new_content: dict[int, bytes], strategy: str) -> dict[str, Any]:
    """§6.0.3 的变长后验证项。判定方向随是否有编辑而相反（§6.0）。"""
    checks: list[dict] = []

    def chk(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    data = rebuilt_path.read_bytes()
    edited = bool(new_content)

    # 哈希语义：零编辑必须相同，有编辑必须不同
    same = data == arc.data
    chk("hash_semantics", (not edited and same) or (edited and not same),
        f"edited={edited} identical={same}")

    # 输出可被自身完整重新解析
    try:
        arc2 = A.parse_archive(rebuilt_path)
        chk("reparse", True, f"entries={len(arc2.entries)}")
    except A.ParseError as exc:
        chk("reparse", False, str(exc))
        return {"ok": False, "checks": checks}

    # 站点集合同构（§6.3）
    chk("site_isomorphism", len(arc2.entries) == len(arc.entries) and
        all(a.name == b.name and a.index_offset == b.index_offset
            for a, b in zip(arc.entries, arc2.entries)),
        f"{len(arc.entries)} -> {len(arc2.entries)}")

    # 覆盖仍为 1.0，无缺口无重叠
    cert = DIS.coverage_certificate(arc2)
    chk("byte_coverage", cert["byte_coverage"] == 1.0 and not cert["gaps"]
        and not cert["overlaps"], f"cov={cert['byte_coverage']}")

    # 每处编辑的新内容确实在输出中；未编辑条目逐字节不变
    new_ok = miss = 0
    unchanged_ok = True
    for e, e2 in zip(arc.entries, arc2.entries):
        got = A.entry_bytes(arc2, e2)
        if e.index in new_content:
            if got == new_content[e.index]:
                new_ok += 1
            else:
                miss += 1
        else:
            if got != A.entry_bytes(arc, e):
                unchanged_ok = False
    chk("edits_present", miss == 0, f"ok={new_ok} miss={miss}")
    chk("untouched_entries_identical", unchanged_ok)

    # 长度差值可解释：等于各条目存储长度变化之和
    expect = sum(len(A.pack_entry(e, new_content[e.index])) - e.size
                 for e in arc.entries if e.index in new_content)
    chk("length_delta_explained", len(data) - len(arc.data) == expect,
        f"actual={len(data) - len(arc.data)} expected={expect}")

    return {"ok": all(c["ok"] for c in checks), "strategy": strategy, "checks": checks}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="从 texts/ 与 asm/ 的改动回封 AOS 归档")
    ap.add_argument("outdir", type=Path, help="disassembler 的输出目录")
    ap.add_argument("--archive", type=Path, default=None, help="源归档（缺省自动定位）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只预览将要发生的改动，不写任何文件")
    a = ap.parse_args(argv)

    outdir = a.outdir.resolve()
    src = a.archive
    if src is None:
        summary = json.loads((outdir / "reports" / "summary.json")
                             .read_text(encoding="utf-8"))
        cand = outdir.parent / summary["archive"]
        if not cand.exists():
            raise SystemExit(f"找不到源归档 {cand}，请用 --archive 指定")
        src = cand
    src = src.resolve()

    try:
        pv = probe(src, outdir)
        print(f"将回封 {src.name}")
        print(f"  改动    {pv['changed_entries']} 条译文"
              f"（其中 {pv['grew_entries']} 条变长，共 {pv['estimated_text_delta']:+d} 字节）"
              f"，涉及 {pv['changed_files']} 个脚本")
        if pv.get("widened_chars"):
            print(f"  全角化  {pv['widened_entries']} 条里的 {pv['widened_chars']} 个半角字符"
                  f"（游戏按 2 字节显示正文，半角会把后面的字切断）")
        print(f"  来源    双行文本 {pv['edit_surfaces']['texts']} 条 / "
              f"ASM {pv['edit_surfaces']['asm']} 条")
        print(f"  冲突    {len(pv['conflicts'])}")
        if pv.get("cell_width_errors"):
            print(f"  格子宽度 {len(pv['cell_width_errors'])} 条无法转成 2 字节，已拒绝")
        if a.dry_run:
            print("  （--dry-run，未写出任何文件）")
            return 0 if pv["applicable"] else 1
        rep = repack(src, outdir, verdict=pv)
    except (ImportError_, ConflictError) as exc:
        print(f"拒绝回封：\n{exc}")
        return 1

    print(f"策略 {rep['selected_strategy']}  改动条目 {rep['changed_entries']} 个文件 / "
          f"{rep['changed_text_entries']} 条文本")
    print(f"长度差 {rep['length_delta']:+d} 字节  回填站点 {rep['relocation_sites']} 处")
    for c in rep["verdict"]["checks"]:
        print(f"  [{'PASS' if c['ok'] else 'FAIL'}] {c['check']}  {c['detail']}")
    print(f"输出 {rep['output']}")
    return 0 if rep["verdict"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
