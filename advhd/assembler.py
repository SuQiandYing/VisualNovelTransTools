# -*- coding: utf-8 -*-
"""源二进制 + 两个编辑面的改动 → 重建二进制。

不从 asm.txt 完整重建，而是重新解析源二进制并应用**新鲜投影的 diff**
（SKILL.md §2.6）——因此无需编写完整 ASM 语法解析器，冲突检出也是自然结果。

回封策略由 tier 与改动性质协商（§6.2 最小能力原则），`run` 失败不自动降级。

**本作回封产物必须重新加密**（用户明确要求）：明文与加密产物分开命名并共存，
各自给出哈希，不以加密结果覆盖明文对照物（§6.5）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import opcodelist as O
from disassembler import (IR_VERSION, TOOL_VERSION, Ir, O_MARK, T_MARK,
                          Ws2ParseError, decode_placeholders, encoded_len,
                          parse_source, render_asm, render_texts, serialize)

_U32 = struct.Struct("<I")

#: 双行文本的行正则。收窄格式时保留旧字段的读取能力：把删掉的字段写成可选
#: 匹配（§4.6），因此这里不限定行尾必须紧跟某字段。
RE_ORIG = re.compile(r"^%s(?P<idx>\d{8})%s(?P<tag>[a-z_]+)%s(?P<text>.*)$"
                     % (O_MARK, O_MARK, O_MARK))
RE_TRAN = re.compile(r"^%s(?P<idx>\d{8})%s(?P<tag>[a-z_]+)%s(?P<text>.*)$"
                     % (T_MARK, T_MARK, T_MARK))
RE_HDR_SHA = re.compile(r"src_sha256=([0-9a-fA-F]{64})")
RE_HDR_ENC = re.compile(r"source=(\S+)\s+target=(\S+)")
RE_HDR_PART = re.compile(r"part=(\d+)/(\d+)")


class RepackError(Exception):
    def __init__(self, code: str, detail: str, refs: list[str] | None = None) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.refs = refs or []


# ---------------------------------------------------------------------------
# 封装层：加解密（参数取自方言，此处不出现具体位移量）
# ---------------------------------------------------------------------------

def _rotate_left_table(bits: int) -> bytes:
    """构造循环左移 `bits` 位的查表。translate 在 C 层完成整块转换。"""
    return bytes(((b << bits) | (b >> (8 - bits))) & 0xFF for b in range(256))


_DEC_TABLE = _rotate_left_table(O.DIALECT["cipher"]["decrypt_rol"])
_ENC_TABLE = _rotate_left_table(O.DIALECT["cipher"]["encrypt_rol"])


def decrypt(data: bytes) -> bytes:
    """加密脚本 → 明文。逐字节循环位移，无密钥（EV_CIPHER_ROT8）。"""
    return data.translate(_DEC_TABLE)


def encrypt(data: bytes) -> bytes:
    """明文 → 加密脚本。decrypt 的逆运算，供回封使用。"""
    return data.translate(_ENC_TABLE)


# ---------------------------------------------------------------------------
# 导入校验（§4.9 的 13 条）
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TextEdit:
    idx: int
    new_text: str
    old_text: str


def parse_text_file(path: Path, ir: Ir, target_encoding: str
                    ) -> tuple[dict[int, TextEdit], list[dict[str, Any]]]:
    """解析译文文件并执行 13 条导入校验。任一条失败即拒绝整个文件。"""
    raw = path.read_text(encoding="utf-8-sig")
    lines = raw.split("\n")
    errors: list[dict[str, Any]] = []
    edits: dict[int, TextEdit] = {}

    header = [ln for ln in lines[:4]]
    if len(header) < 4 or not header[0].startswith("# TEXT/2"):
        raise RepackError("BAD_HEADER", f"{path.name}: 文件头四行缺失或不合法")

    # 1 src_sha256 与当前 IR 匹配
    m = RE_HDR_SHA.search(header[0])
    if not m:
        raise RepackError("BAD_HEADER", f"{path.name}: 缺 src_sha256")
    if m.group(1).lower() != ir.sha256:
        raise RepackError(
            "SRC_HASH_MISMATCH",
            f"{path.name}: 译文文件对应的源已变化（用旧文件导入新 dump）")

    # 2 IR / 工具版本兼容
    if ("ir=%s" % IR_VERSION) not in header[0]:
        raise RepackError("IR_VERSION", f"{path.name}: IR 版本不兼容")

    # 3 分片完整
    mp = RE_HDR_PART.search(header[2]) if len(header) > 2 else None
    if mp and mp.group(1) != mp.group(2):
        raise RepackError("SHARD_INCOMPLETE",
                          f"{path.name}: 分片 {mp.group(1)}/{mp.group(2)}，"
                          f"须全部到齐或显式声明范围")

    by_idx = {t.idx: t for t in ir.texts}
    pending: dict[str, Any] | None = None

    for lineno, line in enumerate(lines, 1):
        if not line or line.startswith("#"):
            continue
        mo, mt = RE_ORIG.match(line), RE_TRAN.match(line)

        # 6 分隔符未混用
        if not mo and not mt:
            if line.lstrip().startswith((O_MARK, T_MARK)):
                errors.append({"line": lineno, "code": "MIXED_SEPARATOR",
                               "detail": "分隔符混用或行格式不合法"})
            continue

        if mo:
            idx = int(mo.group("idx"))
            entry = by_idx.get(idx)
            # 4 idx 定宽、唯一、存在于该源
            if entry is None:
                errors.append({"line": lineno, "code": "UNKNOWN_IDX",
                               "detail": f"idx={idx} 不存在于该源"})
                pending = None
                continue
            # 7 原文行与 IR 的 source 逐字符相等
            if mo.group("text") != entry.source:
                errors.append({
                    "line": lineno, "code": "SOURCE_LINE_ALTERED",
                    "detail": f"idx={idx} 原文行被改动；"
                              f"IR={entry.source!r} 文件={mo.group('text')!r}"})
                pending = None
                continue
            # 5 tag 一致
            if mo.group("tag") != entry.tag:
                errors.append({"line": lineno, "code": "TAG_MISMATCH",
                               "detail": f"idx={idx} tag 不一致"})
                pending = None
                continue
            pending = {"idx": idx, "entry": entry, "line": lineno}
            continue

        # 译文行
        idx = int(mt.group("idx"))
        if pending is None or pending["idx"] != idx:
            errors.append({"line": lineno, "code": "IDX_TRIPLE_MISMATCH",
                           "detail": f"译文行 idx={idx} 与其上方原文行不一致"})
            continue
        entry: Any = pending["entry"]
        pending = None
        new_text = mt.group("text")

        # 13 译文行非空（空 = 误删，不是"未翻译"）
        if new_text == "":
            errors.append({"line": lineno, "code": "EMPTY_TRANSLATION",
                           "detail": f"idx={idx} 译文行为空（误删？"
                                     f"未翻译应保留原文）"})
            continue
        if mt.group("tag") != entry.tag:
            errors.append({"line": lineno, "code": "TAG_MISMATCH",
                           "detail": f"idx={idx} 译文行 tag 不一致"})
            continue

        if new_text == entry.source:
            continue                       # 未翻译，合法状态

        # 8 frozen 条目的译文行未被改动
        if entry.policy == "frozen":
            errors.append({"line": lineno, "code": "FROZEN_MODIFIED",
                           "detail": f"idx={idx} 为锁定条目，不得修改"})
            continue

        # 9 target_encoding 可表示（不静默替换）
        # 11 占位符集合完整
        try:
            new_bytes = decode_placeholders(new_text, target_encoding)
        except UnicodeEncodeError as exc:
            bad = new_text[exc.start:exc.end]
            errors.append({
                "line": lineno, "code": "ENCODING_UNREPRESENTABLE",
                "detail": f"idx={idx}：译文编码 {target_encoding} 无法表示"
                          f"「{bad}」，换一种编码试试"})
            continue
        except ValueError as exc:
            errors.append({"line": lineno, "code": "PLACEHOLDER_BROKEN",
                           "detail": f"idx={idx}：{exc}"})
            continue

        # 变量替换标记必须原样保留：删掉或改写会让游戏显示不出玩家名字。
        # 该错误不会被长度或编码检查发现，只能显式比对集合与个数。
        want = sorted(re.findall(O.INLINE_VARIABLE_RE, entry.source))
        got = sorted(re.findall(O.INLINE_VARIABLE_RE, new_text))
        if want != got:
            errors.append({
                "line": lineno, "code": "INLINE_VARIABLE_BROKEN",
                "detail": f"idx={idx}：变量标记必须原样保留，"
                          f"原文含 {want}，译文含 {got}"})
            continue

        # 10 字节长度符合回封模式（此处只记录，超长由 probe 决定策略）
        edits[idx] = TextEdit(idx=idx, new_text=new_text, old_text=entry.source)

    if pending is not None:
        errors.append({"line": pending["line"], "code": "MISSING_TRANSLATION_LINE",
                       "detail": f"idx={pending['idx']} 缺译文行"})
    return edits, errors


def parse_asm_edits(user_asm: str, fresh_asm: str) -> dict[int, str]:
    """对新鲜投影做 diff，只取用户实际改动的行（§2.6）。

    只解析改动的若干行，行首偏移映射回 IR 对象即一次字典查找；
    转义、引号、共享标记的歧义处理全部不必编写。
    """
    fresh_lines = fresh_asm.split("\n")
    user_lines = user_asm.split("\n")
    changed: dict[int, str] = {}
    if len(fresh_lines) != len(user_lines):
        raise RepackError("ASM_LINE_COUNT",
                          "ASM 行数与新鲜投影不一致：请勿增删行，"
                          "结构改动需 T3（本方言不支持）")
    for a, b in zip(fresh_lines, user_lines):
        if a == b:
            continue
        m = re.match(r"\s*0x([0-9A-Fa-f]{4,})\s", b)
        if not m:
            raise RepackError("ASM_UNLOCATABLE",
                              f"改动行缺少行首偏移，无法定位：{b[:60]!r}")
        changed[int(m.group(1), 16)] = b
    return changed


# ---------------------------------------------------------------------------
# 回封策略：probe / run（§6.1）
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ProbeVerdict:
    strategy_id: str
    applicable: bool
    reason_code: str
    reason_detail: str = ""
    blocking_refs: list[str] = None            # type: ignore[assignment]
    estimated_deltas: dict[str, int] = None    # type: ignore[assignment]

    def as_dict(self) -> dict[str, Any]:
        return {"strategy_id": self.strategy_id, "applicable": self.applicable,
                "reason_code": self.reason_code,
                "reason_detail": self.reason_detail,
                "blocking_refs": self.blocking_refs or [],
                "estimated_deltas": self.estimated_deltas or {}}


CAPABILITY_ORDER = ["identity", "in_place", "pointer-rewrite", "full-layout"]


def probe_all(ir: Ir, edits: dict[int, TextEdit], target_encoding: str,
              asm_changed: bool) -> list[ProbeVerdict]:
    """只读、无副作用地评估全部策略。此阶段不执行任何 run。"""
    by_idx = {t.idx: t for t in ir.texts}
    overflow: list[str] = []
    delta_bytes = 0
    delta_ranges = 0

    term = ir.terminator_size
    for idx, ed in edits.items():
        entry = by_idx[idx]
        old_len = len(entry.raw) + term            # 含终止符（utf16 为 2 字节）
        # 长度按**拼回词缀后**的完整字符串计算，否则容量判定会偏小
        new_len = encoded_len(entry.affix_prefix + ed.new_text + entry.affix_suffix,
                              target_encoding, terminator=term)
        if new_len != old_len:
            delta_ranges += 1
            delta_bytes += new_len - old_len
        if new_len > old_len:
            overflow.append("idx=%08d" % idx)

    verdicts = [
        ProbeVerdict("identity", not edits and not asm_changed,
                     "OK" if not edits and not asm_changed else "LENGTH_OVERFLOW",
                     "" if not edits else "存在编辑，identity 不适用",
                     sorted(edits and ["idx=%08d" % i for i in sorted(edits)] or [])),
        ProbeVerdict("in_place", bool(edits) and not overflow,
                     "OK" if (edits and not overflow)
                     else ("LENGTH_OVERFLOW" if overflow else "OK"),
                     "" if not overflow else f"{len(overflow)} 条译文超出原槽容量",
                     overflow),
        ProbeVerdict("pointer-rewrite", bool(edits), "OK",
                     "全部引用站点已由指令流解析定位",
                     [], {"ranges": delta_ranges, "bytes": delta_bytes}),
        # 未申报 T4：无基本块/可达性分析，故不支持结构重排与指令插删
        ProbeVerdict("full-layout", False, "TIER_TOO_LOW",
                     "本方言申报 T3，未做控制流分析，不支持结构重排",
                     ["R_SCRIPT_MAIN"]),
    ]
    return verdicts


def select_strategy(verdicts: list[ProbeVerdict]) -> ProbeVerdict:
    """在可用策略中选能力最小的（§6.2）。"""
    usable = {v.strategy_id: v for v in verdicts if v.applicable}
    for sid in CAPABILITY_ORDER:
        if sid in usable:
            return usable[sid]
    raise RepackError("NO_APPLICABLE_STRATEGY",
                      "没有可用回封策略；见各策略 reason_code")


# ---------------------------------------------------------------------------
# 变长回封：按站点，不按值（§6.3）
# ---------------------------------------------------------------------------

def rebuild(ir: Ir, edits: dict[int, TextEdit], target_encoding: str
            ) -> tuple[bytes, list[dict[str, Any]]]:
    """应用文本改动并重建。

    七步传播（§6.0.3）：重编码 → 重排偏移 → 按站点回填引用 → 更新长度字段
    → 重算校验和 → 恢复封装层（由调用者做）→ 重新解析验证（由调用者做）。

    本格式无长度字段、无校验和、无对齐 padding（指令紧密排列），故第 4、5 步
    为空操作；第 2、3 步是全部工作量。
    """
    by_idx = {t.idx: t for t in ir.texts}
    nul = bytes(ir.terminator_size)          # 1 or 2 zero bytes
    #: 每个被编辑字符串槽的新字节。译文只含正文，引擎词缀在此原样拼回。
    new_raw: dict[int, bytes] = {}
    for idx, ed in edits.items():
        entry = by_idx[idx]
        new_raw[entry.slot_offset] = decode_placeholders(
            entry.affix_prefix + ed.new_text + entry.affix_suffix, target_encoding)

    # ---- 第 1、2 步：重新编码并计算每条指令的新起始偏移 ----
    old_to_new: dict[int, int] = {}
    cursor = 0
    for inst in ir.instructions:
        old_to_new[inst.offset] = cursor
        size = 1
        for op in inst.operands:
            if op.kind == O.CSTR:
                raw = new_raw.get(op.offset, op.raw)
                size += len(raw) + ir.terminator_size
            else:
                size += op.size
        cursor += size
    total = cursor

    # ---- 第 3 步：按站点回填引用。站点集合外一律 preserve ----
    relocation_log: list[dict[str, Any]] = []
    site_by_offset = {s.site_offset: s for s in ir.sites}

    out = bytearray()
    for inst in ir.instructions:
        out.append(inst.opcode)
        for op in inst.operands:
            if op.kind == O.CSTR:
                out += new_raw.get(op.offset, op.raw) + nul
            elif op.kind == O.PTR32 and op.offset in site_by_offset:
                site = site_by_offset[op.offset]
                if site.key_value not in old_to_new:
                    raise RepackError(
                        "UNRESOLVED_JOIN_SITE",
                        f"站点 {site.join_id} 的目标 0x{site.key_value:X} "
                        f"不落在任何指令边界上",
                        [site.join_id])
                new_value = old_to_new[site.key_value]
                out += _U32.pack(new_value)
                relocation_log.append({
                    "join_id": site.join_id,
                    "site_offset_old": site.site_offset,
                    "site_offset_new": len(out) - 4,
                    "key_value_old": site.key_value,
                    "key_value_new": new_value,
                    "width": 4,
                })
            else:
                out += op.raw

    if len(out) != total:
        raise RepackError("LAYOUT_INCONSISTENT",
                          f"预计长度 {total} 与实际 {len(out)} 不符")
    return bytes(out), relocation_log


def verify_rebuilt(ir: Ir, rebuilt: bytes, edits: dict[int, TextEdit],
                   target_encoding: str, source_encoding: str,
                   tmp_path: Path) -> list[str]:
    """变长回封后必须重新验证的性质（§6.0.3）。返回问题列表，空表示通过。"""
    problems: list[str] = []

    # □ 输出可被自身完整重新解析
    tmp_path.write_bytes(rebuilt)
    try:
        # 以**目标**编码重新解析：重建后的字符串已按 target_encoding 写入。
        # 形态（终止符宽度）沿用源文件的，因为回封不改变字符串形态。
        ir2 = parse_source(tmp_path, target_encoding,
                           string_shape=ir.string_shape)
    except Ws2ParseError as exc:
        return [f"重建结果无法重新解析：{exc}"]

    # □ 重新解析后覆盖仍为 1.0（解析成功即意味着指令恰好平铺，见 parse_source）
    # □ 站点集合同构：数量相同，site_offset 一一对应
    if len(ir2.sites) != len(ir.sites):
        problems.append(f"站点数量不同构：原 {len(ir.sites)} → 新 {len(ir2.sites)}")

    # □ 每处已编辑条目的新内容确实出现在输出中（"可解析"不能证明"已写入"）
    by_idx2 = {t.idx: t for t in ir2.texts}
    by_idx1_all = {t.idx: t for t in ir.texts}
    for idx, ed in edits.items():
        entry2 = by_idx2.get(idx)
        src_entry = by_idx1_all[idx]
        expect = decode_placeholders(
            src_entry.affix_prefix + ed.new_text + src_entry.affix_suffix,
            target_encoding)
        if entry2 is None or entry2.raw != expect:
            problems.append(f"idx={idx:08d} 的新内容未出现在输出中")

    # □ 未编辑条目的字节内容逐条不变
    by_idx1 = {t.idx: t for t in ir.texts}
    for idx, t1 in by_idx1.items():
        if idx in edits:
            continue
        t2 = by_idx2.get(idx)
        if t2 is None or t2.raw != t1.raw:
            problems.append(f"idx={idx:08d} 未被编辑却发生变化")

    # □ 总长度差值等于各条目长度变化之和（无意外增减）
    term = ir.terminator_size
    expect_delta = sum(
        encoded_len(by_idx1[idx].affix_prefix + ed.new_text
                    + by_idx1[idx].affix_suffix, target_encoding, term)
        - (len(by_idx1[idx].raw) + term)
        for idx, ed in edits.items())
    actual_delta = len(rebuilt) - ir.size
    if actual_delta != expect_delta:
        problems.append(f"长度差值无法解释：预计 {expect_delta}，实际 {actual_delta}")

    # □ 指令条数不变（本方言不支持指令插删）
    if len(ir2.instructions) != len(ir.instructions):
        problems.append(f"指令条数改变：{len(ir.instructions)} → {len(ir2.instructions)}")
    return problems


def count_value_collisions(ir: Ir) -> int:
    """站点集合之外、其值恰等于某旧站点键的 4 字节位置数（§6.3 诊断量）。

    不为零是正常的；为零反而值得怀疑键域是否过窄。
    """
    keys = {s.key_value for s in ir.sites}
    site_offsets = {s.site_offset for s in ir.sites}
    if not keys:
        return 0
    data = ir.data
    hits = 0
    for i in range(0, len(data) - 3):
        if i in site_offsets:
            continue
        if _U32.unpack_from(data, i)[0] in keys:
            hits += 1
    return hits


# ---------------------------------------------------------------------------
# 命令行入口：与 GUI 的「回封文本」按钮等价（§11.9 要求命令行不得削减能力）
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ws2 回封：源二进制 + 译文 → 重建脚本（默认输出加密产物）")
    ap.add_argument("source", type=Path, help="源脚本文件夹（或单个文件）")
    ap.add_argument("texts", type=Path, help="译文所在文件夹（含 texts/ 子目录）")
    ap.add_argument("-o", "--output", type=Path, help="回封输出目录")
    ap.add_argument("--source-encoding", help="缺省按字符串形态自动判定")
    ap.add_argument("--target-encoding", help="缺省按字符串形态取默认值")
    ap.add_argument("--no-plain", action="store_true",
                    help="不另存明文副本（默认同时保留，便于比对）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只做预览与校验，不写出任何文件")
    args = ap.parse_args(argv)

    # 延迟导入：repack 依赖本模块，顶层导入会形成循环
    from disassembler import iter_sources
    from repack import plan_repack, run_repack

    srcs = iter_sources([args.source])
    if not srcs:
        print("没有找到 .ws2 / .wsc 文件", file=sys.stderr)
        return 1
    root = args.source if args.source.is_dir() else args.source.parent
    out = args.output or root.parent / (root.name + "_rebuilt")

    if args.dry_run:
        plan = plan_repack(srcs, root, args.texts,
                           source_encoding=args.source_encoding,
                           target_encoding=args.target_encoding)
        print(json.dumps({k: plan[k] for k in
                          ("files", "changed_entries", "longer_entries",
                           "delta_bytes", "strategies", "can_execute")},
                         ensure_ascii=False, indent=2))
        for c in plan["conflicts"][:20]:
            print("冲突 idx=%(idx)s 文本侧=%(texts_value)r" % c, file=sys.stderr)
        for e in plan["errors"][:20]:
            print("! %s %s" % (e.get("file", ""), e.get("detail", "")),
                  file=sys.stderr)
        return 0 if plan["can_execute"] else 1

    result = run_repack(srcs, root, args.texts, out,
                        source_encoding=args.source_encoding,
                        target_encoding=args.target_encoding,
                        emit_plain=not args.no_plain)
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    for e in result["errors"][:20]:
        print("! %s %s" % (e.get("file", ""), e.get("detail", "")),
              file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
