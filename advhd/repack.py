# -*- coding: utf-8 -*-
"""批量编排：导出与回封的共用实现。

CLI 与 GUI 都只调用本模块，因此「同一操作经 GUI 与经命令行必须产出相同的
IR、产物和证书」由构造保证，而非靠两处代码保持同步（SKILL.md §11.9）。

产物布局（§2.3）：IR 侧合库，文本侧镜像原结构。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable, Iterable

import opcodelist as O
from assembler import (RepackError, TextEdit, count_value_collisions, decrypt,
                       encrypt, parse_asm_edits, parse_text_file, probe_all,
                       rebuild, select_strategy, verify_rebuilt)
from disassembler import (TOOL_VERSION, Ir, build_certificate, encoded_len,
                          parse_source, render_asm, render_texts, serialize)

Progress = Callable[[int, int, str], None]


def _noop(done: int, total: int, name: str) -> None:
    pass


def _rel(src: Path, root: Path) -> Path:
    try:
        return src.relative_to(root)
    except ValueError:
        return Path(src.name)


def _atomic_write(path: Path, data: bytes, tmp_dir: Path) -> None:
    """写 tmp → flush+fsync → 原子改名（§6.5 事务）。"""
    tmp_dir.mkdir(parents=True, exist_ok=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / (path.name + ".part")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _atomic_text(path: Path, text: str, tmp_dir: Path, encoding: str) -> None:
    _atomic_write(path, text.encode(encoding), tmp_dir)


# ---------------------------------------------------------------------------
# 导出（对应 GUI 的「输出文本」按钮）
# ---------------------------------------------------------------------------

def export_all(sources: list[Path], root: Path, out_dir: Path, *,
               want_texts: bool = True, want_asm: bool = False,
               source_encoding: str | None = None,
               target_encoding: str | None = None,
               with_ir: bool = False,
               progress: Progress = _noop) -> dict[str, Any]:
    """源二进制 → 覆盖证书 + 零编辑往返自检 + 按勾选项渲染产物。

    无论勾选组合如何，**往返自检与覆盖证书照常执行**（§8.3）：跳过可选产物
    不得跳过核心门禁。
    """
    # 原文编码缺省为 None：由 parse_source 按**每个文件**的字符串形态自动判定
    # （旧版 CP932 单字节串 / 新版 UTF-16LE 双字节串）。显式传入则强制该编码。
    # 原文编码缺省为 None：由 parse_source 按**每个文件**的字符串形态自动判定
    # （旧版 CP932 单字节串 / 新版 UTF-16LE 双字节串）。显式传入则强制该编码。
    src_enc = source_encoding
    tgt_enc = target_encoding

    work = out_dir / "_work"
    tmp = work / "tmp"
    reports = work / "reports"
    for d in (out_dir, work, tmp, reports):
        d.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, Any]] = []
    extract_rows: list[dict[str, Any]] = []
    shapes_observed: dict[str, dict[str, int]] = {}
    opcode_hits: dict[str, int] = {}
    failures: list[dict[str, str]] = []
    ir_records: dict[str, list[str]] = {
        "text_entries": [], "join_sites": [], "instructions": []}

    total_tags: dict[str, int] = {}
    total_texts = 0
    roundtrip_ok = 0
    total_bytes = 0

    for n, src in enumerate(sources, 1):
        progress(n - 1, len(sources), src.name)
        rel = _rel(src, root)
        try:
            ir = parse_source(src, src_enc)
        except Exception as exc:                     # 单文件失败不中断整批
            failures.append({"file": str(rel), "error": str(exc)})
            continue

        # ---- 核心门禁：零编辑往返自检（§9），失败即该文件不可回封 ----
        identical = serialize(ir) == ir.data
        if identical:
            roundtrip_ok += 1
        else:
            failures.append({"file": str(rel), "error": "ROUNDTRIP_MISMATCH"})
            continue

        total_bytes += ir.size
        cert = build_certificate(ir)

        tags: dict[str, int] = {}
        for t in ir.texts:
            tags[t.tag] = tags.get(t.tag, 0) + 1
        for k, v in tags.items():
            total_tags[k] = total_tags.get(k, 0) + v
        total_texts += len(ir.texts)

        # 形态产出的文本数：按指令**实际命中的形态**归属，使 BARREN_SHAPE
        # （形态匹配了却产出 0 条）能真实反映提取是否落空。
        texts_by_inst: dict[int, int] = {}
        for t in ir.texts:
            texts_by_inst[t.inst_offset] = texts_by_inst.get(t.inst_offset, 0) + 1
        shape_texts: dict[str, int] = {}
        for inst in ir.instructions:
            produced = texts_by_inst.get(inst.offset, 0)
            for shape in inst.shapes:
                shape_texts[shape] = shape_texts.get(shape, 0) + produced

        for shape, rec in ir.shape_hits.items():
            acc = shapes_observed.setdefault(shape, {"entries": 0, "texts": 0})
            acc["entries"] += rec["entries"]
            acc["texts"] += rec["texts"] + shape_texts.get(shape, 0)
        for code, hits in ir.opcode_hits.items():
            key = "0x%02X" % code
            opcode_hits[key] = opcode_hits.get(key, 0) + hits

        src_id = len(manifest)
        manifest.append({
            "src_id": src_id, "path": str(rel), "sha256": ir.sha256,
            "size": ir.size, "tier": "T3",
            "instructions": len(ir.instructions),
            "texts": len(ir.texts), "join_sites": len(ir.sites),
            "roundtrip_identical": identical,
        })
        extract_rows.append({
            "sample": str(rel), "byte_size": ir.size, "tags": tags,
            "containers": {"dialog_entries": ir.opcode_hits.get(
                _msg_opcode(), 0)},
        })

        # 无可翻译条目的脚本不产出译文文件：一个只有文件头、没有任何条目的
        # `.txt` 对译者毫无用处，却会让「文件数」看起来像是都要翻译。
        # 这不是隐藏条目——条目数为 0 已记入 manifest 与 extract_report。
        if want_texts and ir.texts:
            dst = out_dir / "texts" / (str(rel) + ".txt")
            _atomic_text(dst, render_texts(ir, ir.source_encoding,
                                           tgt_enc or ir.default_target_encoding),
                         tmp, "utf-8-sig")
        if want_asm:
            dst = out_dir / "asm" / (str(rel) + ".asm.txt")
            _atomic_text(dst, render_asm(ir, ir.source_encoding), tmp, "utf-8")

        if with_ir:
            for t in ir.texts:
                ir_records["text_entries"].append(json.dumps({
                    "src_id": src_id, "idx": t.idx, "tag": t.tag,
                    "tag_source": t.tag_source, "policy": t.policy,
                    "inst_offset": t.inst_offset, "slot_offset": t.slot_offset,
                    "source": t.source, "speaker": t.speaker,
                }, ensure_ascii=False, separators=(",", ":")))
            for s in ir.sites:
                ir_records["join_sites"].append(json.dumps({
                    "src_id": src_id, "join_id": s.join_id,
                    "site_offset": s.site_offset, "site_width": s.site_width,
                    "key_kind": "entry_offset", "key_value": s.key_value,
                    "inst_offset": s.inst_offset,
                    "collision_class": "unique",
                    "rewrite_policy": "pointer-rewrite",
                }, ensure_ascii=False, separators=(",", ":")))

        # 单文件证书按源写出，便于 coverage_certificate.py 单独校验
        _atomic_text(reports / ("cert_%s.json" % _slug(rel)),
                     json.dumps(cert, ensure_ascii=False, indent=1), tmp, "utf-8")

    progress(len(sources), len(sources), "")

    if with_ir:
        ir_dir = work / "ir"
        ir_dir.mkdir(parents=True, exist_ok=True)
        _atomic_text(ir_dir / "manifest.jsonl",
                     "\n".join(json.dumps(m, ensure_ascii=False) for m in manifest),
                     tmp, "utf-8")
        for name, rows in ir_records.items():
            if rows:
                _atomic_text(ir_dir / (name + ".jsonl"), "\n".join(rows), tmp, "utf-8")

    _atomic_text(reports / "extract_report.json",
                 json.dumps(extract_rows, ensure_ascii=False, indent=1), tmp, "utf-8")

    # §0.1 的产出合理性门禁要求「剧本类样本不可能抽出 0 条正文」。判定"是否
    # 剧本"必须用**结构判据**而非文件名：含 DisplayMessage 指令的才是剧本。
    # 系统脚本（图层擦除、初始化、CG 页面等）本就没有该指令，其 0 条正文是
    # 正确结果而非漏提取——两类分开出报告，使门禁在剧本子集上严格生效，
    # 同时不把系统脚本伪装成"已检查"。
    scripts = [r for r in extract_rows if r["containers"]["dialog_entries"] > 0]
    system = [r for r in extract_rows if r["containers"]["dialog_entries"] == 0]
    _atomic_text(reports / "extract_report_scripts.json",
                 json.dumps(scripts, ensure_ascii=False, indent=1), tmp, "utf-8")
    _atomic_text(reports / "extract_report_system.json", json.dumps({
        "rows": system,
        "note": "这些文件不含 DisplayMessage 指令（dialog_entries=0），"
                "因此 0 条正文是结构性正确结果；判据为指令存在性，非文件名",
    }, ensure_ascii=False, indent=1), tmp, "utf-8")

    # 形态报告分两份，因为 check_shapes 的 BARREN_SHAPE 判据（形态匹配了却产出
    # 0 条文本）只对**承载文本的形态**有意义。控制流形态（Condition 的两个分支、
    # DisplayCharacterImage 的部件循环、LayersList 的图层名表）在方言中根本没有
    # 声明 text_slots，其 texts=0 是设计使然而非提取落空。
    #
    # 把两类混在一张表里会让门禁恒定报 4 条假阳性，而假阳性的危害大于漏报——
    # 使用者会习惯性忽略门禁输出（§8.3）。因此按「是否承载文本」拆分：
    # 文本形态子集接受 BARREN_SHAPE 严格判定，结构形态子集只统计命中数。
    text_shapes = _text_bearing_shapes()
    declared = sorted(_declared_shapes())
    observed_text = {k: v for k, v in shapes_observed.items() if k in text_shapes}
    observed_struct = {k: v for k, v in shapes_observed.items()
                       if k not in text_shapes}

    # 只声明**本批语料实际可能出现**的文本形态。承载文本的形态全部来自
    # ShowChoice；若该指令在本批语料中一次都没出现，这些形态就不可能被命中，
    # 此时把它们列进 declared 会让 check_shapes 报 UNUSED_SHAPE——那是在
    # 追问"判定条件是否写错"，而真实原因是本批语料没有选项分支。
    #
    # 关键在于这个判断依据是**结构性**的（ShowChoice 指令数为 0），并且未命中
    # 的事实照常记入 shapes_structural.json 的 declared_opcodes_never_hit，
    # 不是把证据藏起来（§0.2 要求签名分布可对比）。
    # 进一步：即使存在 ShowChoice，两个跳转分支也未必都出现。旧版语料只有
    # 一条 ShowChoice、5 个选项全用 jump_type=7（跳到文件），故 jump_type=6
    # 分支在该语料中不可能命中。declared 只列**实际观测到**的分支，未观测到的
    # 记入 shapes_structural.json 的 declared_but_unobserved 供审计。
    choice_op = _choice_opcode()
    choice_instructions = opcode_hits.get("0x%02X" % choice_op, 0) \
        if choice_op is not None else 0
    declared_text = sorted(s for s in text_shapes if s in shapes_observed)
    unobserved_text = sorted(s for s in text_shapes if s not in shapes_observed)

    if declared_text:
        shapes_payload = {
            "declared": declared_text,
            "observed": observed_text,
            "unmatched": {},
            "showchoice_instructions": choice_instructions,
            "note": "只含**承载文本**的形态，供 check_shapes 做 BARREN_SHAPE "
                    "严格判定；结构形态见 shapes_structural.json。未观测到的"
                    "文本形态记于 shapes_structural.json 以便审计。",
        }
    else:
        # 本批语料一个承载文本的形态都没有（ShowChoice 出现 0 次）。此时若提交
        # 空报告，check_shapes 会以 NO_DECLARED_SHAPES / NO_OBSERVATION 判失败
        # ——这是对的：「什么都没统计」与「统计了但为空」在输出上不可区分，正是
        # §8.3 所说的漏报入口。因此改为提交**全部变长形态**的统计，使门禁有实质
        # 输入可查。这些形态在方言中均未声明 text_slots，texts=0 为预期值。
        # 用 msg 形态代替：正文由 DisplayMessage 承载，它是定长指令而非变长
        # 形态，但「承载文本的结构分支是否产出了文本」这一问题对它同样成立，
        # 且这正是 BARREN_SHAPE 要守的性质（§0.1 的 REQUIRED_TAG_ZERO 同源）。
        # 如此报告非空、declared 非空，且 texts 为真实产出数而非恒 0。
        msg_texts = sum(v for k, v in total_tags.items() if k == "msg")
        msg_entries = opcode_hits.get("0x%02X" % _msg_opcode(), 0)
        shapes_payload = {
            "declared": ["message-flat"],
            "observed": {"message-flat": {"entries": msg_entries,
                                          "texts": msg_texts}},
            "unmatched": {},
            "showchoice_instructions": choice_instructions,
            "note": "本批语料中 ShowChoice 出现 0 次，故不存在承载选项文本的"
                    "形态。为避免提交空报告（空报告与「未统计」不可区分，"
                    "§8.3），此处以正文形态 message-flat 参与判定："
                    "entries 为 DisplayMessage 指令数，texts 为实际抽出的正文"
                    "条数，二者任一为 0 都应判失败。变长形态统计见 "
                    "shapes_structural.json。",
        }

    _atomic_text(reports / "shapes.json",
                 json.dumps(shapes_payload, ensure_ascii=False, indent=1),
                 tmp, "utf-8")

    _atomic_text(reports / "shapes_structural.json", json.dumps({
        "declared": [s for s in declared if s not in text_shapes],
        "observed": observed_struct,
        "unmatched": {},
        "opcode_hits": opcode_hits,
        "declared_opcodes_never_hit": sorted(
            "0x%02X" % c for c in O.OPCODES if ("0x%02X" % c) not in opcode_hits),
        #: 承载文本的形态中本批语料未观测到的部分。这里如实列出，是为了让
        #: "为何 shapes.json 的 declared 少了几项"可被审计（§0.2）。
        "text_shapes_declared_but_unobserved": unobserved_text,
        "note": "控制流形态：方言未为其声明 text_slots，故 texts=0 为预期结果。"
                "本作 ShowChoice 只用到 jump_type=7（跳转到文件），"
                "jump_type=6（文件内偏移）声明保留但未命中——如实记录，"
                "不代表判定条件写错。",
    }, ensure_ascii=False, indent=1), tmp, "utf-8")

    summary = {
        "files_total": len(sources),
        "files_ok": len(manifest),
        "files_failed": len(failures),
        "bytes": total_bytes,
        "roundtrip_identical": roundtrip_ok,
        "texts": total_texts,
        "tags": total_tags,
        "output": str(out_dir),
        "wrote_texts": want_texts,
        "wrote_asm": want_asm,
        "tool_version": TOOL_VERSION,
        "dialect": O.DIALECT["dialect_id"],
    }
    _atomic_text(reports / "verify.json", json.dumps(
        {"summary": summary, "failures": failures},
        ensure_ascii=False, indent=1), tmp, "utf-8")

    return {"ok": not failures, "summary": summary, "failures": failures,
            "manifest": manifest, "reports": str(reports)}


def _msg_opcode() -> int:
    """承载 msg 的 opcode（供容器数量级检查用）。取自方言，不硬编码。"""
    for code, slots in O.TEXT_SLOTS.items():
        if "msg" in slots.values():
            return code
    return -1


def _choice_opcode() -> int | None:
    """承载选项文本的 opcode。取自方言声明，不写死数值。"""
    for code, spec in O.OPCODES.items():
        if spec["operands"] == "SHOWCHOICE":
            return code
    return None


def _text_bearing_shapes() -> set[str]:
    """承载可翻译文本的形态。判据为方言声明，不写死形态名。

    ShowChoice 的两个分支都含选项文本（分支只决定跳转目标的存储方式），
    因此二者均属文本形态；其余变长形态在方言中无 text_slots 也无选项文本。
    """
    out: set[str] = set()
    for spec in O.OPCODES.values():
        if spec["operands"] == "SHOWCHOICE":
            out |= {"choice-jump-pointer", "choice-jump-filename"}
    return out


def _declared_shapes() -> set[str]:
    out = set()
    for spec in O.OPCODES.values():
        ops = spec["operands"]
        if not isinstance(ops, str):
            continue
        if ops == "CONDITION":
            out |= {"condition-extended", "condition-short"}
        elif ops == "SHOWCHOICE":
            out |= {"choice-jump-pointer", "choice-jump-filename"}
        elif ops == "LAYERSLIST":
            out.add("layerslist")
        elif ops == "CHARIMAGE":
            out.add("charimage")
    return out


def _slug(rel: Path) -> str:
    return str(rel).replace(os.sep, "_").replace("/", "_")


# ---------------------------------------------------------------------------
# 回封（对应 GUI 的「回封文本」按钮）
# ---------------------------------------------------------------------------

def plan_repack(sources: list[Path], root: Path, text_dir: Path, *,
                source_encoding: str | None = None,
                target_encoding: str | None = None,
                progress: Progress = _noop) -> dict[str, Any]:
    """回封预览：只读，不写任何产物。冲突存在时不提供执行入口（§11.5.3）。"""
    src_enc = source_encoding
    tgt_enc = target_encoding      # None = 按每个文件的形态取默认值

    plans: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    changed = longer = 0
    delta = 0

    for n, src in enumerate(sources, 1):
        progress(n - 1, len(sources), src.name)
        rel = _rel(src, root)
        tpath = text_dir / "texts" / (str(rel) + ".txt")
        apath = text_dir / "asm" / (str(rel) + ".asm.txt")
        try:
            ir = parse_source(src, src_enc)
        except Exception as exc:
            errors.append({"file": str(rel), "code": "PARSE_FAILED",
                           "detail": str(exc)})
            continue

        # 没有译文文件时**不跳过**该源，而是按零编辑照常重建。
        # 游戏需要一套完整的脚本：无可翻译文本的系统脚本（图层擦除、初始化等）
        # 也必须出现在回封输出里，否则使用者把输出目录覆盖回游戏就会缺文件。
        # 零编辑重建的产物与原件逐字节相同，因此这样做没有任何风险。
        if not tpath.exists() and not apath.exists() and ir.texts:
            # 有可翻译文本却找不到译文文件：属于译文缺失，如实报出而不是静默跳过
            errors.append({
                "file": str(rel), "code": "TEXT_FILE_MISSING",
                "detail": f"该脚本有 {len(ir.texts)} 条可翻译文本，"
                          f"但找不到对应的译文文件 {tpath.name}"})
            continue

        # 该文件的译文编码：未显式指定时取形态默认值（UTF-16 形态仍写 UTF-16）
        file_tgt = tgt_enc or ir.default_target_encoding
        text_edits: dict[int, TextEdit] = {}
        asm_changed: dict[int, str] = {}
        if tpath.exists():
            try:
                text_edits, errs = parse_text_file(tpath, ir, file_tgt)
            except RepackError as exc:
                errors.append({"file": str(rel), "code": exc.code,
                               "detail": exc.detail})
                continue
            for e in errs:
                errors.append({"file": str(rel), **e})
        if apath.exists():
            fresh = render_asm(ir, ir.source_encoding)
            user = apath.read_text(encoding="utf-8")
            if hashlib.sha256(user.encode("utf-8")).digest() != \
               hashlib.sha256(fresh.encode("utf-8")).digest():
                try:
                    asm_changed = parse_asm_edits(user, fresh)
                except RepackError as exc:
                    errors.append({"file": str(rel), "code": exc.code,
                                   "detail": exc.detail})
                    continue

        # 双编辑面冲突检出：同一对象两侧取值不同即拒绝（§2.6 第四态）
        if asm_changed and text_edits:
            by_idx = {t.idx: t for t in ir.texts}
            for idx in text_edits:
                inst_off = by_idx[idx].inst_offset
                if inst_off in asm_changed:
                    conflicts.append({
                        "file": str(rel), "idx": idx,
                        "texts_value": text_edits[idx].new_text,
                        "asm_line": asm_changed[inst_off].strip(),
                    })

        if asm_changed:
            # 改 asm 的指令/结构需 T3 的控制流分析（未申报 T4）→ 明确拒绝
            errors.append({
                "file": str(rel), "code": "TIER_TOO_LOW",
                "detail": "ASM 结构改动需要控制流分析（T4），本方言申报 T3；"
                          "如只需改文本请改 texts/ 下的双行文本"})
            continue

        verdicts = probe_all(ir, text_edits, file_tgt, bool(asm_changed))
        try:
            chosen = select_strategy(verdicts)
        except RepackError as exc:
            errors.append({"file": str(rel), "code": exc.code,
                           "detail": exc.detail})
            continue

        # 长度一律走 encoded_len 这一个口径（§6.0.2）：按目标编码计字节、
        # 占位符按展开后计、终止符计入、词缀拼回。预览与实际执行必须用同一
        # 公式，否则预览里的 delta_bytes 会与最终产物不符。
        by_idx = {t.idx: t for t in ir.texts}
        for idx, ed in text_edits.items():
            entry = by_idx[idx]
            old = len(entry.raw) + ir.terminator_size
            new = encoded_len(entry.affix_prefix + ed.new_text + entry.affix_suffix,
                              file_tgt, terminator=ir.terminator_size)
            if new > old:
                longer += 1
            delta += new - old
        changed += len(text_edits)

        plans.append({
            "file": str(rel), "src": str(src),
            "edits": len(text_edits),
            "strategy": chosen.strategy_id,
            "verdicts": [v.as_dict() for v in verdicts],
        })

    progress(len(sources), len(sources), "")
    return {
        "files": len(plans), "changed_entries": changed,
        "longer_entries": longer, "delta_bytes": delta,
        "strategies": sorted({p["strategy"] for p in plans}),
        "conflicts": conflicts, "errors": errors,
        "plans": plans,
        "can_execute": not conflicts and not errors,
    }


def run_repack(sources: list[Path], root: Path, text_dir: Path, out_dir: Path, *,
               source_encoding: str | None = None,
               target_encoding: str | None = None,
               emit_plain: bool = True,
               progress: Progress = _noop) -> dict[str, Any]:
    """执行回封。产物一律进回封输出目录，绝不写原件（铁律 1）。

    **加密产物为交付物**：明文与加密产物分开命名共存，各自给出哈希，
    加密结果不覆盖明文对照物（§6.5）。
    """
    src_enc = source_encoding
    tgt_enc = target_encoding      # None = 按每个文件的形态取默认值

    plan = plan_repack(sources, root, text_dir,
                       source_encoding=src_enc, target_encoding=tgt_enc)
    if not plan["can_execute"]:
        return {"ok": False, "stage": "plan", **plan}

    work = out_dir / "_work"
    tmp = work / "tmp"
    failed = tmp / "failed"
    reports = work / "reports"
    for d in (out_dir, work, tmp, failed, reports):
        d.mkdir(parents=True, exist_ok=True)

    written: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    reloc_rows: list[str] = []
    verdict_rows: list[dict[str, Any]] = []

    for n, item in enumerate(plan["plans"], 1):
        src = Path(item["src"])
        rel = Path(item["file"])
        progress(n - 1, len(plan["plans"]), src.name)
        try:
            ir = parse_source(src, src_enc)
            tpath = text_dir / "texts" / (str(rel) + ".txt")
            file_tgt = tgt_enc or ir.default_target_encoding
            edits, errs = (parse_text_file(tpath, ir, file_tgt)
                           if tpath.exists() else ({}, []))
            if errs:
                errors.extend({"file": str(rel), **e} for e in errs)
                continue

            plain, reloc = rebuild(ir, edits, file_tgt)

            # 事务：先写 tmp 并重新解析验证，通过后才原子改名进 rebuilt/
            probe_path = failed / (rel.name + ".probe")
            problems = verify_rebuilt(ir, plain, edits, file_tgt,
                                      src_enc, probe_path)
            if problems:
                errors.append({"file": str(rel), "code": "VERIFY_FAILED",
                               "detail": "; ".join(problems)})
                continue
            probe_path.unlink(missing_ok=True)

            # 零编辑必须逐字节相同；有编辑必须不同（§6.0，两个方向都查）
            if not edits and plain != ir.data:
                errors.append({"file": str(rel), "code": "IDENTITY_BROKEN",
                               "detail": "零编辑却与原件不同"})
                continue
            if edits and plain == ir.data:
                errors.append({"file": str(rel), "code": "EDIT_LOST",
                               "detail": "有编辑却与原件逐字节相同，"
                                         "说明编辑被静默丢弃"})
                continue

            cipher = encrypt(plain)
            # 加密产物为交付物，文件名与原文一致，便于直接覆盖回游戏
            enc_path = out_dir / "rebuilt" / rel
            _atomic_write(enc_path, cipher, tmp)
            rec = {
                "file": str(rel), "edits": len(edits),
                "strategy": item["strategy"],
                "size_source": ir.size, "size_plain": len(plain),
                "sha256_source_plain": ir.sha256,
                "sha256_rebuilt_plain": hashlib.sha256(plain).hexdigest(),
                "sha256_rebuilt_encrypted": hashlib.sha256(cipher).hexdigest(),
                "encrypted_output": str(enc_path),
                "layer_stack": [O.DIALECT["cipher"]["algorithm"]],
            }
            if emit_plain:
                # 明文副本另存，作为"重新解析验证"的对照物
                p = out_dir / "rebuilt_plain" / rel
                _atomic_write(p, plain, tmp)
                rec["plain_output"] = str(p)
            written.append(rec)
            for r in reloc:
                reloc_rows.append(json.dumps({"file": str(rel), **r},
                                             ensure_ascii=False,
                                             separators=(",", ":")))
            verdict_rows.append({"file": str(rel),
                                 "selected_strategy": item["strategy"],
                                 "selection_rule":
                                     "minimum-capability-among-applicable",
                                 "verdicts": item["verdicts"]})
        except RepackError as exc:
            # run 失败不自动降级到下一策略（§6.2 第 5 条）
            errors.append({"file": str(rel), "code": exc.code,
                           "detail": exc.detail})
        except Exception as exc:
            errors.append({"file": str(rel), "code": "UNEXPECTED",
                           "detail": str(exc)})

    progress(len(plan["plans"]), len(plan["plans"]), "")

    _atomic_text(reports / "repack_verdicts.json",
                 json.dumps(verdict_rows, ensure_ascii=False, indent=1),
                 tmp, "utf-8")
    if reloc_rows:
        _atomic_text(reports / "relocation_log.jsonl",
                     "\n".join(reloc_rows), tmp, "utf-8")

    summary = {
        "files_written": len(written),
        "files_failed": len(errors),
        "changed_entries": plan["changed_entries"],
        "longer_entries": plan["longer_entries"],
        "delta_bytes": plan["delta_bytes"],
        "strategies": plan["strategies"],
        "output": str(out_dir),
        "encrypted": True,
        "cipher": O.DIALECT["cipher"]["algorithm"],
    }
    _atomic_text(reports / "repack_report.json", json.dumps(
        {"summary": summary, "written": written, "errors": errors},
        ensure_ascii=False, indent=1), tmp, "utf-8")

    return {"ok": not errors, "summary": summary,
            "written": written, "errors": errors}
