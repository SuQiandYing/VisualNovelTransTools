# -*- coding: utf-8 -*-
"""源二进制 → 内存 IR → asm.txt / 双行文本 / 覆盖证书。

结构逻辑模块：**不含任何引擎特定字面量**（opcode 值、魔数、文本正则一律取自
`opcodelist.py`），该约束由 scripts/check_no_literals.py 机械校验。

三个可分别调用的入口，输入均为源二进制、互不依赖（SKILL.md §11.5）：

    parse_source(path)      → Ir          内存 IR，解析真值
    render_asm(ir)          → str         结构编辑面
    render_texts(ir)        → str         双行文本编辑面（译者用）
    build_certificate(ir)   → dict        覆盖证书

IR 默认不落盘（§2.4）：解析确定性保证同一源字节必得同一 IR，重算比反序列化更快。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import opcodelist as O

TOOL_VERSION = "1.0.0"
IR_VERSION = "1"

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_F32 = struct.Struct("<f")


#: 标记「该 cstr 操作数是玩家可见的选项文本」。ShowChoice 的选项由计数驱动的
#: 循环产生，槽位下标不固定，无法用静态的 text_slots 表达，故在解析时打标记。
_CHOICE_TEXT = "<choice-text>"


class Ws2ParseError(Exception):
    """解析失败。必须带偏移，便于定位首个出错位置。"""

    def __init__(self, code: str, offset: int, detail: str = "") -> None:
        super().__init__(f"{code} @ 0x{offset:X} {detail}".strip())
        self.code = code
        self.offset = offset
        self.detail = detail


# ---------------------------------------------------------------------------
# IR 对象
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Operand:
    """单个操作数。`kind` 为原语名；`raw` 保留原始字节以便原样重写。"""
    kind: str
    offset: int
    size: int
    raw: bytes
    value: Any = None


@dataclass(slots=True)
class Instruction:
    offset: int
    size: int
    opcode: int
    mnemonic: str
    operands: list[Operand] = field(default_factory=list)
    #: 该指令内的可翻译文本条目下标（指向 Ir.texts）
    text_idx: list[int] = field(default_factory=list)
    #: 变长指令实际命中的形态 id；定长指令为 None。用于形态报告的产出归属。
    shapes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TextEntry:
    idx: int                  # 1 基，源内唯一，定宽 8 位十进制
    tag: str                  # 闭集八个之一（§4.2）
    tag_source: str           # structural / anchor / binding / heuristic / user / unresolved
    policy: str               # translatable / length-locked / review-required / frozen
    inst_offset: int          # 所属指令起始偏移
    slot_offset: int          # 该字符串在文件中的起始偏移
    raw: bytes                # 原始字节（不含 NUL）
    source: str               # 送给译者的**正文**（已剥离引擎词缀）
    speaker: str = ""         # 说话者名（仅 msg 有，已剥离 %LC）
    undecodable: bool = False
    #: 引擎词缀，不进双行文本，回封时原样拼回（§4.5 的控制码保留要求）。
    #: 不变式：affix_prefix + source + affix_suffix == 完整原文
    affix_prefix: str = ""
    affix_suffix: str = ""

    @property
    def full_source(self) -> str:
        """完整原文（含词缀）。回封与长度计算一律以此为准。"""
        return self.affix_prefix + self.source + self.affix_suffix


@dataclass(slots=True)
class JoinSite:
    """引用站点：承载绝对文件偏移的 4 字节槽（§3）。变长回封的改写单位。"""
    join_id: str
    site_offset: int
    site_width: int
    key_value: int            # 旧的绝对偏移
    inst_offset: int
    opcode: int
    slot_ordinal: int


@dataclass(slots=True)
class Ir:
    path: Path
    data: bytes
    sha256: str
    instructions: list[Instruction]
    texts: list[TextEntry]
    sites: list[JoinSite]
    #: 每个 opcode 的命中次数，供形态报告使用
    opcode_hits: dict[int, int]
    #: 变长形态命中次数（形态 id → 命中数 / 产出文本数）
    shape_hits: dict[str, dict[str, int]]
    #: 字符串形态：sbcs（旧版 CP932）或 utf16（新版 UTF-16LE）
    string_shape: str = O.SHAPE_SBCS
    #: 实际使用的原文编码，由字符串形态决定
    source_encoding: str = "cp932"
    #: 字符串终止符字节数（sbcs=1，utf16=2）
    terminator_size: int = 1

    @property
    def default_target_encoding(self) -> str:
        """该形态下译文应使用的编码。UTF-16 形态必须仍写 UTF-16LE。"""
        return O.STRING_SHAPES[self.string_shape]["default_target"]

    @property
    def size(self) -> int:
        return len(self.data)


# ---------------------------------------------------------------------------
# 占位符（§4.5）
# ---------------------------------------------------------------------------

#: Unicode 码位边界，非引擎常量：C0 控制区上界、DEL、以及基本多文种平面的
#: 私用区（BMP PUA）范围。这些取自 Unicode 标准，与方言无关，故不进
#: opcodelist.py——把它们移入方言反而会让每份方言重复声明同一组标准值。
_CTRL_MAX = 0x20        # dialect-literal-ok: Unicode C0 控制区上界，非引擎常量
_DEL = 0x7F             # dialect-literal-ok: Unicode DELETE，非引擎常量
_PUA_START = 0xE000     # dialect-literal-ok: Unicode BMP 私用区起点，非引擎常量
_PUA_END = 0xF8FF       # dialect-literal-ok: Unicode BMP 私用区终点，非引擎常量


def _needs_placeholder(ch: str) -> bool:
    """控制字符与 Unicode 私用区需占位符；斜杠、全角空格等**不得**转义。"""
    o = ord(ch)
    if o < _CTRL_MAX or o == _DEL:
        return True
    return _PUA_START <= o <= _PUA_END


def encode_placeholders(raw: bytes, encoding: str) -> tuple[str, bool]:
    """字节 → 可显示文本。返回 (文本, 是否存在不可解码字节)。

    不可解码字节禁止静默兜底（§4.4）：整条标 undecodable，逐字节占位符呈现。
    """
    try:
        decoded = raw.decode(encoding)
    except UnicodeDecodeError:
        return "".join("{{%02X}}" % b for b in raw), True

    out: list[str] = []
    for ch in decoded:
        if _needs_placeholder(ch):
            out.append("{{%s}}" % ":".join("%02X" % b for b in ch.encode(encoding)))
        else:
            out.append(ch)
    return "".join(out), False


def split_affixes(text: str, tag: str) -> tuple[str, str, str]:
    """把引擎控制码从正文两端剥离，返回 (前缀, 正文, 后缀)。

    这些标记不需要翻译，放进双行文本只会被误改或误删；剥离后它们仍完整保存
    在 IR 中，回封时原样拼回，因此不损失任何字节。

    后缀按 `MESSAGE_SUFFIX_TOKENS` **反复**剥离而非按定长切除：实测存在
    `%K%P` / `%P` / `%K` 三种收尾，定长切除会吃掉 `%K` 那条的最后一个字符。
    """
    if not O.STRIP_AFFIXES:
        return "", text, ""

    prefix = ""
    if tag == "name":
        for p in O.NAME_PREFIXES:
            if text.startswith(p):
                prefix, text = p, text[len(p):]
                break
        return prefix, text, ""

    # 后缀：反复剥离直到不再匹配。`%XE` 位于 `%K%P` 内侧，形如 `…%XE%K%P`，
    # 由循环自然处理，不必假定顺序。
    suffix = ""
    changed = True
    while changed:
        changed = False
        for token in O.MESSAGE_SUFFIX_TOKENS:
            if text.endswith(token):
                suffix = token + suffix
                text = text[:-len(token)]
                changed = True

    # 前缀：文字效果开始标记 `%XS<n>`。前后缀**各自独立判定**——实测存在
    # 只有 %XS 而没有 %XE 的条目，若按成对处理会漏剥。
    m = re.match(O.MESSAGE_PREFIX_RE, text)
    if m:
        prefix, text = m.group(), text[m.end():]
    return prefix, text, suffix


_PH_OPEN, _PH_CLOSE = "{{", "}}"


def decode_placeholders(text: str, encoding: str) -> bytes:
    """文本 → 字节。占位符直接解析为原始字节，忽略编码边界（§4.5）。"""
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        j = text.find(_PH_OPEN, i)
        if j < 0:
            out += text[i:].encode(encoding)
            break
        out += text[i:j].encode(encoding)
        k = text.find(_PH_CLOSE, j)
        if k < 0:
            raise ValueError("占位符未闭合")
        body = text[j + len(_PH_OPEN):k]
        for part in body.split(":"):
            if len(part) != 2 or any(c not in "0123456789ABCDEF" for c in part):
                raise ValueError(f"占位符必须为大写两位十六进制：{{{{{body}}}}}")
            out.append(int(part, 16))
        i = k + len(_PH_CLOSE)
    return bytes(out)


def encoded_len(text: str, encoding: str, terminator: int = 1) -> int:
    """§6.0.2 的唯一长度口径：按目标编码计字节，占位符按展开后计，含终止符。"""
    return len(decode_placeholders(text, encoding)) + terminator


# ---------------------------------------------------------------------------
# 解析：源二进制 → 内存 IR
# ---------------------------------------------------------------------------

def _read_cstr(data: bytes, i: int, term: int = 1) -> tuple[bytes, int]:
    """读一个终止符宽度为 `term` 字节的字符串，返回 (内容, 终止符后的偏移)。

    UTF-16 形态下终止符是 0x0000 且必须落在**偶数步长**上：单字节 find 会在
    形如 `41 00 42 00` 的串中途命中，把字符串截断在第一个高位字节处。
    """
    if term == 1:
        j = data.find(b"\x00", i)
        if j < 0:
            raise Ws2ParseError("UNTERMINATED_STRING", i)
        return data[i:j], j + 1

    n = len(data)
    j = i
    while j + term <= n:
        if data[j:j + term] == b"\x00" * term:
            return data[i:j], j + term
        j += term
    raise Ws2ParseError("UNTERMINATED_STRING", i)


def _operand_sequence(data: bytes, i: int, opcode: int,
                      shape_hits: dict[str, dict[str, int]],
                      hit_shapes: list[str] | None = None,
                      term: int = 1
                      ) -> tuple[list[tuple[str, int]], int, list[Operand]]:
    """求出该 opcode 的操作数序列。

    返回 (待读序列, 新偏移, 已读操作数)。变长形态在此就地展开：判定为纯谓词，
    与提取分离；无形态命中即抛错，**不返回空结果**（§7.1.3）。
    """
    spec = O.OPCODES[opcode]
    ops = spec["operands"]
    pre: list[Operand] = []

    if not isinstance(ops, str):
        return list(ops), i, pre

    n = len(data)

    if ops == "CONDITION":
        if i >= n:
            raise Ws2ParseError("OVERRUN", i)
        cfg = data[i]
        pre.append(Operand(O.U8, i, 1, data[i:i + 1], cfg))
        i += 1
        extended = cfg in O.CONDITION_EXTENDED_VALUES or (
            cfg == 3 and i < n and data[i] in O.CONDITION_CFG3_NEXT)
        shape = "condition-extended" if extended else "condition-short"
        _bump(shape_hits, shape, hit_shapes=hit_shapes)
        return (list(O.CONDITION_EXTENDED_OPERANDS) if extended else []), i, pre

    if ops == "SHOWCHOICE":
        if i >= n:
            raise Ws2ParseError("OVERRUN", i)
        count = data[i]
        pre.append(Operand(O.U8, i, 1, data[i:i + 1], count))
        i += 1
        for _ in range(count):
            if i + 2 > n:
                raise Ws2ParseError("OVERRUN", i)
            pre.append(Operand(O.U16, i, 2, data[i:i + 2], _U16.unpack_from(data, i)[0]))
            i += 2
            # 选项文本：玩家可见，可翻译。标记 is_choice_text 供文本收集识别，
            # 因为该槽位由循环产生，位置不固定，无法用静态 text_slots 下标表达。
            raw, nxt = _read_cstr(data, i, term)
            op = Operand(O.CSTR, i, nxt - i, raw, raw)
            op.value = _CHOICE_TEXT
            pre.append(op)
            i = nxt
            if i + 4 > n:
                raise Ws2ParseError("OVERRUN", i)
            jump_type = data[i + 3]
            pre.append(Operand((O.BYTES, 4), i, 4, data[i:i + 4], None))
            i += 4
            if jump_type == O.SHOWCHOICE_JUMP_POINTER:
                if i + 4 > n:
                    raise Ws2ParseError("OVERRUN", i)
                pre.append(Operand(O.PTR32, i, 4, data[i:i + 4],
                                   _U32.unpack_from(data, i)[0]))
                i += 4
                _bump(shape_hits, "choice-jump-pointer", hit_shapes=hit_shapes)
            elif jump_type == O.SHOWCHOICE_JUMP_FILENAME:
                raw, nxt = _read_cstr(data, i, term)
                pre.append(Operand(O.CSTR, i, nxt - i, raw, raw))
                i = nxt
                _bump(shape_hits, "choice-jump-filename", hit_shapes=hit_shapes)
            else:
                # 未知跳转类型：不猜测，直接失败（铁律 4）
                raise Ws2ParseError("UNKNOWN_CHOICE_JUMP_TYPE", i - 1,
                                    f"jump_type=0x{jump_type:02X}")
        return [], i, pre

    if ops == "LAYERSLIST":
        if i >= n:
            raise Ws2ParseError("OVERRUN", i)
        count = data[i]
        pre.append(Operand(O.U8, i, 1, data[i:i + 1], count))
        i += 1
        for _ in range(count):
            raw, nxt = _read_cstr(data, i, term)
            pre.append(Operand(O.CSTR, i, nxt - i, raw, raw))
            i = nxt
        _bump(shape_hits, "layerslist", hit_shapes=hit_shapes)
        return [], i, pre

    if ops == "CHARIMAGE":
        raw, nxt = _read_cstr(data, i, term)
        pre.append(Operand(O.CSTR, i, nxt - i, raw, raw))
        i = nxt
        if i + 3 > n:
            raise Ws2ParseError("OVERRUN", i)
        part_count = data[i + 2]
        pre.append(Operand((O.BYTES, 3), i, 3, data[i:i + 3], None))
        i += 3
        for _ in range(part_count):
            if i + 2 > n:
                raise Ws2ParseError("OVERRUN", i)
            pre.append(Operand(O.U16, i, 2, data[i:i + 2], _U16.unpack_from(data, i)[0]))
            i += 2
        _bump(shape_hits, "charimage", hit_shapes=hit_shapes)
        return [], i, pre

    raise Ws2ParseError("UNKNOWN_SHAPE", i, str(ops))


def _bump(hits: dict[str, dict[str, int]], shape: str, texts: int = 0,
          hit_shapes: list[str] | None = None) -> None:
    rec = hits.setdefault(shape, {"entries": 0, "texts": 0})
    rec["entries"] += 1
    rec["texts"] += texts
    if hit_shapes is not None and shape not in hit_shapes:
        hit_shapes.append(shape)


def detect_string_shape(data: bytes) -> str:
    """结构性判定该文件用哪种字符串形态（§7.1.2：不看文件名，只看结构）。

    以两种形态分别做全量顺序解析，取**唯一**能让指令流恰好覆盖整个文件的那个。
    两种都通过或都失败时抛错，不任选（铁律 4：歧义不得静默消解）。
    """
    survivors: list[tuple[str, int]] = []
    for sid, shape in O.STRING_SHAPES.items():
        parsed = _try_parse(data, shape["terminator_size"])
        if parsed is not None:
            survivors.append((sid, parsed))

    if not survivors:
        raise Ws2ParseError("NO_STRING_SHAPE_MATCHES", 0,
                            "两种字符串形态都无法完整解析该文件")
    if len(survivors) == 1:
        return survivors[0][0]

    # 多个形态同时走通，只在**该文件根本不含字符串**时才允许——此时两种形态
    # 产出完全相同的指令流与 IR，选哪个都不影响任何字节，故非真歧义。
    # 实测旧版语料中 Init/FlagInit/ClearCheck 三个纯控制流脚本属于此类。
    if all(count == 0 for _, count in survivors):
        return O.DIALECT["default_string_shape"]

    # 含字符串却仍多解 → 判据确实不足，拒绝并要求收窄（铁律 4）
    raise Ws2ParseError(
        "AMBIGUOUS_STRING_SHAPE", 0,
        f"多个形态同时成立且文件含字符串：{[s for s, _ in survivors]}；判据需收窄")


def _try_parse(data: bytes, term: int) -> int | None:
    """试解析。走通则返回字符串操作数个数，失败返回 None。

    纯谓词、无副作用（§7.1.3）。返回字符串个数而非布尔，是为了让上层能区分
    「两种形态都能过是因为没有字符串」与「真的存在歧义」。
    """
    try:
        instructions, _, _ = _walk(data, term)
    except Ws2ParseError:
        return None
    return sum(1 for inst in instructions
               for op in inst.operands if op.kind == O.CSTR)


def parse_source(path: Path, source_encoding: str | None = None,
                 string_shape: str | None = None) -> Ir:
    """源二进制 → 内存 IR。确定性：同一字节 + 同一编码必得同一 IR。

    `string_shape` 缺省时按结构自动判定（sbcs / utf16），因此同一套代码同时
    支持旧版（CP932 单字节串）与新版（UTF-16LE 双字节串）语料。
    """
    data = path.read_bytes()
    shape_id = string_shape or detect_string_shape(data)
    shape = O.STRING_SHAPES[shape_id]
    enc = source_encoding or shape["encoding"]
    term = shape["terminator_size"]

    instructions, opcode_hits, shape_hits = _walk(data, term)
    texts: list[TextEntry] = []
    sites: list[JoinSite] = []
    _collect_texts(instructions, texts, sites, enc, term)

    return Ir(path=path, data=data, sha256=hashlib.sha256(data).hexdigest(),
              instructions=instructions, texts=texts, sites=sites,
              opcode_hits=opcode_hits, shape_hits=shape_hits,
              string_shape=shape_id, source_encoding=enc,
              terminator_size=term)


def _walk(data: bytes, term: int, collect: bool = True
          ) -> tuple[list[Instruction], dict[int, int], dict[str, dict[str, int]]]:
    """严格顺序切分指令流。检测与解析共用同一实现，避免两处逻辑漂移。

    任何未定义 opcode / 越界 / 未终止字符串 / FileEnd 后有残留字节，都抛错，
    绝不跳过或猜测（铁律 4、§1.4）。
    """
    n = len(data)
    instructions: list[Instruction] = []
    opcode_hits: dict[int, int] = {}
    shape_hits: dict[str, dict[str, int]] = {}

    i = O.DIALECT["code_start"]
    saw_file_end = False

    while i < n:
        start = i
        opcode = data[i]
        spec = O.OPCODES.get(opcode)
        if spec is None:
            # 未定义 opcode：回溯到最后一条已验证指令，报错并停止（§1.4）
            raise Ws2ParseError(
                "UNDEFINED_OPCODE", start,
                f"0x{opcode:02X}; last_verified="
                f"0x{instructions[-1].offset:X}" if instructions else "none")
        i += 1

        hit_shapes: list[str] = []
        seq, i, operands = _operand_sequence(data, i, opcode, shape_hits,
                                             hit_shapes, term)

        for slot, kind in enumerate(seq):
            if isinstance(kind, tuple):            # (BYTES, n)
                width = kind[1]
                if i + width > n:
                    raise Ws2ParseError("OVERRUN", i)
                operands.append(Operand(kind, i, width, data[i:i + width], None))
                i += width
            elif kind == O.CSTR:
                raw, nxt = _read_cstr(data, i, term)
                operands.append(Operand(O.CSTR, i, nxt - i, raw, raw))
                i = nxt
            elif kind == O.U8:
                if i + 1 > n:
                    raise Ws2ParseError("OVERRUN", i)
                operands.append(Operand(O.U8, i, 1, data[i:i + 1], data[i]))
                i += 1
            elif kind == O.U16:
                if i + 2 > n:
                    raise Ws2ParseError("OVERRUN", i)
                operands.append(Operand(O.U16, i, 2, data[i:i + 2],
                                        _U16.unpack_from(data, i)[0]))
                i += 2
            elif kind == O.F32:
                if i + 4 > n:
                    raise Ws2ParseError("OVERRUN", i)
                operands.append(Operand(O.F32, i, 4, data[i:i + 4],
                                        _F32.unpack_from(data, i)[0]))
                i += 4
            else:                                   # U32 / PTR32
                if i + 4 > n:
                    raise Ws2ParseError("OVERRUN", i)
                operands.append(Operand(kind, i, 4, data[i:i + 4],
                                        _U32.unpack_from(data, i)[0]))
                i += 4

        inst = Instruction(start, i - start, opcode, spec["mnemonic"], operands,
                           shapes=hit_shapes)
        instructions.append(inst)
        opcode_hits[opcode] = opcode_hits.get(opcode, 0) + 1

        if opcode == O.DIALECT["file_end_opcode"]:
            saw_file_end = True
            if i != n:
                raise Ws2ParseError("TRAILING_BYTES_AFTER_FILE_END", i,
                                    f"file_size={n}")
            break

    if i != n:
        raise Ws2ParseError("INCOMPLETE_PARSE", i, f"file_size={n}")
    if not saw_file_end:
        raise Ws2ParseError("MISSING_FILE_END", n)

    return instructions, opcode_hits, shape_hits


def _collect_texts(instructions: list[Instruction], texts: list[TextEntry],
                   sites: list[JoinSite], enc: str, term: int = 1) -> None:
    """从已解析的指令流中收集文本条目、人名绑定与引用站点。

    全部依据结构（指令 + 操作数序号），不做任何字节扫描（铁律 2）。
    """
    # ---- 引用站点：承载绝对偏移的 PTR32 操作数 ----
    for inst in instructions:
        ordinal = 0
        for op in inst.operands:
            if op.kind != O.PTR32:
                continue
            ordinal += 1
            if op.value == 0:          # 0 表示无目标，不登记
                continue
            sites.append(JoinSite(
                join_id=f"J{len(sites) + 1:05d}",
                site_offset=op.offset, site_width=4, key_value=op.value,
                inst_offset=inst.offset, opcode=inst.opcode,
                slot_ordinal=ordinal))

    # ---- 文本条目 ----
    # 说话者绑定：method = slot-ordinal（引擎调用序约束，非物理相邻猜测）。
    # SetDisplayName 设置当前说话者，紧邻的下一条 DisplayMessage 使用它。
    pending_speaker = ""
    idx = 0
    name_op = next(iter(O.TEXT_SLOTS))  # 占位，避免下面用字面量

    for inst in instructions:
        slots = O.TEXT_SLOTS.get(inst.opcode)
        produced_name = None

        # 选项文本：由循环产生，按标记识别而非固定下标（见 _CHOICE_TEXT）
        for op in inst.operands:
            if op.kind != O.CSTR or op.value is not _CHOICE_TEXT:
                continue
            full, undecodable = encode_placeholders(op.raw, enc)
            prefix, body, suffix = ("", full, "") if undecodable else \
                split_affixes(full, "choice")
            if not body:
                continue
            idx += 1
            entry = TextEntry(
                idx=idx, tag="choice", tag_source="structural",
                policy=("frozen" if undecodable
                        else O.TRANSLATE_POLICY_BY_TAG["choice"]),
                inst_offset=inst.offset, slot_offset=op.offset,
                raw=op.raw, source=body, undecodable=undecodable,
                affix_prefix=prefix, affix_suffix=suffix)
            if entry.full_source != full:
                raise Ws2ParseError("AFFIX_SPLIT_LOSSY", op.offset,
                                    f"{entry.full_source!r} != {full!r}")
            texts.append(entry)
            inst.text_idx.append(len(texts) - 1)

        if slots:
            # 取该指令中 cstr 操作数的序号，与声明的 text_slots 下标对齐
            cstr_ordinals = [k for k, op in enumerate(inst.operands)
                             if op.kind == O.CSTR]
            for slot_index, tag in slots.items():
                if slot_index >= len(inst.operands):
                    continue
                op = inst.operands[slot_index]
                if op.kind != O.CSTR:
                    continue
                raw = op.raw
                if not raw:
                    # 空槽：无可翻译内容，不产出条目（结构性判定，非启发式）
                    continue
                full, undecodable = encode_placeholders(raw, enc)
                prefix, body, suffix = ("", full, "") if undecodable else \
                    split_affixes(full, tag)
                if not body:
                    # 整条只有引擎标记（实测 5 条 `%P`）：没有可翻译内容，
                    # 不产出条目。词缀仍在原字节中，回封时原样写回。
                    continue
                idx += 1
                entry = TextEntry(
                    idx=idx, tag=tag,
                    tag_source="structural",
                    policy=("frozen" if undecodable
                            else O.TRANSLATE_POLICY_BY_TAG.get(tag, "review-required")),
                    inst_offset=inst.offset, slot_offset=op.offset,
                    raw=raw, source=body, undecodable=undecodable,
                    affix_prefix=prefix, affix_suffix=suffix)
                # 不变式：拼回后必须与完整原文逐字符相同，否则剥离逻辑有缺陷
                if entry.full_source != full:
                    raise Ws2ParseError("AFFIX_SPLIT_LOSSY", op.offset,
                                        f"{entry.full_source!r} != {full!r}")
                texts.append(entry)
                inst.text_idx.append(len(texts) - 1)
                if tag == "name":
                    produced_name = entry

        # 绑定：name 条目暂存，供紧邻的下一条 msg 使用
        if produced_name is not None:
            pending_speaker = produced_name.source
        elif inst.text_idx:
            for t in inst.text_idx:
                if texts[t].tag == "msg" and pending_speaker:
                    texts[t].speaker = pending_speaker
                    texts[t].tag_source = "structural"
            pending_speaker = ""
        else:
            # 其他指令打断绑定关系
            if O.TEXT_SLOTS.get(inst.opcode) is None:
                pending_speaker = pending_speaker if inst.opcode in _TRANSPARENT else ""


#: 不打断 name→msg 绑定的指令（本作中 name 与 msg 严格紧邻，故为空集）。
_TRANSPARENT: frozenset[int] = frozenset()


# ---------------------------------------------------------------------------
# 投影一：asm.txt（结构编辑面）
# ---------------------------------------------------------------------------

def _fmt_operand(op: Operand, enc: str) -> str:
    if op.kind == O.CSTR:
        text, _ = encode_placeholders(op.raw, enc)
        return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')
    if op.kind == O.PTR32:
        return "loc_%08X" % op.value if op.value else "0"
    if op.kind == O.F32:
        return repr(op.value)
    if isinstance(op.kind, tuple):
        return ", ".join(str(b) for b in op.raw)
    return str(op.value)


def render_asm(ir: Ir, source_encoding: str | None = None) -> str:
    """IR → asm.txt。渲染必须确定性：同一 IR 逐字节相同（§2.6）。"""
    enc = source_encoding or O.DIALECT["encoding"]["source"]
    targets = {s.key_value for s in ir.sites}

    lines = [
        "; %s" % ir.path.name,
        '.encoding "%s"' % enc,
        '.dialect  "%s" version "%s"' % (O.DIALECT["dialect_id"],
                                         O.DIALECT["schema_version"]),
        '.tier     "T3"',
        "",
    ]
    text_by_inst: dict[int, list[int]] = {}
    for k, t in enumerate(ir.texts):
        text_by_inst.setdefault(t.inst_offset, []).append(k)

    for inst in ir.instructions:
        if inst.offset in targets:
            lines.append("")
            lines.append("loc_%08X:" % inst.offset)
        args = ", ".join(_fmt_operand(op, enc) for op in inst.operands)
        comment = ""
        ids = text_by_inst.get(inst.offset)
        if ids:
            comment = "    ; " + " ".join(
                "idx=%08d" % ir.texts[k].idx for k in ids)
        lines.append("    0x%04X  %-24s %s%s"
                     % (inst.offset, inst.mnemonic, args, comment))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 投影二：双行文本（译者编辑面，§4.6）
# ---------------------------------------------------------------------------

O_MARK, T_MARK = "○", "●"


def render_texts(ir: Ir, source_encoding: str | None = None,
                 target_encoding: str | None = None) -> str:
    """IR → 双行文本。译文行预填原文（§4.6），未翻译判据为 target == source。"""
    src = source_encoding or O.DIALECT["encoding"]["source"]
    tgt = target_encoding or O.DIALECT["encoding"]["target"]

    out = [
        "# TEXT/2 ir=%s tool=%s src_sha256=%s" % (IR_VERSION, TOOL_VERSION, ir.sha256),
        "# encoding source=%s target=%s file=utf-8" % (src, tgt),
        "# scope kind=all range=ALL part=1/1",
        "# tags name msg choice label ui system ruby misc",
        "#",
        "",
    ]
    for t in ir.texts:
        # 元数据行只写导入时真正校验的字段 + 译者真正会读的 speaker（§4.6）
        meta = "# idx=%08d off=0x%08X tag=%s" % (t.idx, t.slot_offset, t.tag)
        if t.tag == "msg" and t.speaker:
            meta += " speaker=%s" % t.speaker
        out.append(meta)
        out.append("%s%08d%s%s%s%s" % (O_MARK, t.idx, O_MARK, t.tag, O_MARK, t.source))
        out.append("%s%08d%s%s%s%s" % (T_MARK, t.idx, T_MARK, t.tag, T_MARK, t.source))
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 覆盖证书（§8）
# ---------------------------------------------------------------------------

def build_certificate(ir: Ir) -> dict[str, Any]:
    """逐指令一个区间，恰好平铺 [0, size)。T3 区间附 opcode 与操作数。"""
    intervals = []
    for inst in ir.instructions:
        raw = ir.data[inst.offset:inst.offset + inst.size]
        intervals.append({
            "id": "I%08X" % inst.offset,
            "layer_id": "L000",
            "start": inst.offset,
            "end": inst.offset + inst.size,
            "status": "decoded",
            "kind": "instruction",
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "owner": inst.mnemonic,
            "decode_tier": "T3",
            "tier_evidence_refs": ["EV_OPCODE_TABLE", "EV_FULL_WALK"],
            "tier_blocked_at": None,
            "confidence": "derived",
            "evidence_refs": ["EV_OPCODE_TABLE"],
            "rewrite_policy": "pointer-rewrite",
            "opcode": "0x%02X" % inst.opcode,
            "variant": inst.mnemonic,
            "operands": [
                {"kind": (op.kind if isinstance(op.kind, str)
                          else "bytes[%d]" % op.kind[1]),
                 "offset": op.offset, "size": op.size}
                for op in inst.operands],
            "label": None,
            "target": None,
        })

    tag_source_counts = {k: 0 for k in
                         ("structural", "anchor", "binding", "heuristic",
                          "user", "unresolved")}
    for t in ir.texts:
        tag_source_counts[t.tag_source] = tag_source_counts.get(t.tag_source, 0) + 1

    return {
        "schema_version": "1.1.0",
        "layer_id": "L000",
        "source_size": ir.size,
        "intervals": intervals,
        "gaps": [],
        "overlaps": [],
        # status_counts 以**字节数**计（与 tier_coverage 同口径），不是区间条数
        "status_counts": {"decoded": ir.size},
        "byte_coverage": 1.0,
        "structural_coverage": 1.0,
        "tier_coverage": {"T0": 0, "T1": 0, "T2": 0, "T3": ir.size, "T4": 0},
        "min_tier": "T3",
        "declared_capabilities": ["roundtrip", "in_place", "pointer-rewrite"],
        "tier_blocked": [],
        "instruction_coverage": 1.0,
        "tag_source_counts": tag_source_counts,
        "transform_edges": [{
            "id": "T000",
            "algorithm": O.DIALECT["cipher"]["algorithm"],
            "reversible": True,
            "evidence_refs": O.DIALECT["cipher"]["evidence_refs"],
            "note": "回封时按逆序重新加密；明文与加密产物分开落盘",
        }],
        "roundtrip": {},
        "toolchain": {"tool": "ws2_tool", "version": TOOL_VERSION,
                      "dialect": O.DIALECT["dialect_id"],
                      "ir_version": IR_VERSION},
        "analysis_mode": "bytecode-disasm",
        "declared_tier": "T3",
        "unpack_mode": "not-required",
        "text_source": "embedded",
    }


def serialize(ir: Ir) -> bytes:
    """IR → 字节。零编辑时必须与源逐字节相同（§6.0 identity）。"""
    nul = b"\x00" * ir.terminator_size
    out = bytearray()
    for inst in ir.instructions:
        out.append(inst.opcode)
        for op in inst.operands:
            if op.kind == O.CSTR:
                out += op.raw + nul
            else:
                out += op.raw
    return bytes(out)


# ---------------------------------------------------------------------------
# 批量入口
# ---------------------------------------------------------------------------

def iter_sources(inputs: Iterable[Path]) -> list[Path]:
    """收集输入。排除 output/ 目录，避免把上一轮产物当新输入。"""
    exts = {".ws2", ".wsc"}
    found: list[Path] = []
    for p in inputs:
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.suffix.lower() in exts and "output" not in f.parts:
                    found.append(f)
        elif p.suffix.lower() in exts:
            found.append(p)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ws2 反汇编：源二进制 → 双行文本 / ASM / 覆盖证书")
    ap.add_argument("inputs", type=Path, nargs="+")
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument("--source-encoding")
    ap.add_argument("--target-encoding")
    ap.add_argument("--no-texts", action="store_true")
    ap.add_argument("--asm", action="store_true", help="同时输出 ASM 清单")
    ap.add_argument("--with-ir", action="store_true", help="额外落盘 IR（排查用）")
    args = ap.parse_args(argv)

    srcs = iter_sources(args.inputs)
    if not srcs:
        print("没有找到 .ws2 / .wsc 文件", file=sys.stderr)
        return 1
    if args.no_texts and not args.asm:
        print("请至少选择一种输出（双行文本或 ASM）", file=sys.stderr)
        return 1

    root = args.inputs[0] if args.inputs[0].is_dir() else args.inputs[0].parent
    out = args.output or root.parent / (root.name + "_text")

    from repack import export_all      # 复用同一套实现，保证三入口一致
    result = export_all(srcs, root, out,
                        want_texts=not args.no_texts, want_asm=args.asm,
                        source_encoding=args.source_encoding,
                        target_encoding=args.target_encoding,
                        with_ir=args.with_ir)
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
