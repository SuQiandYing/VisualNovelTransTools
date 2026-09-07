# -*- coding: utf-8 -*-
"""结构逻辑：容器解析、Huffman 编解码、行形态派发、内存 IR。

本模块不含引擎特定字面量——全部数值、命令名、正则来自 opcodelist（§7 硬规则，
可用 check_no_literals.py 机械检查）。
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import opcodelist as D


class ParseError(Exception):
    pass


class BadEscape(ParseError):
    """译文里出现无法识别的转义。可用的只有 \\n / \\t / \\\\（§4.5 的方言写法）。"""


class UnknownLineShape(ParseError):
    """无形态命中。§7.1.3：必须失败，不得返回空结果。"""

    def __init__(self, src: str, lineno: int, signature: str):
        super().__init__(f"{src}:{lineno} 无形态命中，signature={signature!r}")
        self.src, self.lineno, self.signature = src, lineno, signature


class AddressSpaceGapError(ParseError):
    pass


class AddressSpaceCollisionError(ParseError):
    pass


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------
# Huffman（TRANSFORMS["huffman_lilim"]）
# --------------------------------------------------------------------------
_HUF = next(t for t in D.TRANSFORMS if t["id"] == "huffman_lilim")
_HP = _HUF["params"]
_TREE = _HP["tree"]


class _BitReader:
    __slots__ = ("b", "p", "acc", "n")

    def __init__(self, b: bytes):
        self.b, self.p, self.acc, self.n = b, 0, 0, 0

    def bit(self) -> int:
        if self.n == 0:
            if self.p >= len(self.b):
                raise ParseError("位流提前耗尽")
            self.acc = self.b[self.p]
            self.p += 1
            self.n = 8
        v = (self.acc >> 7) & 1
        self.acc = (self.acc << 1) & 0xFF
        self.n -= 1
        return v

    def bits(self, count: int) -> int:
        v = 0
        for _ in range(count):
            v = (v << 1) | self.bit()
        return v


class _BitWriter:
    __slots__ = ("out", "acc", "n")

    def __init__(self):
        self.out, self.acc, self.n = bytearray(), 0, 0

    def bit(self, v: int) -> None:
        self.acc = (self.acc << 1) | (v & 1)
        self.n += 1
        if self.n == 8:
            self.out.append(self.acc)
            self.acc, self.n = 0, 0

    def bits(self, value: int, count: int) -> None:
        for i in range(count - 1, -1, -1):
            self.bit((value >> i) & 1)

    def finish(self) -> bytes:
        if self.n:
            self.out.append((self.acc << (8 - self.n)) & 0xFF)
            self.acc, self.n = 0, 0
        return bytes(self.out)


def huffman_decode(payload: bytes, unpacked_size: int) -> bytes:
    """解压。位序与树编码见 opcodelist.TRANSFORMS。"""
    br = _BitReader(payload)
    limit = _TREE["max_symbols"]
    first = _TREE["first_internal_symbol"]
    lhs = [0] * limit
    rhs = [0] * limit
    next_sym = [first]
    internal = _TREE["internal_marker"]
    vbits = _TREE["leaf_value_bits"]

    def build() -> int:
        # 迭代式前序重建，避免深树触发递归上限。
        root_slot: list[int] = []
        stack: list[tuple[int, int]] = []  # (parent, which_child) which: 0=left 1=right
        while True:
            if br.bit() == internal:
                node = next_sym[0]
                next_sym[0] += 1
                if node >= limit:
                    raise ParseError("Huffman 节点数超出方言声明上限")
            else:
                node = br.bits(vbits)
            if stack:
                parent, which = stack.pop()
                if which == 0:
                    lhs[parent] = node
                    stack.append((parent, 1))
                else:
                    rhs[parent] = node
            else:
                root_slot.append(node)
            if node >= first:
                stack.append((node, 0))
            elif not stack:
                break
        return root_slot[0]

    root = build()
    out = bytearray()
    if root < first:
        # 单叶树：整个流为同一字节的重复，无判定位。
        return bytes([root]) * unpacked_size
    while len(out) < unpacked_size:
        sym = root
        while sym >= first:
            sym = rhs[sym] if br.bit() else lhs[sym]
        out.append(sym)
    return bytes(out)


def _canonical_tree(data: bytes) -> tuple[dict[int, str], list[tuple[int, Any]]]:
    """按频次构造 Huffman 树，返回码表与前序编码序列。

    构造规则固定（频次升序、同频按字节值升序、合并结果插回队尾保持稳定），因此
    同一输入必得同一棵树——渲染确定性的前提（§2.6）。
    """
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    if not freq:
        raise ParseError("空数据无法构造 Huffman 树")

    first = _TREE["first_internal_symbol"]
    nodes: dict[int, Any] = {}
    seq = sorted(freq.items(), key=lambda kv: (kv[1], kv[0]))
    heap: list[tuple[int, int, Any]] = [(f, b, b) for b, f in seq]
    counter = 0
    while len(heap) > 1:
        heap.sort(key=lambda t: (t[0], t[1]))
        (f1, o1, n1), (f2, o2, n2) = heap[0], heap[1]
        del heap[:2]
        counter += 1
        node = ("I", n1, n2)
        heap.append((f1 + f2, first + counter, node))
    root = heap[0][2]

    codes: dict[int, str] = {}
    preorder: list[tuple[int, Any]] = []

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, tuple):
            preorder.append((_TREE["internal_marker"], None))
            walk(node[1], prefix + "0")
            walk(node[2], prefix + "1")
        else:
            preorder.append((_TREE["leaf_marker"], node))
            codes[node] = prefix or "0"

    import sys
    old = sys.getrecursionlimit()
    # 树深上界为符号数，取声明上限的若干倍留余量；纯语言运行时参数，非方言值。
    sys.setrecursionlimit(max(old, _TREE["max_symbols"] * 8))  # dialect-literal-ok
    try:
        walk(root, "")
    finally:
        sys.setrecursionlimit(old)
    return codes, preorder


def huffman_encode(data: bytes) -> bytes:
    """压缩为该方言的位流（不含前置长度字段）。"""
    codes, preorder = _canonical_tree(data)
    bw = _BitWriter()
    vbits = _TREE["leaf_value_bits"]
    for marker, value in preorder:
        bw.bit(marker)
        if value is not None:
            bw.bits(value, vbits)
    for byte in data:
        for ch in codes[byte]:
            bw.bit(1 if ch == "1" else 0)
    return bw.finish()


# --------------------------------------------------------------------------
# 容器（AOSv2）
# --------------------------------------------------------------------------
_V2 = D.CONTAINER["v2"]
_FMT_U32 = "<I" if D.CONTAINER["endianness"] == "little" else ">I"
_FMT_I32 = "<i" if D.CONTAINER["endianness"] == "little" else ">i"


@dataclass
class ArcEntry:
    index: int
    name: str
    name_raw: bytes
    rel_offset: int
    offset: int
    size: int
    index_offset: int  # 该条目索引项在文件中的起始偏移
    is_packed: bool
    raw_sha256: str
    unpacked_size: int | None = None


@dataclass
class Archive:
    path: Path
    data: bytes
    base_offset: int
    index_size: int
    entries: list[ArcEntry]
    src_sha256: str

    @property
    def index_offset(self) -> int:
        return _V2["index"]["offset"]


def _read_u32(d: bytes, off: int) -> int:
    return struct.unpack_from(_FMT_U32, d, off)[0]


def parse_archive(path: Path) -> Archive:
    data = Path(path).read_bytes()
    sig = _V2["signature"]
    if struct.unpack_from(_FMT_I32, data, sig["offset"])[0] != sig["equals"]:
        raise ParseError(f"{path.name} 不是 AOSv2（签名字段不为声明值）")

    hdr = {f["name"]: f for f in _V2["header"]["fields"]}
    base = _read_u32(data, hdr["base_offset"]["offset"])
    index_size = struct.unpack_from(_FMT_I32, data, hdr["index_size"]["offset"])[0]
    idx_off = _V2["index"]["offset"]
    stride = _V2["index"]["stride"]

    if index_size <= 0 or idx_off + index_size > len(data):
        raise ParseError("索引大小越界")
    if base < idx_off + index_size or base > len(data):
        raise ParseError("base_offset 与索引区冲突")
    if index_size % stride:
        raise ParseError("索引大小不是条目步长的整数倍")

    ef = _V2["entry"]
    nf, of, sf = ef["name"], ef["offset"], ef["size"]
    term = bytes.fromhex(nf["terminator"])
    packed_ext = _HUF["applies_to_extension"]

    entries: list[ArcEntry] = []
    for i in range(index_size // stride):
        io = idx_off + i * stride
        raw = data[io + nf["offset"]: io + nf["offset"] + nf["width"]]
        z = raw.find(term)
        name_raw = raw if z < 0 else raw[:z]
        if not name_raw:
            raise ParseError(f"索引项 {i} 名字为空")
        name = name_raw.decode(D.SCRIPT["source_encoding"])
        rel = _read_u32(data, io + of["offset"])
        size = _read_u32(data, io + sf["offset"])
        start = base + rel
        if start + size > len(data):
            raise ParseError(f"条目 {name} 越界")
        entries.append(ArcEntry(
            index=i, name=name, name_raw=name_raw, rel_offset=rel,
            offset=start, size=size, index_offset=io,
            is_packed=name.lower().endswith(packed_ext),
            raw_sha256=sha256(data[start:start + size]),
        ))
    return Archive(path=Path(path), data=data, base_offset=base,
                   index_size=index_size, entries=entries, src_sha256=sha256(data))


def entry_bytes(arc: Archive, e: ArcEntry) -> bytes:
    """返回条目的解封装内容；.scr 走 Huffman 逆变换。"""
    stored = arc.data[e.offset:e.offset + e.size]
    if not e.is_packed:
        return stored
    po = _HP["payload_offset"]
    usz = _read_u32(stored, _HP["unpacked_size"]["offset"])
    e.unpacked_size = usz
    out = huffman_decode(stored[po:], usz)
    if len(out) != usz:
        raise ParseError(f"{e.name} 解压长度不符：{len(out)} != {usz}")
    return out


def pack_entry(e: ArcEntry, content: bytes) -> bytes:
    """把内容重新封装成存档中的字节形态。"""
    if not e.is_packed:
        return content
    body = huffman_encode(content)
    return struct.pack(_FMT_U32, len(content)) + body


# --------------------------------------------------------------------------
# 行形态派发（§7.1.3）
# --------------------------------------------------------------------------
_SHAPES = [(s["id"], re.compile(s["match"]), s) for s in D.LINE_SHAPES]
_ARG_RULES = {(r["cmd"], r["ordinal"]): r for r in D.CALLEE_STRING_ARGS}
_INNER_RULES = {(r["cmd"], r["ordinal"]): re.compile(r["inner_regex"])
                for r in D.CALLEE_STRING_ARGS if r.get("inner_regex")}
_STR_LIT = re.compile(r'"([^"]*)"')

#: (shape_id, slot_name) -> tag_subtype。来自 LINE_SHAPES 声明期即校验：
#: 形态有 text_slots 却无 subtype 声明时，parse_script 直接报错而非静默。
_SUBTYPES = {
    ("dialogue", "msg"): "dialogue-body",
    ("dialogue", "speaker"): "speaker-name",
    ("narration", "msg"): "narration-body",
    ("choice", "choice"): "choice-option",
    ("choice_listing", "choice"): "choice-option",
    ("quoted_narration", "msg"): "quoted-narration-body",
    ("dialogue_cont", "msg"): "dialogue-continuation",
    ("cg_label", "label"): "cg-label",
}


_SIG_BUCKET = 20   # dialect-literal-ok: 报告用长度分桶粒度，不参与解析判定
_SIG_CAP = 80      # dialect-literal-ok: 同上，仅影响签名字符串的可读性


def line_signature(line: str) -> str:
    """形态签名：首字符类别 + 长度桶。用于报告未命中形态（§7.1.3）。"""
    if not line:
        return "empty"
    c = line[0]
    kind = ("ascii-alpha" if c.isascii() and c.isalpha()
            else "ascii-punct" if c.isascii() and not c.isspace()
            else "ascii-space" if c.isascii()
            else "wide")
    return f"{kind}/len{min(len(line), _SIG_CAP) // _SIG_BUCKET * _SIG_BUCKET}"


@dataclass
class ContSpan:
    """续行片段：同一句正文被作者折到下一物理行的那一段。

    条目的 source 是各片段按行序拼接的结果，因此译者看到的是完整一句
    （EV_SHAPE_CONT）。改写时主片段写入新译文，续行片段清空——片段各自
    按 (lineno, col_start, col_end) 定位，仍是按站点不按值（§6.3）。
    """
    lineno: int
    col_start: int
    col_end: int
    source: str
    shape_id: str


@dataclass
class TextSlot:
    """一处可翻译文本，即改写站点（§3：JoinSite 同时是发现依据与改写单位）。"""
    idx: int
    lineno: int
    shape_id: str
    slot_name: str
    tag: str
    tag_subtype: str
    tag_source: str
    translate_policy: str
    source: str
    col_start: int  # 在该行中的字符起止，改写按此定位，不按值
    col_end: int
    speaker: str | None = None
    pair_idx: int | None = None
    #: 别名站点：同文件内正文与主条目相同的重复槽位（DEBUG 分支等）。导出时省略，
    #: 回封时随主条目一并回填（用户确认的选项归并需求）。None = 主条目。
    alias_of: int | None = None
    #: 续行片段（折行的后续物理行）。非空时 source 为各片段拼接结果，
    #: own_source 保存主片段在原行中的那一段，供改写前逐字校验。
    cont_spans: list[ContSpan] = field(default_factory=list)
    own_source: str | None = None


@dataclass
class ScriptIR:
    src_id: str
    name: str
    src_sha256: str          # 解封装后内容的哈希
    stored_sha256: str       # 存档中原始存储字节的哈希
    lines: list[str]
    shapes: list[str]
    slots: list[TextSlot]
    trailing_terminator: bool
    unmatched_signatures: dict[str, int] = field(default_factory=dict)


def _policy_for(tag: str, tag_source: str) -> str:
    if tag_source == "unresolved":
        return "review-required"
    return D.POLICY_MAP[tag]


def parse_script(src_id: str, name: str, content: bytes,
                 stored_sha: str) -> ScriptIR:
    """把 .scr 内容解析成内存 IR。文本发现只走行形态声明，不做正则扫描全文。"""
    enc = D.SCRIPT["source_encoding"]
    term = D.SCRIPT["line_terminator"]
    text = content.decode(enc)  # 不设 errors 兜底（§4.4）
    parts = text.split(term)
    trailing = parts[-1] == ""
    lines = parts[:-1] if trailing else parts

    shapes: list[str] = []
    slots: list[TextSlot] = []
    counter = 0

    # 续行合并（EV_SHAPE_CONT）：continuation 形态不产生独立条目，而是并入
    # **紧邻上一物理行**的正文条目。prev_msg 记住上一行的 msg 槽位；只要中间
    # 隔了任何其他形态（含空行）就清空，故不会跨段误并（D_22.scr 的信件段落
    # 引号跨多段但各段之间有空行，实测不受影响）。
    # 片段之间以原始行终止符相连：导出时由占位符机制呈现为 {{0D}}{{0A}}（§4.5），
    # 回封时按同一终止符切回原物理行，故行结构逐字节复原。
    prev_msg: TextSlot | None = None

    for lineno, line in enumerate(lines):
        for shape_id, rx, decl in _SHAPES:
            m = rx.match(line)
            if not m:
                continue
            shapes.append(shape_id)
            group_slots: dict[str, TextSlot] = {}
            for slot_name, tag in decl["text_slots"].items():
                value = m.group(slot_name)
                if value is None or not value:
                    continue
                counter += 1
                subtype = _SUBTYPES.get((shape_id, slot_name))
                if subtype is None:
                    raise ParseError(
                        f"形态 {shape_id} 槽位 {slot_name} 未声明 subtype")
                ts = TextSlot(
                    idx=counter, lineno=lineno, shape_id=shape_id,
                    slot_name=slot_name, tag=tag, tag_subtype=subtype,
                    tag_source="structural", translate_policy=_policy_for(tag, "structural"),
                    source=value, col_start=m.start(slot_name), col_end=m.end(slot_name),
                )
                group_slots[slot_name] = ts
                slots.append(ts)
            # 人名绑定：同一行的两个槽位，method=slot-ordinal（§4.7）
            binding = decl.get("binding")
            if binding and binding["name_slot"] in group_slots and binding["msg_slot"] in group_slots:
                nm = group_slots[binding["name_slot"]]
                ms = group_slots[binding["msg_slot"]]
                ms.speaker = nm.source
                ms.pair_idx = nm.idx
                nm.pair_idx = ms.idx
            # call 形态的字符串参数
            if decl.get("arg_text_rule"):
                cmd = m.group("cmd")
                args = m.group("args")
                base = m.start("args")
                for ordinal, lit in enumerate(_STR_LIT.finditer(args)):
                    if not lit.group(1):
                        continue
                    rule = _ARG_RULES.get((cmd, ordinal))
                    counter += 1
                    if rule:
                        tag, subtype, policy = rule["tag"], rule["tag_subtype"], None
                    else:
                        tag, subtype, policy = "misc", D.FROZEN_STRING_ARG_SUBTYPE, "frozen"
                    # inner_regex：可见正文只是字面量的一部分（如「正文」＋对齐＋标记）。
                    # 槽位仅覆盖第 1 捕获组；括号与标记留在槽位外，回封时原样保留。
                    # 未命中时槽位取整串（11 条【…】を見る类）。
                    src = lit.group(1)
                    cs = base + lit.start(1)
                    ce = base + lit.end(1)
                    if rule:
                        inner = _INNER_RULES.get((cmd, ordinal))
                        if inner:
                            im = inner.search(src)
                            if im and im.group(1):
                                cs, ce = cs + im.start(1), cs + im.end(1)
                                src = im.group(1)
                    slots.append(TextSlot(
                        idx=counter, lineno=lineno, shape_id=shape_id,
                        slot_name=f"arg{ordinal}", tag=tag, tag_subtype=subtype,
                        tag_source="structural",
                        translate_policy=policy or _policy_for(tag, "structural"),
                        source=src, col_start=cs, col_end=ce,
                    ))
            # 续行合并：本行的 msg 并入紧邻上一行的正文条目，不作为独立条目。
            # 无可依附的上一行时不合并——此时它是自成一句的正文，照常导出。
            if decl.get("continuation") and "msg" in group_slots and prev_msg is not None:
                frag = group_slots["msg"]
                slots.remove(frag)
                counter -= 1
                if prev_msg.own_source is None:
                    prev_msg.own_source = prev_msg.source
                prev_msg.cont_spans.append(ContSpan(
                    lineno=frag.lineno, col_start=frag.col_start,
                    col_end=frag.col_end, source=frag.source,
                    shape_id=frag.shape_id))
                prev_msg.source += term + frag.source
                group_slots.pop("msg")
            # 维护续行的依附目标：仅紧邻的上一行有效，隔一行即失效
            prev_msg = group_slots.get("msg")
            break
        else:
            raise UnknownLineShape(name, lineno, line_signature(line))

    _mark_choice_aliases(slots, name)

    return ScriptIR(src_id=src_id, name=name, src_sha256=sha256(content),
                    stored_sha256=stored_sha, lines=lines, shapes=shapes,
                    slots=slots, trailing_terminator=trailing)


def _mark_choice_aliases(slots: list[TextSlot], name: str) -> None:
    """同文件内正文相同的 choice 槽位：首个（行序）为主条目，其余标 alias_of。

    依据（EV_SHAPE_CHOICE_BTN + 用户确认）：本作选项经 btnset 写入，DEBUG 分支与
    正常分支各写一份同一选项。正文相同 ⇒ 玩家可见文本相同 ⇒ 译文必须一致，
    归并为一条导出、多站点回填，从机制上杜绝翻译不统一。
    仅归并 choice（D.CHOICE_ALIAS["tags"]）；msg/name 不归并——同一正文在不同
    语境可能有不同译法，且 name 可能是多个角色的同一占位写法（如『？？？』）。
    主条目按行序取首个，判定确定且与导出顺序一致。
    """
    tags = set(D.CHOICE_ALIAS["tags"])
    primary: dict[str, int] = {}
    for s in slots:
        if s.tag not in tags:
            continue
        if s.source in primary:
            s.alias_of = primary[s.source]
        else:
            primary[s.source] = s.idx


def render_script(ir: ScriptIR, overrides: dict[int, str] | None = None) -> bytes:
    """从 IR 重建 .scr 内容。overrides 为 idx -> 新文本；空则逐字节还原。

    改写按 (lineno, col_start, col_end) 定位，同一行多槽位从右向左套用，
    使前面的列偏移不受影响（§6.3 按站点不按值）。

    别名站点（alias_of）：主条目的译文同时回填到全部别名站点——同文件内正文
    相同的选项槽位只导出一次，回封时逐站点按各自列区间套用，保证一致（用户
    确认的需求）。别名站点自身的 source 仍逐字校验，不符即拒绝。
    """
    ov = dict(overrides or {})
    # 展开别名：主条目译文 → 别名站点。逐层解析（本方言归并只有一层）。
    for s in ir.slots:
        if s.alias_of is not None and s.alias_of in ov and ov[s.alias_of] != s.source:
            ov.setdefault(s.idx, ov[s.alias_of])

    term = D.SCRIPT["line_terminator"]
    # 站点表：(lineno, col_start, col_end, 原文, 新文)。折行条目按行终止符切成
    # 各物理行的片段——片段数必须与原来一致，否则无法判断新的换行落在哪里。
    edits: dict[int, list[tuple[int, int, str, str, int]]] = {}
    for s in ir.slots:
        if s.idx not in ov or ov[s.idx] == s.source:
            continue
        new = ov[s.idx]
        if not s.cont_spans:
            edits.setdefault(s.lineno, []).append(
                (s.col_start, s.col_end, s.source, new, s.idx))
            continue
        parts = new.split(term)
        want = len(s.cont_spans) + 1
        if len(parts) != want:
            raise ParseError(
                f"{ir.name} idx={s.idx} 折行条目的换行数被改动："
                f"原有 {want - 1} 处换行，译文有 {len(parts) - 1} 处。"
                f"请保留原来的 \\n，数量与位置不变")
        assert s.own_source is not None
        edits.setdefault(s.lineno, []).append(
            (s.col_start, s.col_end, s.own_source, parts[0], s.idx))
        for span, piece in zip(s.cont_spans, parts[1:]):
            edits.setdefault(span.lineno, []).append(
                (span.col_start, span.col_end, span.source, piece, s.idx))

    out_lines = list(ir.lines)
    for lineno, group in edits.items():
        line = out_lines[lineno]
        for cs, ce, old, new, idx in sorted(group, key=lambda t: t[0], reverse=True):
            if line[cs:ce] != old:
                raise ParseError(
                    f"{ir.name}:{lineno} idx={idx} 站点内容与 IR 不符，拒绝改写")
            line = line[:cs] + new + line[ce:]
        out_lines[lineno] = line

    text = term.join(out_lines) + (term if ir.trailing_terminator else "")
    return text.encode(D.SCRIPT["target_encoding"])


def iter_scripts(arc: Archive) -> Iterator[tuple[ArcEntry, bytes]]:
    for e in arc.entries:
        yield e, entry_bytes(arc, e)
