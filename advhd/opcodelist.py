# -*- coding: utf-8 -*-
"""声明式方言：WillPlus / AdvHD `.ws2` 脚本字节码。

本文件是**唯一**允许出现引擎特定字面量的地方（SKILL.md §7）：opcode 数值、
操作数布局、加解密参数、编码、窗口常量全部集中在此，且每条带 evidence_refs
与 confidence。结构逻辑（disassembler / assembler）只读取这些声明，不含任何
魔数——该规则由 scripts/check_no_literals.py 机械校验。

证据台账见 vm_analysis.md。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 操作数原语。宽度即字节数；cstr 为 NUL 结尾变长串。
#
# 取自参考实现 Ws2/Reader.php：readWord=unpack('v')=2B 小端，
# readDWord=unpack('V')=4B 小端，readFloat=unpack('f')=4B，
# readString=NUL 结尾（长度含终止符）。证据 EV_READER_PRIMITIVES。
# ---------------------------------------------------------------------------
U8 = "u8"
U16 = "u16"
U32 = "u32"
F32 = "f32"
CSTR = "cstr"
PTR32 = "ptr32"        # 绝对文件偏移，参与重定位
BYTES = "bytes"        # (BYTES, n) 定长不透明字节

#: 指令流起始偏移。`.ws2` 无文件头，直接以 opcode 流开始（EV_NO_HEADER）。
CODE_START = 0

#: 目标引擎版本。取自 AdvHD.exe VS_VERSION_INFO FileVersion = 1.9.2.2
#: （EV_ENGINE_VERSION）。参考实现中多处 `version > X` 分支据此求值：
#: >1.06 成立、>1.4 成立、>2.1 **不**成立。
ENGINE_VERSION = 1.92

#: `updateMode` 仅在 version == 1.0 时改变行为，本作恒为假，故所有
#: `updateMode > 0 && version == 1.0` 分支均不适用（EV_UPDATE_MODE_NA）。
UPDATE_MODE = 0


def _sized(base: int, gates: list[tuple[float, int]]) -> int:
    """求值参考实现中的 `$size` 版本门。gates 为 (阈值, 增量) 列表。"""
    size = base
    for threshold, delta in gates:
        if ENGINE_VERSION > threshold:
            size += delta
    return size


# ---------------------------------------------------------------------------
# 字符串形态（L2 形态级差异，§7.1.1）
#
# 同一引擎的不同版本对**字符串编码**有两种形态，opcode 表与操作数布局完全相同，
# 只有「一个字符串占几字节、终止符几字节」不同：
#
#   sbcs   单字节编码（CP932），NUL 终止符 1 字节      —— 旧版语料
#   utf16  UTF-16LE，终止符 2 字节（0x0000）          —— 新版语料
#
# 判据为**结构性**的，不看文件名、不看目录（§7.1.2 禁止依据文件名选方言）：
# 以两种形态分别做全量顺序解析，恰好有一种能让指令流严丝合缝地覆盖整个文件。
#
# 双向实测（EV_STRING_SHAPE）：
#   新版 47 个文件：utf16 → 47/47 通过；sbcs → 45 个撞未定义 opcode
#   旧版 262 个文件：sbcs → 262/262 通过；utf16 → 218 个撞未定义 opcode
# 两个方向都验证过，因此该判据不是"挑一个能过的"，而是有反例支撑的鉴别式。
# ---------------------------------------------------------------------------
SHAPE_SBCS = "sbcs"
SHAPE_UTF16 = "utf16"

STRING_SHAPES = {
    SHAPE_SBCS: {
        "id": SHAPE_SBCS,
        "terminator_size": 1,
        "char_size": 1,
        #: 该形态下 source_encoding 为单字节/双字节混合的本地编码
        "encoding": "cp932",
        #: 译文默认写回 GBK：单字节形态下换用中文本地编码是常规做法
        "default_target": "gbk",
        "evidence_refs": ["EV_STRING_SHAPE", "EV_READER_PRIMITIVES"],
        "confidence": "observed",
    },
    SHAPE_UTF16: {
        "id": SHAPE_UTF16,
        "terminator_size": 2,
        "char_size": 2,
        "encoding": "utf-16-le",
        #: UTF-16 形态的译文**必须**仍是 UTF-16LE：终止符为双字节 0x0000，
        #: 换成单字节编码会让串长与终止符宽度不匹配，游戏读不出文本。
        #: 好处是 UTF-16 能表示任意字符，不存在 GBK 那类"无法表示"的问题。
        "default_target": "utf-16-le",
        #: 参考实现 ws2_decompile.php 在 version > 2 时置 encoding='utf16'，
        #: 走 FastBuffer::read2ByteString（双 NUL 终止）。
        "evidence_refs": ["EV_STRING_SHAPE", "EV_UTF16_MODE"],
        "confidence": "observed",
    },
}


DIALECT = {
    "schema_version": "1.0.0",
    "engine_id": "WILLPLUS_ADVHD",
    "dialect_id": "ADVHD_KOISOTTO",
    "endianness": "little",
    "code_start": CODE_START,
    "engine_version": ENGINE_VERSION,

    #: 不含任何字符串的文件用哪种形态都产出相同 IR，此时取该缺省值。
    #: 只在"两种形态都走通且字符串数为 0"时使用，不作为一般兜底。
    "default_string_shape": SHAPE_SBCS,

    # -----------------------------------------------------------------------
    # 封装层：整文件逐字节循环左移 2 位（解密）/ 右移 2 位（加密）。
    #
    # dec(b) = ((b << 6) | (b >> 2)) & 0xFF
    # enc(b) = ((b << 2) | (b >> 6)) & 0xFF
    #
    # 二者互为逆运算。证据 EV_CIPHER_ROT8：以 Rio.arc 内 263 条条目与已解密
    # 文本目录逐一比对，262 条 `.ws2` 全部满足 dec(arc) == plain 且
    # enc(plain) == arc（Pan.dat 为非 ws2 格式，明文存储，不参与）。
    # -----------------------------------------------------------------------
    # 以「循环左移多少位」直接声明，避免"左移/右移"命名歧义导致方向写反：
    #   解密 rol 6 == ((b << 6) | (b >> 2)) & 0xFF
    #   加密 rol 2 == ((b << 2) | (b >> 6)) & 0xFF
    # 两者互逆（6 + 2 == 8）。方向写反会使产物无法被游戏载入，故以
    # tests/test_ws2.py::test_cipher_matches_reference_expressions 双向锁定。
    "cipher": {
        "algorithm": "ROT8",
        "decrypt_rol": 6,
        "encrypt_rol": 2,
        "applies_to": "whole-file",
        "evidence_refs": ["EV_CIPHER_ROT8"],
        "confidence": "observed",
    },

    "encoding": {
        "source": "cp932",
        "target": "gbk",
        "text_file": "utf-8-sig",
        "asm": "utf-8",
        "evidence_refs": ["EV_ENCODING_CP932"],
        "confidence": "observed",
    },

    # -----------------------------------------------------------------------
    # 文本内控制码。这些是引擎标记而非可翻译内容，必须原样保留。
    # `%K%P` 为每条消息的收尾，`\n` 为换行（字面两字符，非转义），
    # `%LC` 为说话者名前缀。证据 EV_TEXT_CONTROL_CODES。
    # -----------------------------------------------------------------------
    "text_control_codes": ["%K%P", "%K", "%P", "%LC", "%LF", "\\n", "\\d"],

    # -----------------------------------------------------------------------
    # 文件终结符：0xFF + u32 + 4 字节 = 9 字节，恰止于 EOF。
    # 证据 EV_FILEEND：262 个文件 byte[-9] 全部为 0xFF。
    # -----------------------------------------------------------------------
    "file_end_opcode": 0xFF,

    "windows": [
        # 本方言不使用前瞻/扫描窗口：指令流为严格顺序解析，长度由 opcode 表
        # 直接给出，终止条件为结构性的（FileEnd 且 offset == EOF）。
        # 因此不存在 §1.6 所述的窗口截断风险，window_hits 恒为空。
    ],
}


# ---------------------------------------------------------------------------
# Opcode 表。
#
# 每条：mnemonic / operands / evidence_refs / confidence，可选 text_slots
# 与 pointer_slots。operands 为顺序列表，元素为原语名或 (BYTES, n)。
#
# 全部布局取自参考实现 DarthFly/advhd_ws2_tools 的 Ws2/Opcodes/*.php 中
# 各类的 decompile() 读取序列，并以本作 262 个样本的全量顺序解析交叉验证
# （EV_OPCODE_TABLE、EV_FULL_WALK）。
#
# text_slots：该 opcode 中承载**可翻译文本**的操作数下标（0 基，指 operands
# 内位置）。未列出的字符串槽为资源名/标识符，标 frozen。
# pointer_slots：承载绝对文件偏移的操作数下标，参与站点级重定位（§6.3）。
# ---------------------------------------------------------------------------
OPCODES: dict[int, dict] = {
    0x00: {"mnemonic": "Undefined", "operands": [],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    # Condition：首字节为比较类型；仅在该值属于特定集合时才有后续操作数。
    # 这是全表唯一的**子码相关变长**指令，规则见 CONDITION_EXTENDED_*。
    0x01: {"mnemonic": "Condition", "operands": "CONDITION",
           "pointer_slots": [3, 4],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_CONDITION_SUBCODE"],
           "confidence": "derived"},

    0x02: {"mnemonic": "Jump2", "operands": [PTR32], "pointer_slots": [0],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x04: {"mnemonic": "RunFile", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x05: {"mnemonic": "Unk05", "operands": [],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x06: {"mnemonic": "Jump", "operands": [PTR32], "pointer_slots": [0],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x07: {"mnemonic": "NextFile", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x08: {"mnemonic": "Unk08", "operands": [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x09: {"mnemonic": "LayerConfig", "operands": [(BYTES, 3), F32],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x0A: {"mnemonic": "Unk0A", "operands": [(BYTES, 22)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x0B: {"mnemonic": "SetFlag", "operands": [U16, (BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x0D: {"mnemonic": "Unk0D", "operands": [(BYTES, 8)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x0E: {"mnemonic": "Unk0E", "operands": [(BYTES, 5)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    # ShowChoice：选项数为首字节，每项 u16 id + 选项文本 + 4 字节 +
    # 依 op[3] 分支的跳转目标。选项文本可翻译。规则见 SHOWCHOICE_RULE。
    0x0F: {"mnemonic": "ShowChoice", "operands": "SHOWCHOICE",
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_SHOWCHOICE"],
           "confidence": "derived"},

    0x11: {"mnemonic": "SetTimer",
           "operands": [CSTR] + ([(BYTES, 1)] if ENGINE_VERSION > 1.4 else []) + [F32],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x12: {"mnemonic": "StartTimer",
           "operands": [CSTR, (BYTES, _sized(2, [(2.1, 1)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    # 参考实现声明 9 字节，在本作（script 1.9）为**零长度**：实测 37 个
    # *_ANIME_ERASE.ws2 的尾部自 0x13 至 EOF 恰为 10 字节，而其后的 FileEnd
    # 已占 9 字节。两个方向都验证过：长度 0 → 262/262 通过；长度 9 → 37 个失败。
    # 见 vm_analysis.md 的 EV_UNK13_ZERO_LENGTH。
    0x13: {"mnemonic": "Unk13", "operands": [],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_UNK13_ZERO_LENGTH"],
           "confidence": "observed"},

    # DisplayMessage：正文承载者。operands[1]=图层名（frozen），
    # operands[2]=消息正文（可翻译）。末尾类型字节仅 version>1.06 存在。
    0x14: {"mnemonic": "DisplayMessage",
           "operands": [U32, CSTR, CSTR]
                       + ([(BYTES, 1)] if ENGINE_VERSION > 1.06 else []),
           "text_slots": {2: "msg"},
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_MSG_LAYOUT"],
           "confidence": "observed"},

    # SetDisplayName：说话者名。内容形如 `%LC<名>`，前缀为引擎标记。
    0x15: {"mnemonic": "SetDisplayName",
           "operands": [CSTR] + ([(BYTES, 1)] if ENGINE_VERSION > 1.06 else []),
           "text_slots": {0: "name"},
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_NAME_LAYOUT"],
           "confidence": "observed"},

    0x16: {"mnemonic": "Unk16",
           "operands": [(BYTES, _sized(1, [(1.06, 1)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x17: {"mnemonic": "Unk17", "operands": [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    # AddMessageToLog：回想日志文本，可翻译。
    0x18: {"mnemonic": "AddMessageToLog", "operands": [(BYTES, 1), CSTR],
           "text_slots": {1: "msg"},
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    0x19: {"mnemonic": "Unk19",
           "operands": [(BYTES, _sized(0, [(1.4, 3), (2.1, 1)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x1A: {"mnemonic": "OpenTitle", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x1B: {"mnemonic": "Unk1B", "operands": [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x1C: {"mnemonic": "ExecuteFunction",
           "operands": [CSTR, CSTR, (BYTES, _sized(2, [(1.0, 1)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x1D: {"mnemonic": "Unk1D", "operands": [(BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x1E: {"mnemonic": "PlayMusic",
           "operands": [CSTR, CSTR, (BYTES, _sized(13, [(1.06, 4)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x1F: {"mnemonic": "StopMusic", "operands": [CSTR, F32],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x20: {"mnemonic": "MusicUnk1", "operands": [CSTR, F32, U16],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x28: {"mnemonic": "SoundEffect",
           "operands": [CSTR, CSTR, F32, F32, (BYTES, _sized(10, [(1.06, 4)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x29: {"mnemonic": "SoundUnk1", "operands": [CSTR, F32],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x2A: {"mnemonic": "SoundUnk2", "operands": [CSTR, F32, (BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x2E: {"mnemonic": "CharMessageStart", "operands": [],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x30: {"mnemonic": "SoundEffectUnk30", "operands": [CSTR, F32],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x32: {"mnemonic": "VariableUnk32", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x33: {"mnemonic": "SetBackground", "operands": [CSTR, CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x34: {"mnemonic": "UsePnaPackage", "operands": [CSTR, CSTR, (BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x35: {"mnemonic": "PlayMovie", "operands": [CSTR, CSTR, (BYTES, 3)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x36: {"mnemonic": "PrepareBackgroundArea",
           "operands": [CSTR, F32, F32, F32, F32, F32, F32, F32, (BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x37: {"mnemonic": "ClearLayer", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x38: {"mnemonic": "VariableUnk3", "operands": [CSTR, (BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    # DisplayCharacterImage：立绘合成。config[2] 为后续 u16 个数（变长）。
    0x39: {"mnemonic": "DisplayCharacterImage", "operands": "CHARIMAGE",
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_CHARIMAGE"],
           "confidence": "derived"},

    0x3A: {"mnemonic": "UnkBackground2", "operands": [CSTR, (BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    # BackgroundMessage：背景层文字，可翻译（operands[1]）。
    0x3B: {"mnemonic": "BackgroundMessage",
           "operands": [CSTR, CSTR, U16, U32] + [F32] * 8,
           "text_slots": {1: "msg"},
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    0x3D: {"mnemonic": "Unk3D", "operands": [(BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x3E: {"mnemonic": "Unk3E", "operands": [],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},

    # LayersList：首字节为个数，随后该数量个 cstr（图层名，frozen）。
    0x3F: {"mnemonic": "LayersList", "operands": "LAYERSLIST",
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_LAYERSLIST"],
           "confidence": "observed"},

    0x40: {"mnemonic": "SetMask", "operands": [CSTR, CSTR, (BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x41: {"mnemonic": "UnkBackground3", "operands": [CSTR, (BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x42: {"mnemonic": "Unk42", "operands": [CSTR, (BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x43: {"mnemonic": "Unk43", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x44: {"mnemonic": "Effect44", "operands": [CSTR, CSTR, (BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x45: {"mnemonic": "DragBackground",
           "operands": [CSTR, (BYTES, 2), F32, F32, F32, F32],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x46: {"mnemonic": "MoveBackground",
           "operands": [CSTR, (BYTES, 3), F32, F32, F32, F32],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x47: {"mnemonic": "Effect1",
           "operands": [CSTR, CSTR, (BYTES, 4)] + [F32] * 6 + [(BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x48: {"mnemonic": "Effect2",
           "operands": [CSTR, CSTR, (BYTES, _sized(5, [(2.1, 1)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x4A: {"mnemonic": "Unk4A", "operands": [CSTR, CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x51: {"mnemonic": "VariableUnk51", "operands": [CSTR, CSTR, (BYTES, 7)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x52: {"mnemonic": "VariableUnk2",
           "operands": [CSTR, CSTR, F32, (BYTES, 7), CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x53: {"mnemonic": "VariableUnk4", "operands": [CSTR, CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x56: {"mnemonic": "RainStart",
           "operands": [CSTR, (BYTES, 7)] + [F32] * 10 + [U32] * 5
                       + [CSTR, (BYTES, 2), CSTR, CSTR, (BYTES, 4)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x57: {"mnemonic": "UnkBackground1", "operands": [CSTR, (BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x58: {"mnemonic": "Effect3", "operands": [CSTR, CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x5B: {"mnemonic": "InitKeyName", "operands": [CSTR, U16, (BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x5C: {"mnemonic": "RainEnd", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x64: {"mnemonic": "Unk64", "operands": [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x65: {"mnemonic": "Unk65",
           "operands": [(BYTES, 3), F32, F32, (BYTES, _sized(2, [(2.1, 1)]))],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_ENGINE_VERSION"],
           "confidence": "derived"},
    0x66: {"mnemonic": "ShowGraphic", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x67: {"mnemonic": "Unk67",
           "operands": [(BYTES, 4)] + [F32] * 5 + [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x68: {"mnemonic": "Unk68", "operands": [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x6E: {"mnemonic": "SetVariable", "operands": [CSTR, CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x6F: {"mnemonic": "VariableUnk", "operands": [CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x73: {"mnemonic": "SetPnaFile", "operands": [CSTR, CSTR, (BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x75: {"mnemonic": "Unk75", "operands": [CSTR, CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x78: {"mnemonic": "Unk78", "operands": [CSTR, CSTR, (BYTES, 3)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x7A: {"mnemonic": "Unk7A", "operands": [CSTR, CSTR, F32, (BYTES, 3)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x7B: {"mnemonic": "Unk7B", "operands": [CSTR, CSTR],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x84: {"mnemonic": "Unk84",
           "operands": [CSTR, CSTR, CSTR, F32, (BYTES, 2), F32],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0x97: {"mnemonic": "Unk97", "operands": [(BYTES, 3)] + [F32] * 4,
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0xB0: {"mnemonic": "UnkB0", "operands": [CSTR, (BYTES, 4)] + [F32] * 4,
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0xE6: {"mnemonic": "ConditionalJump", "operands": [PTR32, PTR32],
           "pointer_slots": [0, 1],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0xF0: {"mnemonic": "UnkScreen", "operands": [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0xFB: {"mnemonic": "UnkFB", "operands": [(BYTES, 1)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0xFC: {"mnemonic": "UnkFC", "operands": [(BYTES, 2)],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0xFD: {"mnemonic": "UnkFD", "operands": [],
           "evidence_refs": ["EV_OPCODE_TABLE"], "confidence": "derived"},
    0xFF: {"mnemonic": "FileEnd", "operands": [U32, (BYTES, 4)],
           "evidence_refs": ["EV_OPCODE_TABLE", "EV_FILEEND"],
           "confidence": "observed"},
}


# ---------------------------------------------------------------------------
# 变长形态声明（§7.1.3）。四个 opcode 的长度依赖数据内容，判定与提取分离，
# 每个形态自带判定条件；无形态命中即失败，不回落（禁止返回空结果）。
# ---------------------------------------------------------------------------

#: Condition (0x01)：首字节 cfg 决定是否存在扩展操作数。
#: 参考实现条件为
#:   cfg ∈ {2,128,129,130,192}  或  (cfg == 3 且 下一字节 ∈ {50,51,127,128})
#: 扩展部分为 u16 + f32 + ptr32 + ptr32（两个跳转目标，0 表示无）。
CONDITION_EXTENDED_VALUES = frozenset({2, 128, 129, 130, 192})
CONDITION_CFG3_NEXT = frozenset({50, 51, 127, 128})
CONDITION_EXTENDED_OPERANDS = [U16, F32, PTR32, PTR32]

#: ShowChoice (0x0F) 的分支跳转类型。6 → 4 字节文件内偏移；7 → cstr 文件名。
SHOWCHOICE_JUMP_POINTER = 6
SHOWCHOICE_JUMP_FILENAME = 7

#: 承载可翻译文本的 opcode → {操作数下标: tag}。跨方言逻辑只读 tag。
TEXT_SLOTS: dict[int, dict[int, str]] = {
    code: spec["text_slots"]
    for code, spec in OPCODES.items() if "text_slots" in spec
}

#: 承载绝对文件偏移的 opcode → 操作数下标列表（重定位站点来源）。
POINTER_SLOTS: dict[int, list[int]] = {
    code: spec["pointer_slots"]
    for code, spec in OPCODES.items() if "pointer_slots" in spec
}

#: 说话者名前缀。`%LC` 之后为名字本体；前缀属引擎标记，不可改动。
NAME_PREFIXES = ("%LC", "%LF")

#: 可出现在正文**末尾**的引擎控制码。按声明顺序反复剥离，直到不再匹配，
#: 因此 `%K%P`、`%K`、`%P` 三种收尾都能被正确切分。
#:
#: 实测分布（262 个文件、30,568 条正文）：
#:   `%K%P` 30,562 条、`%P` 5 条（整条仅此标记，无正文）、`%K` 1 条。
#: 三种都存在，故**不得**假定收尾恒为 `%K%P` 后按定长切掉——那会把
#: `%K` 那一条的最后一个字符当成标记吃掉。
#:
#: `%XE` 是文字效果（震动/大字等）的**闭合**标记，与开头的 `%XS<n>` 配对。
#: 剥离顺序上它必须排在 `%K`/`%P` 之前被尝试，因为它位于二者内侧：
#: 实际形如 `%XS22「…」%XE%K%P`。
MESSAGE_SUFFIX_TOKENS = ("%K", "%P", "%XE")

#: 可出现在正文**开头**的引擎控制码（正则，需匹配可变数字参数）。
#: `%XS<n>` 为文字效果开始标记，n 为效果编号。
#:
#: 实测 11 条命中：`%XS20` ×2、`%XS22` ×5、`%XS23` ×4。其中 10 条有配对的
#: `%XE`，但 `T_ol_08.ws2` 的一条**只有 %XS20 而无 %XE**——因此剥离逻辑
#: 不得假定成对出现，前后缀各自独立判定。
MESSAGE_PREFIX_RE = r"%XS\d+"

#: 词缀（前缀 / 后缀）不进入双行文本：它们是引擎标记，不需要翻译，
#: 出现在译文里只会被误改或误删。词缀原样存在 IR 中，回封时重新拼回。
#: 不变式：`affix_prefix + body + affix_suffix == 原始文本`，逐条校验。
STRIP_AFFIXES = True

#: 文本内的**变量替换标记**，由引擎在运行时替换为实际值（如玩家输入的名字）。
#: 它们出现在正文中间，无法像词缀那样剥离，必须原样保留在译文里——写错或删掉
#: 会让游戏显示不出名字。导入时逐条校验其集合与个数不变（§4.9 第 11 条同理）。
#:
#: 实测新版语料 `<@FIRNAME>` 出现 415 次（其中 414 次作为说话者名）。
INLINE_VARIABLE_RE = r"<@[A-Z0-9_]+>"

#: 默认 translate_policy 映射（§4.3）。方言不覆盖默认值。
TRANSLATE_POLICY_BY_TAG = {
    "name": "translatable",
    "msg": "translatable",
    "choice": "translatable",
    "ui": "translatable",
    "system": "translatable",
    "ruby": "translatable",
    "label": "frozen",
    "misc": "review-required",
}
