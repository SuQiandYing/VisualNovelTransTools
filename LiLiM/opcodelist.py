# -*- coding: utf-8 -*-
"""LiLiM / Le.Chocolat AOS 方言声明（SKILL.md §7）。

纯数据，无控制流。结构逻辑在 disassembler.py / assembler.py，那里不得出现
本文件中的任何魔数、命令名或正则。每条声明带 evidence_refs 与 confidence，
证据台账见 vm_analysis.md。
"""

SCHEMA_VERSION = "1.0.0"
ENGINE_ID = "LILIM_AOS"
DIALECT_ID = "LILIM_AOS_SFA15"
TOOL_VERSION = "1.0.0"
IR_VERSION = "1"

# --- 容器层 ---------------------------------------------------------------
# AOSv2：头 0x111 字节，索引项 0x28 字节（名字 0x20 + 相对偏移 u32 + 大小 u32）。
CONTAINER = {
    "endianness": "little",
    "v2": {
        "signature": {"offset": 0, "width": 4, "kind": "i32", "equals": 0},
        "header": {
            "size": 0x111,
            "fields": [
                {"name": "base_offset", "offset": 4, "width": 4, "kind": "u32"},
                {"name": "index_size", "offset": 8, "width": 4, "kind": "i32"},
            ],
        },
        "index": {"offset": 0x111, "stride": 0x28},
        "entry": {
            "name": {"offset": 0x00, "width": 0x20, "terminator": "00"},
            "offset": {"offset": 0x20, "width": 4, "kind": "u32", "base": "base_offset"},
            "size": {"offset": 0x24, "width": 4, "kind": "u32"},
        },
        "evidence_refs": ["EV_AOSV2_INDEX"],
        "confidence": "derived",
    },
}

# 归档条目在索引顺序上首尾相接、无对齐填充、无校验字段。
# 该性质由 EV_AOSV2_CONTIGUOUS 证明（151 条目 0 缺口，末条目终点 == 文件长度），
# 是 assembler 得以重排布局的前提。
CONTAINER_LAYOUT = {
    "contiguous": True,
    "alignment": 1,
    "checksums": [],
    "evidence_refs": ["EV_AOSV2_CONTIGUOUS"],
    "confidence": "observed",
}

# --- 封装层：.scr 的 Huffman ------------------------------------------------
# 条目前 4 字节为解压后长度，其后是位流。位序 MSB-first；树以前序编码：
# 1 = 内部节点（左右子树紧随），0 = 叶（随后 8 位为字节值）。内部节点编号自 256 起。
TRANSFORMS = [
    {
        "id": "huffman_lilim",
        "algorithm": "HUFFMAN_PREORDER_TREE",
        "applies_to_extension": ".scr",
        "params": {
            "unpacked_size": {"offset": 0, "width": 4, "kind": "u32"},
            "payload_offset": 4,
            "bit_order": "msb_first",
            "tree": {"internal_marker": 1, "leaf_marker": 0, "leaf_value_bits": 8,
                     "first_internal_symbol": 256, "max_symbols": 512},
        },
        "reversible": True,
        "evidence_refs": ["EV_HUFFMAN_STREAM"],
        "confidence": "observed",
    },
]

# --- 脚本文本层 -----------------------------------------------------------
# .scr 解压后是 CP932 纯文本，CRLF 分行，末尾恒有一个空行（尾部 CRLF）。
SCRIPT = {
    "source_encoding": "cp932",
    "target_encoding": "cp932",
    "text_encoding": "utf-8",
    "asm_encoding": "utf-8",
    "line_terminator": "\r\n",
    "evidence_refs": ["EV_SCR_PLAINTEXT"],
    "confidence": "observed",
}

# 行形态：闭集，声明顺序即判定顺序（§7.1.3）。matches 为纯谓词（正则全匹配），
# 无形态命中时 disassembler 抛 UnknownLineShape，不得回落。
# text_slots 指出该形态中哪些捕获组是可翻译文本及其 tag。
LINE_SHAPES = [
    {"id": "blank", "match": r"^[ \t　]*$", "text_slots": {},
     "evidence_refs": ["EV_SHAPE_BLANK"], "confidence": "observed"},

    # 选项清单注释行（EV_SHAPE_CHOICE_LIST，用户确认需要提取）：
    # '#//①「正文」（好感度标记）' 是脚本作者维护的选项清单，正文与 btnset 一致
    # （58/66）或是无 btnset 文件里选项文本的唯一记录（8/66，如 03_03）。
    # 编号前缀（①-⑳/数字）与括号注记不属于正文，留在槽位外。
    # 判定顺序在 comment 之前；无编号的 '#//「…」' 是开发者注记（原台词参照、
    # 路由说明、说话者显示注记），保持 comment 不提取。
    {"id": "choice_listing",
     "match": r"^#[ \t]*//[ \t]*(?:[①-⑳]|[0-9]{1,2})[「『](?P<choice>[^」』]*)[」』]",
     "text_slots": {"choice": "choice"},
     "evidence_refs": ["EV_SHAPE_CHOICE_LIST"], "confidence": "derived"},

    {"id": "comment", "match": r"^[ \t]*#.*$", "text_slots": {},
     "evidence_refs": ["EV_SHAPE_COMMENT"], "confidence": "derived"},

    {"id": "label", "match": r"^[ \t]*::?[A-Za-z_0-9][^\s#]*[ \t]*(?:#.*)?$",
     "text_slots": {},
     "evidence_refs": ["EV_SHAPE_LABEL"], "confidence": "derived"},

    {"id": "directive", "match": r"^[ \t]*\^.*$", "text_slots": {},
     "evidence_refs": ["EV_SHAPE_DIRECTIVE"], "confidence": "derived"},

    {"id": "assign", "match": r"^[ \t]*%.*$", "text_slots": {},
     "evidence_refs": ["EV_SHAPE_ASSIGN"], "confidence": "derived"},

    {"id": "choice",
     "match": r"^(?P<indent>[ \t]*)/(?P<choice>[^/].*?)(?P<trail>/*)$",
     "text_slots": {"choice": "choice"},
     "evidence_refs": ["EV_SHAPE_CHOICE"], "confidence": "derived"},

    {"id": "vardecl", "match": r"^[ \t]*(?:var|global)\b.*$", "text_slots": {},
     "evidence_refs": ["EV_SHAPE_VARDECL"], "confidence": "derived"},

    {"id": "call",
     "match": r"^(?P<indent>[ \t]*)(?P<cmd>[A-Za-z_]\w*)[ \t]*\((?P<args>.*)\)"
              r"(?P<trail>[ \t]*(?:#.*)?)$",
     "text_slots": {},
     "arg_text_rule": "callee_string_args",
     "evidence_refs": ["EV_SHAPE_CALL"], "confidence": "derived"},

    {"id": "bare_cmd",
     "match": r"^(?P<indent>[ \t]*)(?P<cmd>[A-Za-z_]\w*)(?P<trail>[ \t]*(?:#.*)?)$",
     "text_slots": {},
     "evidence_refs": ["EV_SHAPE_BARE"], "confidence": "derived"},

    {"id": "dialogue",
     "match": r"^\[(?P<speaker>[^\]]*)\](?P<msg>.*)$",
     "text_slots": {"speaker": "name", "msg": "msg"},
     "binding": {"method": "slot-ordinal", "name_slot": "speaker", "msg_slot": "msg"},
     "evidence_refs": ["EV_SHAPE_DIALOGUE"], "confidence": "derived"},

    {"id": "narration",
     "match": r"^　(?P<msg>.*)$",
     "text_slots": {"msg": "msg"},
     "evidence_refs": ["EV_SHAPE_NARRATION"], "confidence": "derived"},

    # 本作新增形态（EV_SHAPE_QUOTED / EV_SHAPE_CONT / EV_SHAPE_CGLABEL）：
    # 引号起首的第三人称旁白（引用语直接开行，无说话者槽）。
    # 起首的 「/『 **属于正文**：与 dialogue 形态一致（其 msg 槽含完整的「」），
    # 否则译者看到的原文缺开引号，且译文无法自行补回（槽位外的字符不可改）。
    {"id": "quoted_narration",
     "match": r"^(?P<msg>[「『].*)$",
     "text_slots": {"msg": "msg"},
     "evidence_refs": ["EV_SHAPE_QUOTED"], "confidence": "derived"},

    # 对话折行的续行（kaomoji 表情、以非结构起首字符开行）。
    # 判定顺序最末：仅在前述形态全部未命中时才可能命中，不会吞噬其他形态。
    # continuation=True：本形态不产生独立条目，而是并入紧邻上一行的正文条目，
    # 使译者看到完整一句（EV_SHAPE_CONT）。行间的换行以占位符呈现，回封时
    # 按占位符切回原来的物理行，故行结构逐字节复原。
    {"id": "dialogue_cont",
     "match": r"^(?![\[　「『ｔ0-9A-Za-z_%#^:\s])(?P<msg>.+)$",
     "text_slots": {"msg": "msg"},
     "continuation": True,
     "evidence_refs": ["EV_SHAPE_CONT"], "confidence": "derived"},

    # 立绘 CG 标签：全角字母数字前缀（半宽化后与前一 chon() 资产 ID 一致）+ 表情注记。
    # 开发者索引行，非游戏可见文本 → misc / review-required（§4.2 角色未证明）。
    {"id": "cg_label",
     "match": r"^[０-９ａ-ｚＡ-Ｚ]+(?P<label>[^ \t\r\n]*)$",
     "text_slots": {"label": "misc"},
     "evidence_refs": ["EV_SHAPE_CGLABEL"], "confidence": "derived"},
]

# call 形态的字符串参数：绝大多数是资产 ID（在 grp.aos / cv.aos / bgm / se / movie
# 中存在同名条目，19,802 / 19,848 命中），因此默认 frozen。只有以下命令的指定序号
# 参数经证明是玩家可见文本。
# 序号按 _STR_LIT 枚举的**字符串字面量**序号计，不按原始参数位计。
# 本作 EV_SHAPE_CHOICE_BTN：btnset 的第 1 个字面量（第 0 个恒为窗口资源 ID）是
# 玩家可见的选项文本（192/192）。其中 181 条形如「选项正文」＋可选的全角空格对齐
# ＋好感度标记（トワ好感度○），仅「」内正文可翻译（用户确认）；「」外部分
# （括号、对齐、标记）不属于任何槽位，回封时原样保留。11 条无「」（【…】を見る）
# 整串可翻译。inner_regex 命中时槽位取第 1 捕获组，未命中时槽位取整串。
CALLEE_STRING_ARGS = [
    {"cmd": "title", "ordinal": 0, "tag": "ui", "tag_subtype": "window-title",
     "evidence_refs": ["EV_TITLE_ARG"], "confidence": "derived"},
    {"cmd": "btnset", "ordinal": 1, "tag": "choice", "tag_subtype": "choice-option",
     "inner_regex": r"「([^」]*)」",
     "evidence_refs": ["EV_SHAPE_CHOICE_BTN"], "confidence": "derived"},
]

# 其余命令的字符串参数一律 frozen，并记 subtype 便于审计。
FROZEN_STRING_ARG_SUBTYPE = "asset-id"

# 占位符阈值（§4.5）：码位低于此值的字符不可直接显示，以 {{XX}} 呈现。
# 取 CP932 的首个可打印码位；斜杠、全角空格等均在此之上，故不被转义。
PLACEHOLDER = {
    "display_min_codepoint": 0x20,
    "evidence_refs": ["EV_SCR_PLAINTEXT"],
    "confidence": "derived",
}

# tag_subtype 取值集合（§4.2：核心逻辑只读 tag，不读 subtype）。
TAG_SUBTYPES = [
    "dialogue-body", "narration-body", "speaker-name",
    "choice-option", "window-title", "asset-id",
    "quoted-narration-body", "dialogue-continuation", "cg-label",
]

# 默认 translate_policy 映射（§4.3）。
POLICY_MAP = {
    "name": "translatable",
    "msg": "translatable",
    "choice": "translatable",
    "ui": "translatable",
    "label": "frozen",
    "system": "translatable",
    "ruby": "translatable",
    "misc": "review-required",
}

# 窗口常量（§1.6）。本方言的解析全部由结构终止条件驱动（行终止符、括号配对、
# 索引项计数），无扫描窗口；此处显式记零以便报告可核对。
WINDOWS = []

# 归档级重定位站点：索引项中的 offset/size 字段。文本变长后条目大小改变，
# 必须按站点回填这两个字段（§6.3），不得按值搜索替换。
JOIN_SITES = {
    "kind": "container-index-slot",
    "key_kind": "entry_offset",
    "site_width": 4,
    "site_endianness": "little",
    "slots": ["offset", "size"],
    "evidence_refs": ["EV_AOSV2_INDEX"],
    "confidence": "derived",
}

# 申报的理解深度（§1.2）。脚本层为 CP932 明文行序列，行形态穷举且往返一致，
# 但未逆向宿主 sfa15.exe 的命令分发表，故不申报指令级语义。
DECODE_TIER = {
    "container": "T2",
    "script": "T2",
    "evidence_refs": ["EV_AOSV2_INDEX", "EV_SCR_PLAINTEXT", "EV_SHAPE_EXHAUSTIVE"],
}

# 形态判定版本。LINE_SHAPES 与 CALLEE_STRING_ARGS 随作品扩容时递增，
# 供报告与 vm_analysis 交叉核对（§7.1.5：新增形态须与既有版本可区分）。
SHAPE_SET_VERSION = "2"

# 继承形态（§7.1 同引擎方言家族）：本方言家族内某一作未出现、其他作实际使用的行形态。
# 键 = LINE_SHAPES 的 id，值 = 证据指引（写入 shapes.json，供门禁降级为 advisory）。
# choice：行式「/选项」在本作 0 命中（本作由 btnset 第 1 字面量承载，见
# EV_SHAPE_CHOICE_BTN）；在兄弟语料 あい☆きゃん中 112 行命中（其 EV_SHAPE_CHOICE）。
# quoted_narration / dialogue_cont / cg_label：本作（恋キセ）实测命中，兄弟语料 0 命中。
INHERITED_SHAPES = {
    "choice": "兄弟语料 D:/あい☆きゃんDL/scr/scr.aos 112 行命中"
              "（本作由 btnset 第 1 字面量承载，见 EV_SHAPE_CHOICE_BTN）",
    "choice_listing": "本作 66 行命中（EV_SHAPE_CHOICE_LIST）；"
                      "兄弟语料无该形态（其选项为行式「/选项」）",
    "quoted_narration": "本作 145 行命中（EV_SHAPE_QUOTED）；兄弟语料 0 行",
    "dialogue_cont": "本作 1 行命中（EV_SHAPE_CONT）；兄弟语料 0 行",
    "cg_label": "本作 1,456 行命中（EV_SHAPE_CGLABEL）；兄弟语料 0 行",
}

# 选项别名归并（用户确认的需求）：同一脚本内正文相同的 choice 槽位（DEBUG 分支与
# 正常分支各写一份 btnset）只导出一次，回封时回填全部站点。alias_scope 指明归并范围；
# alias_exempt 列出不参与归并的命令（title 等 UI 参数不在选项语义内，保持逐条导出）。
CHOICE_ALIAS = {
    "tags": ["choice"],
    "scope": "per-file",
    "evidence_refs": ["EV_SHAPE_CHOICE_BTN"],
    "confidence": "derived",
}
