# WillPlus / AdvHD `.ws2` 逆向分析与证据台账

本文件是 `opcodelist.py` / `disassembler.py` / `assembler.py` / `run_gui.py`
共同的唯一真值源。每个方言数值在此登记来源、交叉验证与反例检查。

- 样本作品：`恋はそっと咲く花のように`（ensemble，2021）
- 宿主：`AdvHD.exe`，`FileVersion = 1.9.2.2`
- 语料 A（旧版）：`文本/*.ws2` 共 262 个文件，5,508,130 字节（已解密）
- 语料 B（新版）：`新版文本/*.ws2` 共 9 个文件，381 KB（已解密），
  字符串为 **UTF-16LE**，见 §3.2
- 原始归档：`Rio.arc`，263 条条目（262 个 `.ws2` + 1 个 `Pan.dat`）

---

## 1. 申报

| 项目 | 值 |
|---|---|
| `analysis_mode` | `bytecode-disasm` |
| `declared_tier` | **T3** `instruction-stream` |
| `unpack_mode` | `not-required`（文本内嵌于脚本，脚本已由外部解密置于 `文本/`） |
| `text_source` | `embedded` |
| `repack_strategy` | `identity` / `in_place` / `pointer-rewrite` |
| `dialect_id` | `ADVHD_KOISOTTO` |

T3 依据：262 个文件全部完成**完整指令边界切分**，指令逐条首尾相接、
无缝无重叠、恰好覆盖 `[0, file_size)`，且末条指令为 `FileEnd` 并精确止于 EOF
（EV_FULL_WALK）。`tier_blocked` 为空。

未申报 T4：未构建基本块与调用图。跳转目标已解析为标签并参与重定位，
但可达性分析与栈效应未做，故不宣称 `semantic-cfg`。

---

## 2. 体系结构

- 字节码为**顺序指令流**，无文件头（EV_NO_HEADER）：偏移 0 即第一条指令的
  opcode 字节。
- 指令编码：`opcode:u8` + 依 opcode 表确定的操作数序列。**变长**，长度由
  操作数布局决定，而非指令内的长度字段。
- 字节序：小端（`u16`=`<H`，`u32`=`<I`，`f32`=`<f`）。
- 字符串：NUL 结尾变长，编码 CP932；长度含终止符。
- 无对齐要求：指令紧密排列，无 padding。
- 跳转目标为**绝对文件偏移**（自解密后文件起始计），非相对偏移。

### 2.1 EV_NO_HEADER — 无文件头

- 证据等级：`observed`
- 来源：262 个文件从偏移 0 起按 opcode 表顺序解析，全部成功且恰好止于 EOF。
  若存在头部，首字节将无法作为合法 opcode 解释或末尾会出现剩余字节。
- 交叉验证：首字节分布为 `0x16`×177、`0x38`×37、`0x01`×22、`0x1F`×6、
  `0x28`×5、`0x64`×5、`0x09`×3、`0x05`×3 等，全部属于已定义 opcode 集合，
  无统一魔数——与"无头部"一致，与"有固定头部"矛盾。
- 反例检查：不存在以非法 opcode 开头的文件。

### 2.2 EV_READER_PRIMITIVES — 原语宽度与字节序

- 证据等级：`derived`
- 来源：参考实现 `DarthFly/advhd_ws2_tools` 的 `Ws2/Reader.php`：
  `readWord = unpack('v')`（2 字节小端无符号）、
  `readDWord = unpack('V')`（4 字节小端无符号）、
  `readFloat = unpack('f')`（4 字节）、
  `readString` 为 NUL 结尾且返回长度含终止符。
- 交叉验证：以这些宽度对全部 262 个文件做顺序解析，逐字节严丝合缝
  （EV_FULL_WALK）。任一宽度取错都会立即导致错位并在数千处产生非法 opcode。

---

## 3. 封装层

### EV_CIPHER_ROT8 — 整文件循环位移

- 证据等级：`observed`
- 算法：逐字节循环移位，**无密钥、无位置依赖**。

```text
解密  dec(b) = ((b << 6) | (b >> 2)) & 0xFF     # 循环左移 2 位
加密  enc(b) = ((b << 2) | (b >> 6)) & 0xFF     # 循环右移 2 位
```

- 来源：现场脚本 `文本/RioScriptTool.py` 的 `CryptoWorker.process_file`
  给出上述两式，用户确认为本作加解密逻辑。
- 交叉验证（决定性）：解析 `Rio.arc` 索引得 263 条条目，逐条取出存储字节并
  施加 `dec`，与 `文本/` 下同名文件比对：
  - **262 个 `.ws2` 全部 `dec(arc) == plain` 成立**，且
    `enc(plain) == arc` 逐字节还原，证明二者互逆。
  - `Pan.dat` 不成立——该条目**明文存储**（`enc == plain`，首四字节为
    `PAN2`），属另一格式，不参与 ws2 流程。
- 反例检查：`Rio/co01_01.ws2`（游戏根目录下的散件覆盖文件）大小 12,733，
  而 `文本/co01_01.ws2` 为 12,701，两者非同一版本，**不可用作校验对**。
  已改用 `Rio.arc` 内条目作为真值来源。
- 结论：`identity` 回封时必须以 `enc` 重新加密（用户明确要求：最终回封产物
  必须为加密脚本）。明文与加密产物分开命名并共存（§6.5 / SKILL.md）。

### EV_STRING_SHAPE / EV_UTF16_MODE — 两种字符串形态（L2 形态级差异）

- 证据等级：`observed`
- 现象：新版语料的 opcode 序列与操作数布局与旧版**完全相同**，唯一差别是
  字符串编码：

```text
sbcs   单字节（CP932），NUL 终止符 1 字节        旧版 262 个文件
utf16  UTF-16LE，终止符 2 字节（0x00 0x00）      新版 9 个文件
```

  例：`bg01_DELETE_KEY` 在旧版为 `62 67 30 31 …` + `00`，
  在新版为 `62 00 67 00 30 00 31 00 …` + `00 00`。

- 来源：参考实现 `ws2_decompile.php` 在 `version > 2` 时置
  `encoding='utf16'`，字符串改走 `FastBuffer::read2ByteString()`（双 NUL
  终止）。本作两批语料分别对应两种模式。
- 判定方式：**结构性判定，不看文件名、不看目录**（§7.1.2）。以两种形态分别做
  全量顺序解析，取唯一能让指令流恰好覆盖整个文件的那个。
- 双向对照（两个方向都测过，故非"挑一个能过的"）：

```text
新版 47/9 个文件：utf16 → 全部通过；sbcs → 45 个撞未定义 opcode
旧版 262 个文件：sbcs → 全部通过；utf16 → 218 个撞未定义 opcode
```

- **纯控制流文件的两解性**：`Init.ws2` / `FlagInit.ws2` / `ClearCheck.ws2`
  不含任何字符串操作数，两种形态产出完全相同的指令流与 IR，故两者皆可。
  这不是真歧义（选哪个都不影响任何字节），实现中仅在「两种形态都走通**且**
  字符串数为 0」时取缺省形态；含字符串却仍多解则拒绝并要求收窄判据。
- 回封约束：UTF-16 形态的**译文必须仍写 UTF-16LE**。终止符为双字节，换成
  单字节编码会使串长与终止符宽度不匹配，游戏读不出文本。附带好处是 UTF-16
  可表示任意字符，不存在 GBK 那类「无法表示」的问题。
- 跨版本回归（§7.1.5）：新增 utf16 形态后，旧版语料产出条数**完全不变**
  （msg 30,563 / name 18,216 / choice 5），零编辑往返仍逐字节一致，
  且 262 个加密产物与 `Rio.arc` 仍逐字节相同。

### 3.2 Rio.arc 归档布局（仅用于取证，非本工具交付范围）

```text
u32 entry_count
u32 unknown
entry_count × { u32 size; u32 offset; UTF-16LE 文件名, 以 0x0000 结尾 }
数据区基址 = 索引结束偏移；条目数据位于 base + offset
```

验证：263 条条目的 `base + offset + size` 末条恰等于 5,518,579 = 文件总长。

---

## 4. Opcode 字典

完整表见 `opcodelist.py` 的 `OPCODES`，共 **87** 个 opcode。

### EV_OPCODE_TABLE — 操作数布局来源

- 证据等级：`derived`
- 来源：参考实现 `Ws2/Opcodes/*.php` 共 91 个类，其中 87 个声明
  `const OPCODE`（4 个为抽象基类）。每个类的 `decompile()` 方法给出该 opcode
  的**有序读取序列**，即操作数布局。无重复 opcode。
  继承型布局：
  - `AbstractUndefined` → 读 `getSize()` 个不透明字节
  - `AbstractNullByteText` → 读 1 个 NUL 结尾串
- 交叉验证：见 EV_FULL_WALK。
- 未决：`Unk**` 类名表示参考实现未确定其语义。**这不影响 T3**——指令边界
  与长度已确定，语义未知的操作数按不透明字节原样保留。

### EV_FULL_WALK — 全语料指令流验证（本方言最强证据）

- 证据等级：`observed`
- 方法：以 `opcodelist.py` 对 262 个文件逐一做严格顺序解析，规则为
  「遇未定义 opcode / 越界 / 未终止字符串即失败并报出偏移」，**不允许跳过或
  猜测**。
- 结果：**262 / 262 全部通过**，共切分 **287,776** 条指令；每个文件的指令
  首尾相接（`instr[k].start == instr[k-1].end`）、末条为 `FileEnd`
  且 `end == file_size`。
- 意义：这是一个极强的自洽约束。任何一处长度取错都会使后续解析错位，
  在数十万条指令中几乎必然撞上非法 opcode 或越界；全量通过因此同时验证了
  表中每个被用到的 opcode 的长度。
- 覆盖情况：262 个文件实际使用 **55** 个 opcode；表中另 32 个在本作未出现，
  按声明保留（供同引擎其他作品复用），并在形态报告中如实标记为未命中。

### EV_ENGINE_VERSION — 脚本版本 1.9

- 证据等级：`observed`
- 来源：`AdvHD.exe` 的 VS_VERSION_INFO `FileVersion = 1.9.2.2`。
- 交叉验证：参考实现 `VERSIONS.md` 将 exe `1.9.x` 一律对应
  **Script Version 1.9**（含 2019–2023 年多部作品），其 `ws2_decompile.php`
  默认值亦为 `1.9`。
- 推论（决定若干 opcode 的操作数宽度）：

```text
version > 1.06   成立   → 0x14 尾部 +1 字节、0x15 尾部 +1、0x16 宽度 2
                          0x1E +4、0x28 +4
version > 1.4    成立   → 0x11 多读 1 字节、0x19 宽度 3
version > 2.1    不成立 → 0x12 宽度 2、0x48 宽度 5、0x65 尾部 2、0x19 不再 +1
version == 1.0   不成立 → 全部 updateMode 补偿分支均不适用
```

- 独立验证：`0x14` 的末尾类型字节在全语料 30,563 处**取值恒为 0**，与
  「该字节存在且为类型标志」一致；若该字节实际不存在，则解析会自 0x14 之后
  整体错位一字节，而 EV_FULL_WALK 不会通过。

### EV_UNK13_ZERO_LENGTH — 对参考实现的一处修正

- 证据等级：`observed`
- 现象：参考实现 `Unk13::getSize()` 返回 **9**，即 `0x13` 占 1+9=10 字节。
  按此解析，37 个 `*_ANIME_ERASE.ws2` 全部失败。
- 判定：这 37 个文件的尾部固定为 `… KEY\0 | 13 | FF 00000000 00000000`，
  自 `0x13` 至 EOF 恰为 **10** 字节；而 `FileEnd`（`0xFF` + u32 + 4 字节）
  已占 9 字节，故 `0x13` 只能占 **1** 字节，即零操作数。
- 决定性对照（两个方向都测，避免只挑通过的那个）：

```text
0x13 长度 = 0  →  262 / 262 解析成功
0x13 长度 = 9  →  225 成功，37 个 NO_FILEEND 失败
```

- 反例检查：`0x13` 在本语料中仅出现 37 次，全部位于 `FileEnd` 之前该位置，
  无其他上下文，故不存在「另一处需要 9 字节」的反证。
- 结论：本作（script 1.9）中 `0x13` 为零长度。已在 `opcodelist.py` 中按
  实测值声明，并在此登记与参考实现的差异。**未修改参考实现的其他条目**。
- 未决：该差异可能是版本相关（参考实现的 9 或许适用于某个更早/更晚版本），
  本台账不作跨版本推断。

---

## 5. 变长形态（§7.1.3）

四个 opcode 的长度依赖数据内容。判定条件为纯谓词，与提取分离；无形态命中
即抛错，**不返回空结果**。

### EV_CONDITION_SUBCODE — `0x01` Condition

- 证据等级：`derived`
- 首字节 `cfg` 决定是否存在扩展操作数：

```text
extended  ⟺  cfg ∈ {2, 128, 129, 130, 192}
             或  (cfg == 3  且  下一字节 ∈ {50, 51, 127, 128})
extended 为真   → 追加 u16 + f32 + ptr32 + ptr32
extended 为假   → 无追加操作数（仅 opcode + cfg 共 2 字节）
```

- 来源：参考实现 `Condition::decompile()` 的分支条件，逐值照抄。
- 交叉验证：EV_FULL_WALK 通过。若该谓词取错，`0x01` 之后会立即错位 14 字节。
- 两个 `ptr32` 为真/假分支的跳转目标；值为 0 表示"无目标"，不登记为站点。

### EV_SHOWCHOICE — `0x0F` ShowChoice（选项文本承载者）

```text
count : u8
重复 count 次:
    choice_id : u16
    text      : cstr          ← 可翻译（tag=choice）
    op0..op2  : u8 ×3
    jump_type : u8
    if jump_type == 6 : target : u32    ← 文件内绝对偏移，登记为重定位站点
    if jump_type == 7 : target : cstr   ← 目标文件名，非偏移
    其他值           : 抛错（不猜测）
```

- 证据等级：`derived`，来源同上。
- 本语料中共 5 条 choice 文本；数量少是因为本作分支极少，非提取失配——
  已用形态命中数与 `ShowChoice` 指令数交叉核对（见形态报告）。

### EV_LAYERSLIST — `0x3F` LayersList

```text
count : u8
count × cstr        ← 图层名，资源标识符，frozen
```

- 证据等级：`observed`
- 独立验证：`LAYER_ORDER.ws2` 全长 218 字节，解析为
  `0x3F` + count=40 + 40 个图层名（`dds`/`ev01`/`bg01`/`st01`…`text03`）
  + `FileEnd`，恰好 218 字节。计数与字符串条数精确吻合。

### EV_CHARIMAGE — `0x39` DisplayCharacterImage

```text
channel : cstr
config  : u8 ×3
config[2] × u16      ← 立绘部件 ID 个数由 config[2] 给出
```

- 证据等级：`derived`，来源为 `DisplayCharacterImage::decompile()` 的
  `for ($i=0; $i<$config[2]; $i++)`。
- 交叉验证：EV_FULL_WALK 通过。

---

## 6. 文本与人名绑定

### EV_MSG_LAYOUT — `0x14` DisplayMessage（正文）

```text
0x14 | msg_id:u32 | layer:cstr | text:cstr | type:u8      (type 仅 version>1.06)
                     ↑ frozen     ↑ 可翻译 tag=msg
```

- 证据等级：`observed`
- 交叉验证：全语料 30,568 条 `0x14`；其中 30,563 条的 `layer` 恒为 `"char"`，
  `text` 以 `%K%P` 结尾。`%K%P` 全语料出现 30,562 次，与条数一致。
- `msg_id` 为阅读进度标记，自 0 递增；实测 `yoko_20.ws2` 有 17 条、
  最大 id 16，与条数吻合。
- `type` 字节全语料恒为 0。

### EV_NAME_LAYOUT — `0x15` SetDisplayName（说话者名）

```text
0x15 | name:cstr | cfg:u8         (cfg 仅 version>1.06)
        ↑ 形如 "%LC<名>"，%LC 为引擎前缀，不可改
```

- 证据等级：`observed`
- 交叉验证：全语料 `0x15` 共 **61,130** 条，其 `name` 槽只有两种形态：
  - `%LC` + 名字：**18,216** 条（与全语料 `%LC` 计数 18,216 精确相等）
  - **空串**：42,914 条 → 表示旁白 / 内心独白（无说话者）
  - 其他形态：**0 条**
- **空串不导出为可翻译条目**：它不含任何可翻译内容，导出会产生四万余条
  空条目淹没译文文件。该判定为结构性的（长度为 0），非启发式。
- 反例检查：不存在 `%LF` 前缀条目（本作为 0），故 `%LF` 虽在方言中声明，
  在本作形态报告中如实标记为未命中。

### EV_NAME_BINDING — 人名绑定（`method = slot-ordinal`）

- 证据等级：`derived`
- 规则：`0x15` 与其**紧邻的下一条** `0x14` 构成一对。这不是"物理相邻猜测"
  （`adjacency`），而是引擎的调用序约束：`SetDisplayName` 设置当前说话者，
  随后的 `DisplayMessage` 使用它。
- 交叉验证：全语料 30,568 条 `0x14` 中，**30,563 条**的前一条指令为 `0x15`
  （占 99.98%），仅 5 条为孤立正文（`msg_orphan`）。
- 歧义处理：孤立的 5 条 `speaker` 记为空，不猜测；不存在"一条 msg 对应多个
  name 候选"的情形（前驱唯一），故无 `ambiguous`。

### EV_ENCODING_CP932 — 编码

- 证据等级：`observed`
- 原文编码 CP932（Shift-JIS）：正文与人名字节以 CP932 严格解码成功
  （核心路径不使用 `errors='replace'`/`surrogateescape`）。
- 不可解码字节按 §4.4 处理：标 `parse_status=undecodable`、保留原始字节、
  强制 `frozen`、以占位符呈现。本语料实测无此类条目。

### EV_TEXT_CONTROL_CODES — 文本内控制码

- 证据等级：`observed`
- 全语料计数：`%K%P` 30,562、`\n`（字面反斜杠 + n，两个字符）20,022、
  `%LC` 18,216、`%LF` 0、`\d` 0。
- 这些是引擎标记，**不是可翻译内容**，回封时必须原样保留。
  `\n` 按 SKILL.md §4.5 处理：反斜杠不是转义前缀，按字面保留，
  **不得**转成 `{{5C}}` 之类占位符。

#### 词缀剥离：控制码不进双行文本

引擎标记不需要翻译，出现在译文文件里只会被误改或误删，因此在导出时从正文
两端剥离，存入 `TextEntry.affix_prefix` / `affix_suffix`，回封时原样拼回。
不变式 `affix_prefix + source + affix_suffix == 完整原文` 逐条校验
（`AFFIX_SPLIT_LOSSY`），因此剥离不损失任何字节。

| 标记 | 位置 | 含义 | 实测计数 |
|---|---|---|---|
| `%LC` | 人名前缀 | 说话者名标记 | 旧 18,216 / 新 1,038 |
| `%K%P` | 正文末尾 | 等待按键 + 翻页 | 30,562 |
| `%K` | 正文末尾 | 仅等待按键 | 1 |
| `%P` | 正文末尾 | 仅翻页 | 5（整条只有该标记） |
| `%XS<n>` | 正文开头 | 文字效果开始（n 为效果编号） | 11 |
| `%XE` | 正文末尾 | 文字效果结束 | 10 |

三处必须按实测形态处理，不能想当然：

1. **后缀按 token 反复剥离，不按定长切除。** 三种收尾（`%K%P` / `%K` / `%P`）
   同时存在；假定恒为 `%K%P` 后切掉 4 个字符，会把 `%K` 那一条的最后一个
   正文字符吃掉。
2. **`%XS<n>` 与 `%XE` 各自独立判定，不假定成对。** 10 条成对，但
   `T_ol_08.ws2` 有一条只有 `%XS20` 而无 `%XE`；按成对处理该条会漏剥。
3. **整条只有标记时不产出条目。** 5 条 `%P` 剥离后正文为空，导出会给译者
   五条无意义的空条目。词缀仍在原字节中，回封时原样写回。

导出后全语料正文中的 `%XX` 残留数为 **0**，以
`test_no_percent_codes_left_in_any_body` 在两批语料上断言。

### EV_INLINE_VARIABLE — 文本内变量替换标记

- 证据等级：`observed`
- 新版语料的正文与人名中存在 `<@FIRNAME>`（共 415 次，其中 414 次作为说话者
  名），由引擎在运行时替换为玩家输入的名字。
- 它位于正文**中间**，无法像词缀那样剥离，必须原样保留在译文里。删掉或写错
  会让游戏显示不出名字，而该错误**不会被长度或编码检查发现**——只能显式比对
  标记集合与个数，见导入校验的 `INLINE_VARIABLE_BROKEN`。

---

## 7. 跳转与重定位

### EV_POINTER_SITES — 绝对偏移站点

- 证据等级：`derived`
- 承载绝对文件偏移的操作数（`opcodelist.POINTER_SLOTS`）：

| opcode | 助记符 | 站点 |
|---|---|---|
| `0x01` | `Condition` | 扩展形态的第 3、4 操作数（真/假分支） |
| `0x02` | `Jump2` | 唯一操作数 |
| `0x06` | `Jump` | 唯一操作数 |
| `0x0F` | `ShowChoice` | `jump_type == 6` 的每个选项目标 |
| `0xE6` | `ConditionalJump` | 两个操作数 |

- 宽度 4 字节，小端，基准为**解密后文件起始**（绝对偏移，非相对）。
- 值 0 表示"无目标"，不登记为站点、不参与重定位。
- 站点集合来自**指令流解析**（每个站点带 `join_id` 与所属指令偏移），
  不来自任何字节扫描——满足 SKILL.md §3 的引用连接要求与 §6.3 的
  「按站点，不按值」。
- 独立验证（`EVRET.ws2`，53 字节，逐条列出）：

```text
0x00  Condition(cfg=2)  → 目标 0x1C, 0x2C   ← 两者均落在下方指令首字节
0x10  NextFile "TITLE"
0x17  Jump2             → 目标 0x2C
0x1C  LayerConfig
0x24  NextFile "NMSSCN"
0x2C  FileEnd                                ← 恰止于 EOF (53)
```

  三个非零跳转目标 `0x1C` / `0x2C` **全部精确落在指令边界上**，且 `0x2C`
  正是 `FileEnd` 的起始。若偏移基准或宽度取错，目标将落在指令中部。
  该性质已在全语料上作为回封后的站点同构校验项。

- `preserved_value_collisions`：站点集合之外、其值恰等于某旧偏移的字
  （常量、坐标、浮点位型等）一律 `preserve`。实测此类碰撞数不为零
  （例如 `yoko_20.ws2` 中值 101、2560、49 等重复出现于非站点位置），
  正是 §6.3 所述必须避免按值改写的情形。

---

## 8. 已知风险与未决事项

1. **跨样本验证已做，但仅限同一作品的两个版本**（SKILL.md §0.3）：
   已在两批形态分布不同的语料上验证（旧版 262 个 sbcs 文件、新版 9 个 utf16
   文件），二者的字符串形态分布完全不同，满足「两个来源且签名分布不同」。
   但同引擎**其他作品**（尤其 script 版本 1.06 / 1.4 / 2.11）未取得样本，
   `opcodelist.py` 中 `>1.06` / `>1.4` / `>2.1` 各版本门虽已按参考实现声明，
   除 1.9 之外**均未经实测**。列为已知风险，不宣称跨作品可用。
2. 表中 32 个 opcode 在本作未被命中，其布局仅有参考实现单一来源，
   未经本语料交叉验证，置信度为 `derived` 而非 `observed`。
3. `Unk**` 系列语义未知；本工具不解释其操作数，按不透明字节保留。
   这不影响往返一致性与文本回封。
4. `EV_UNK13_ZERO_LENGTH` 与参考实现存在差异，可能为版本相关，未作推断。
5. 未申报 T4：无基本块 / 调用图 / 可达性分析，因此**不支持**指令插删与
   控制流改写。`full-layout` 策略在本方言中一律 `applicable=false`
   （`reason_code = TIER_TOO_LOW`）。
