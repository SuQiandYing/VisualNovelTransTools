# ToolForYuris / YU-RIS YPF Python GUI v10

v10 目标：按 ArcYPF/GARbro 的 YPF 解析方式补全自动兼容；同为 v500 的不同 YPF 变体也会按文件表实际格式识别。

## 主要变化

- 解包普通 YPF：自动读取版本、长度表、文件名 XOR key、path hash、data hash、表结构，写入 `.ypf_meta.json`。
- 回封普通 YPF：自动读取 `.ypf_meta.json`，复用版本、type、压缩标记、长度表、文件名 XOR key、path hash、data hash 和表结构；没有 metadata 时才用内置启发式。
- GUI 版本框：选择或解包 YPF 后会回填实际版本数字，例如 `500`，不再一直停在 `auto`。
- OP 视频：`op.ypf` 这种裸 MPEG Program Stream 不走 YPF 文件表，解包会直接导出 `.mpg`，回封视频会直接生成裸视频型 `.ypf`。
- GUI 已隐藏兼容/profile/hash 选项；这些逻辑保留在核心模块里自动处理。
- GUI 的“语言”已改成“编码”，直接使用 `cp932 / cp949 / gbk / big5 / cp1252 / utf-8` 这类真实 Python codec 名称；下拉框也允许手动输入其它编码。
- 已兼容两类 v500：Relirium/ToolForYuris 变体，以及 ArcYPF/GARbro 风格的 swap00 + key=FF + CRC32 path + Adler32 data 变体。
- 支持多文件夹打包：一次打包 `ysbin + scenario + cgsysf` 到同一个 `update1.ypf`。

## 运行 GUI

```bat
pip install -r requirements.txt
python tool_for_yuris_py.py --gui
```

Windows 下也可以双击：

```bat
run_gui.bat
```

## FFmpeg 说明

Python 没有内置 FFmpeg。

- 如果 OP 输入已经是 MPEG Program Stream，也就是文件头 `00 00 01 BA`，工具会直接复制，不需要 FFmpeg。
- 如果 OP 输入是 MP4/MKV/AVI/MOV 等格式，工具需要 FFmpeg 转码为 Yu-RIS 常见的 MPEG-1 PS。
- 工具会自动按顺序查找：工具目录下的 `ffmpeg.exe`、系统 PATH 里的 `ffmpeg`、以及 `imageio-ffmpeg` 包提供的 ffmpeg。

可选安装：

```bat
pip install imageio-ffmpeg
```

## 命令行示例

查看信息：

```bat
python tool_for_yuris_py.py info cgsysf.ypf -e cp932
python tool_for_yuris_py.py info op.ypf
```

解包普通 YPF：

```bat
python tool_for_yuris_py.py extract cgsysf.ypf -o Output_cgsysf -e cp932 --verify-hash
```

解包 OP 视频型 YPF：

```bat
python tool_for_yuris_py.py extract op.ypf -o Output_op
```

打包多个子文件夹：

```bat
python tool_for_yuris_py.py pack E:\Relirium\Output2 E:\Relirium\update1.ypf --from-children -e cp932 -v auto
```

手动指定多个根目录：

```bat
python tool_for_yuris_py.py pack E:\Relirium\Output2\cgsysf E:\Relirium\update1.ypf -a E:\Relirium\Output2\scenario -a E:\Relirium\Output2\ysbin -e cp932 -v auto
```

回封 OP 视频：

```bat
python tool_for_yuris_py.py pack op_extracted.mpg op.ypf
python tool_for_yuris_py.py pack new_op.mp4 op.ypf
```

## 模块接口

```python
from yurisypf import YpfArchive, ExtractOptions, PackOptions

ypf = YpfArchive()
ypf.extract(ExtractOptions("cgsysf.ypf", "Output_cgsysf", language="cp932", verify_hash=True))

ypf.pack(PackOptions(
    input_paths=["Output2/cgsysf", "Output2/scenario", "Output2/ysbin"],
    output_ypf="update1.ypf",
    language="cp932",
    version=None,  # None/auto：优先从 .ypf_meta.json 读取
))
```

## 文件结构

```text
tool_for_yuris_py.py       # 入口
run_gui.bat                # Windows GUI 启动
requirements.txt           # tkinterdnd2；imageio-ffmpeg 是可选 FFmpeg 来源

yurisypf/
  archive.py               # YPF 读写核心，自动分流 OP 视频型 .ypf
  op.py                    # OP 裸视频 .ypf 解包/回封/FFmpeg 调用
  cli.py                   # CLI 参数
  codec.py                 # 路径编码 / 长度表 / XOR
  constants.py             # 常量和版本号
  gui.py                   # Tkinter GUI
  hashers.py               # CRC/Adler/Murmur2/XXH32/hash 自动逻辑
  meta.py                  # .ypf_meta.json 查找/读写
  models.py                # dataclass 接口模型
```
