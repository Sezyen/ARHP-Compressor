# ARHP Compressor

带 Reed-Solomon 纠错恢复与 AES-256-GCM 认证的压缩归档工具（Python）。

- **版本**：1.0.2.2
- **许可证**：GPL-3.0-or-later（详见 LICENSE.txt）
- **版权**：Copyright (C) MienArch | 面包图书馆 | 2026

## 简介

ARHP Compressor 是一个压缩归档工具，在常规压缩的基础上内嵌 Reed-Solomon 纠删码恢复数据：归档中少量数据块损坏（比特衰减、坏道、传输丢包等）时可以自动修复；配合逐块 CRC 与 AES-GCM 认证，篡改过的数据不可能被"修复"成看似正常的内容。

同时兼容 `.zip` 与 `.7z` 两种通用格式，提供图形界面（PySide6）与命令行两种使用方式。

## 主要特性

- **三种归档格式**
  - `.arhp`（自有格式）：Zstd 压缩（0–22 级，0 为仅存储）+ 可选 AES-256-GCM 加密 + Reed-Solomon 恢复数据
  - `.zip`：标准库 deflate / store，兼容所有压缩软件（不支持加密与恢复数据）
  - `.7z`：LZMA2 压缩（需 py7zr），可选 AES-256 加密（含头加密）
- **恢复数据（仅 .arhp）**：冗余度 0–50% 可调（默认 3%），分块大小 64K–128M 可选
- **自动修复**：解压/测试时逐块 CRC 校验，损坏块用校验块 Reed-Solomon 恢复；恢复出的数据再次 CRC 验证，通不过则拒绝解压
- **加密（仅 .arhp/.7z）**：PBKDF2-HMAC-SHA256（60 万次迭代）派生密钥；载荷按 4 MiB 分块独立 AES-256-GCM 认证加密；归档头保持明文，便于修复与列目录
- **多分卷**：任意格式均可按大小分卷（`name.ext.001/.002/...`），读取时任给一分卷或基名即可，自动合并
- **选择性解压**：只解压指定文件或目录子树
- **7-Zip 风格列目录**：名称/大小/压缩后大小/修改时间/属性/CRC/算法
- **安全解压**：拦截绝对路径、`..` 与 Windows 盘符路径，防止目录穿越
- **GUI**：添加压缩包 / 打开压缩包双标签页，双击文件即用系统默认程序查看

## 运行环境与依赖

需要 Python 3.x（建议 3.10+）。

| 依赖 | 用途 | 是否必需 |
| --- | --- | --- |
| `pyzstd` | .arhp 的 Zstd 压缩/解压（缺失时自动回退到 `zstandard`） | 创建/读取 .arhp 必需 |
| `cryptography` | AES-256-GCM 加密/解密 | .arhp 加密归档必需 |
| `py7zr` | .7z 读写（≥0.20 支持加密） | 仅 .7z |
| `PySide6` | 图形界面 | 仅 GUI |

```bash
pip install pyzstd cryptography py7zr PySide6
```

## 快速开始

### 图形界面

双击 `arhp_main-1.0.2.2.py`，或：

```bash
python arhp_main-1.0.2.2.py        # 无参数 → 启动 GUI
pythonw arhp_main-1.0.2.2.py       # Windows 无控制台启动
python arhp_main-1.0.2.2.py gui    # 强制启动 GUI
```

窗口与任务栏图标：把 `ARHP.png` 放在脚本/exe 同目录即可自动加载。

### 命令行（无头模式）

```bash
python arhp_main-1.0.2.2.py --headless <子命令> [选项]
```

| 子命令 | 说明 |
| --- | --- |
| `create` / `c` | 创建归档（扩展名决定格式，也可用 `-f` 指定） |
| `extract` / `x` | 解压归档 |
| `test` / `t` | 测试归档完整性（含修复能力与加密认证） |
| `list` / `l` / `ls` | 列出归档内容（预览） |
| `info` / `i` | 查看归档信息 |
| `gui` | 启动图形界面 |

示例：

```bash
# 创建高压缩 + 5% 恢复数据 + 4M 分块 + DVD 分卷的加密归档
python arhp_main-1.0.2.2.py create -o backup.arhp -l 19 -r 5 -b 4M -V 4480M -p 密码 文档/ 照片/

# 解压（多分卷给任一分卷或基名均可），只解压其中一个目录
python arhp_main-1.0.2.2.py extract backup.arhp.001 -o 恢复目录 -p 密码 --only 文档

# 测试 / 列目录 / 信息
python arhp_main-1.0.2.2.py test backup.arhp -p 密码
python arhp_main-1.0.2.2.py list backup.arhp
python arhp_main-1.0.2.2.py info backup.arhp
```

`create` 常用选项：`-l 级别`（arhp: 0–22；zip/7z: 0–9）、`-r 冗余%`（仅 arhp，0–50）、`-b 分块大小`（如 256K/1M/4M）、`-V 分卷大小`（如 32M/650M/1G）、`-p 密码` 或 `--encrypt` 交互输入。密码也可用环境变量 `ARHP_PASSWORD` 提供。

## .arhp 归档格式（v2）

大端布局：

```
magic   6B   b"ARHP\x00\x01"
hlen    8B   uint64，头长度
header  JSON 分块表、逐块 CRC、恢复参数、加密参数
data    N 个数据块（按真实长度连续存放；Zstd 流或密文）
parity  K 个 Reed-Solomon 校验块（等长 block_size，N+K ≤ 255）
```

- `compression`：`zstd`（载荷为 Zstd 流）或 `store`（原始 tar，level=0）
- `encrypted`：载荷为 AES-256-GCM 密文，解密后方可解压
- `method` 固定为 `rs`：内嵌 Reed-Solomon 校验块，单文件自足
- 加密只作用于载荷；CRC + RS 负责纠错恢复，GCM 负责防篡改认证

## 分卷

所有格式都支持分卷：超过设定大小时输出 `name.ext.001/.002/...` 并删除原单文件。读取端（解压/测试/列目录/信息）给出任一分卷或基名即可，程序会在临时目录自动合并。

## 临时文件

中间产物统一存放在程序临时目录（不会污染输出位置）：

- Windows：`%LOCALAPPDATA%\MienArch\ARHP`
- 其他系统：`~/.cache/MienArch/ARHP`

GUI 解压结束后会自动清理其中的缓存。

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `arhp_main-1.0.2.2.py` | 程序入口 + PySide6 图形界面 |
| `arhp_core.py` | 核心库：Reed-Solomon（GF(2^8)）、Zstd 流式封装、AES-256-GCM 加密、三种格式读写、CLI 入口 |
| `ARHP.png` | 窗口/任务栏图标（可选，放同目录即可） |

`arhp_main` 会自动加载同目录的 `arhp_core.py`，无需安装；核心库也可单独作为模块导入（`import arhp_core`）。

## 打包为可执行文件

以 PyInstaller onedir 方式打包即可，把 `ARHP.png` 放在生成的 exe 旁作为图标；程序同时兼容 onefile 模式（资源打进内部目录）。

## 版本历史

- **v1.0.2.2**：修复 zip 打包时断链（失效符号链接）被误存为目录条目、解压后凭空多出目录的问题；修复 `_create_arhp` 中未使用变量等已知小问题。

## 版权与许可

Copyright (C) MienArch | 2026

本项目基于 GPL-3.0-or-later 许可证发布，详见 LICENSE.txt。本软件不提供任何担保；因使用本软件造成的任何损失，作者概不负责。
