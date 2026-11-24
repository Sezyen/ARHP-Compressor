# MienArch ARHP Compressor说明文档

> 支持 Reed-Solomon 纠删码恢复数据、AES-256-GCM 加密与多分卷的跨格式压缩归档工具
> 当前版本：**2.0.0.2** · GPL-3.0-or-later · Python 3.8+

一个程序，四种格式：`.arh2`（Cauchy-MDS RS + 受保护中心目录）、`.arhp`（Vandermonde RS，v3 头保护）、`.zip`（deflate）、`.7z`（LZMA2）。图形界面与命令行双入口，内置 Windows 右键菜单集成。

---

## 目录

- [功能特性](#功能特性)
- [安装与依赖](#安装与依赖)
- [快速开始](#快速开始)
- [命令行用法](#命令行用法)
- [四种归档格式](#四种归档格式)
- [安全模型](#安全模型)
- [Windows 右键菜单](#windows-右键菜单)
- [打包为可执行文件](#打包为可执行文件)
- [兼容性说明](#兼容性说明)
- [版本历史](#版本历史)
- [许可证](#许可证)

---

## 功能特性

### 归档格式
| 格式 | 压缩算法 | 纠删码 | 中心目录 | 加密 | 说明 |
|------|----------|--------|----------|------|------|
| `.arh2` | zstd 0–22 级 | Cauchy-MDS RS（任意分片组合可恢复） | ✅ 受 RS 保护，可选加密 | AES-256-GCM | **推荐格式**，列目录走快路径 |
| `.arhp` | zstd 0–22 级 | Vandermonde RS | ❌ | AES-256-GCM + 头 HMAC | 兼容 arhp 1.1.0.2 |
| `.zip`  | deflate 0–9 级 | ❌ | ❌ | ❌（标准库限制） | 兼容所有压缩软件 |
| `.7z`   | LZMA2 0–9 级 | ❌ | ❌ | AES-256（py7zr ≥ 0.20） | 高压缩率通用格式 |

### 核心能力

- **Reed-Solomon 纠删码**（GF(2⁸)，本原多项式 0x11D）：恢复数据比例 0–50% 可调（默认 3%，对齐 RAR5 恢复记录），可自动修复归档内随机损坏的分块；归档头与 `.arh2` 中心化目录同样纳入 RS 保护。
- **AES-256-GCM 分块加密**（4 MiB/块，每块独立认证），密钥派生二选一：
  - `PBKDF2-HMAC-SHA256`（60 万次迭代，兼容全部旧版本）；
  - `Argon2id`（3 轮 × 128 MiB × 4 线程，显著抬高 GPU/ASIC 离线破解成本，需 `argon2-cffi`）。
- **流式内存模型**：分块校验、RS 编码/解码全部按块/按列切片进行，载荷工作集由内存限制参数控制（16M–1024M 档位，默认 128M）。
- **原子写入**：全部四种格式的创建与解压均先写同目录临时文件、成功后 `os.replace` 原子替换——崩溃不留半文件、磁盘不足时保留原有归档、解压不跟随已存在目标的硬链接。
- **分卷**：按任意大小拆分为 `name.ext.001/.002/...`（自动检测分卷缺口并拒绝静默忽略），解压时任给一分卷或基名即可。
- **安全解压**：统一拒绝 `../`、绝对路径、Windows 盘符、重复成员名与文件/目录层级冲突；符号链接不跟随打包、链接目标越界即跳过；权限掩码收紧为 0o777，不恢复 setuid/setgid。
- **符号链接保留**：`.arh2/.arhp/.zip` 均以链接本身存入归档（zip 以 Unix 模式位写入），解压时按链接还原。
- **程序临时目录统一管理与清理**：所有中间产物集中在 `%LOCALAPPDATA%\MienArch\ARHP`（拒绝符号链接抢占路径），缓存清理只删本程序前缀条目。
- **7-Zip Manager 风格 GUI**：内容树预览（名称/大小/压缩后/修改时间/属性/CRC/算法）、双击条目即用系统默认程序查看、选中条目部分解压。

---

## 安装与依赖

```bash
pip install pyzstd cryptography PySide6 argon2-cffi py7zr
```

| 依赖 | 用途 | 缺失时 |
|------|------|--------|
| `pyzstd`（或 `zstandard`） | zstd 压缩 | `.arh2/.arhp` 创建失败 |
| `cryptography` | AES-256-GCM / PBKDF2 | 加密功能不可用 |
| `PySide6` | 图形界面 | 自动回退纯命令行 |
| `argon2-cffi` | Argon2id 密钥派生 | 仅该加密方案不可用 |
| `py7zr` | `.7z` 读写 | `.7z` 格式不可用 |

> 程序自动加载同目录下的 `arhp_core.py` 核心库，无需安装；
> 同目录的 `arhp_plugin.py` 存在时启用右键菜单集成（缺失不影响其他功能）；
> 同目录放置 `ARHP.png` 即作为窗口与任务栏图标（打包为 onedir exe 时放 exe 旁即可）。

---

## 快速开始

```bash
# 图形界面（双击运行 / pythonw 启动 / 显式 gui 子命令）
python arhp_main_2.0.0.2.py gui

# 双击 .arh2 / .arhp 文件（装好文件关联后）直接进入打开页并加载该归档
arhp.exe "C:\path\to\archive.arh2"
```

GUI 主界面含两个标签页：

- **添加压缩包**：文件列表、输出路径、格式、压缩等级（0–22）、恢复数据比例（0–50%）、分块大小（64K–128M）、加密（PBKDF2/Argon2id）、中心目录加密（仅 .arh2）、分卷大小预设、内存限制。
- **打开压缩包**：树形内容预览、解压到所选目录 / 解压到同名子文件夹、测试、信息，支持多选条目部分解压。

压缩前若目标文件已存在，会先弹确认框再覆盖（底层为原子替换）。

---

## 命令行用法

```text
arhp create -o out.arh2|out.arhp|out.zip|out.7z [选项] 文件/目录...
arhp extract 归档 [-o 目录] [-p 密码] [--only 名称...]
arhp test 归档 [-p 密码]
arhp info 归档
arhp list 归档 [-p 密码]        # 列出归档内容（预览）
arhp gui                        # 启动图形界面
```

无参数运行默认进入 GUI；`--headless` 强制命令行模式（打印帮助）。

### 常用示例

```bash
# 创建加密 .arh2（Argon2id + 加密中心目录），3% 恢复数据，分卷 650M
arhp create ./docs -o backup.arh2 --crypto argon2id --cd-encrypt \
    -p "your-password" -r 3 -V 650M

# 创建 .7z（AES-256 加密 + LZMA2 最高压缩）
arhp create ./photos -o photos.7z -l 9 -p "your-password"

# 解压分卷归档（任给一分卷即可），限制内存 256M
arhp extract backup.arh2.001 -o ./restore -p "your-password" -m 256M

# 只解压指定条目（文件或目录子树）
arhp extract backup.arh2 -o ./restore --only docs/report.pdf docs/notes/

# 测试完整性（含修复能力与加密认证，不写出文件）
arhp test backup.arh2

# 环境变量也可提供密码（避免命令行历史泄露）
ARHP_PASSWORD="your-password" arhp extract backup.arh2
```

### create 主要选项

| 选项 | 说明 |
|------|------|
| `-l, --level` | 压缩级别：arh2/arhp 0–22（0=仅存储），zip/7z 0–9（默认 9） |
| `-r, --redundancy` | RS 恢复数据百分比 0–50（仅 arh2/arhp，默认 3） |
| `-b, --block-size` | 纠删码分块大小，如 256K/1M/4M（默认 1M） |
| `-V, --volumes` | 分卷大小，如 32M/650M/4480M（全格式支持） |
| `-p, --password` | 加密密码（zip 不支持写入加密，会明确报错） |
| `--crypto` | arh2/arhp 加密方案：`gcm`（默认）/ `argon2id` |
| `--cd-encrypt` | 仅 .arh2：加密中心化目录（列目录也需密码） |
| `-m, --memory` | 内存限制 16M–1024M（默认 128M） |
| `--encrypt` | 交互输入并二次确认密码 |

---

## 四种归档格式

### .arh2（ARH2 v1，推荐）

```
魔数 ARH2\x00\x01 │ JSON 头（header_crc 自校验）│ 数据块 │ RS 校验块
│ 头分块 + 头校验块（RS 保护）│ 中心化目录（可选加密 + RS 保护）│ 自描述尾注 ARH2\x00\x02
```

- **Cauchy-MDS 校验矩阵**：任意可用分片组合均可恢复，优于只能逐块顺序修复的方案；
- **受保护的中心化目录**：列目录走快路径，无需解压载荷；目录与头使用同一套 RS 保护布局（HB/HP 分块 + 逐块 CRC + 自描述尾注），损坏可自动修复；
- 读取端与旧版 **arh2 1.0.0.2** 完全双向兼容。

### .arhp（ARHP v2/v3）

- v3 格式在 RS 校验区之后追加**头分块 + 头校验块 + 自描述尾注**，归档头纳入 Reed-Solomon 保护（扁平键名布局，**arhp 1.1.0.2 可直接读取新创建的 .arhp**）；
- 加密归档的头额外含 **HMAC-SHA256** 认证（`header_mac` 字段，规范化头 JSON 为认证对象），头被篡改立即报错；
- v2 旧归档（无尾注）保持读取兼容；无中心目录，列目录需流式处理载荷（该格式的固有成本）。

### .zip / .7z

- `.zip`：标准库 zipfile（deflate/store），兼容所有压缩软件；标准库不支持写入加密，传入密码会明确报错并建议改用 .arh2/.arhp/.7z；创建时保留符号链接（Unix 模式位），解压重复成员名/层级冲突一律拒绝（与 tar 路径对齐）。
- `.7z`：py7zr（LZMA2/Copy），可选 AES-256 加密；py7zr 在传入 filters 时必须显式 `header_encryption=True` 才会真正加密；解压前对全部成员名做统一预检，不再把路径安全完全交给第三方库。

---

## 安全模型

**明确边界：CRC32 与 Reed-Solomon 都是线性码，只能检测/修复「随机损坏」，不能防「恶意篡改」**——攻击者可以重算 CRC 并伪造校验块，使 `test` 全部通过。未加密归档不具备防篡改能力，本工具的「容错」仅指抗随机损坏。

- **加密归档**：AES-256-GCM 载荷逐块认证；`.arhp` 的头额外纳入 HMAC-SHA256；`.arh2` 的头由 CRC32 + Cauchy-MDS RS 保护（与旧版兼容）。RS 恢复出的块经 CRC 验证后与原始密文逐字节一致，因此加密归档的比特级损坏同样可自动修复（先纠错、后认证）。
- **防资源耗尽**：读取端严格校验 KDF 参数（PBKDF2 迭代上限 200 万次、Argon2id 内存上限 256 MiB）、头/尾注长度上限（64 MiB / 1 MiB）、分块布局连续性，恶意头会被明确拒绝而非拖垮系统。
- **路径安全**：解压统一拒绝 `../`、绝对路径、盘符路径、ADS 冒号组件、符号链接父路径、重复成员名与文件/目录层级冲突；符号链接目标越出解压目录即跳过。
- **加密强度**：Argon2id（128 MiB 内存硬派生）显著优于 PBKDF2（60 万次迭代）对抗 GPU/ASIC 离线破解，创建加密归档时推荐选用。

---

## Windows 右键菜单

主程序 GUI 提供「安装右键菜单 / 移除右键菜单」按钮，注册到 `HKCU\Software\Classes`（**免管理员权限**）：

```
任意文件、文件夹     → ARHP → 添加到 ARHP 压缩包
文件夹空白处         → ARHP → 将当前文件夹添加到 ARHP 压缩包
.arh2/.arhp/.zip/.7z → ARHP → 打开压缩包 / 解压文件到当前位置 / 解压到同名文件夹
```

- 一级级联菜单通过**根键 MUIVerb + 空 `SubCommands` + `shell` 子键承载静态动词**实现（Windows 7–11 经典菜单均支持，无需注册 Explorer Command Store）；
- 二级菜单显示顺序按**键名排序**，归档根下动词键名带 `a_/b_/c_` 前缀固定顺序；
- 同时注册 `.arh2` 与 `.arhp` 文件关联（ProgID `MienArch.ARH2` / `MienArch.ARHP`）：资源管理器双击以裸路径参数调起主程序，dispatch 直接按「打开压缩包」处理。**只在用户尚未指定其他打开方式（或已指向本 ProgID）时写入，绝不覆盖用户手动选择过的程序**；`.zip` 不注册关联；
- 安装/卸载时顺带清理旧版 arh2 插件的平铺菜单键与 `arh2` 级联根键，避免新旧两套菜单并存；
- 右键「添加」弹小对话框收集输出名/格式/密码/级别（切到 zip 自动清空密码），注册表 verb 只传入单个选中对象，多选打包为单对象设计；
- Windows 11 中经典右键菜单折叠在「显示更多选项」(Shift+F10) 中；如需固定到一级菜单需 MSIX 稀疏包 + IExplorerCommand COM，超出本插件范围。

---

## 打包为可执行文件

```bash
pip install pyinstaller

# onedir 模式（推荐：exe 旁放 ARHP.png 即成为窗口/任务栏图标）
pyinstaller --noconfirm --windowed --name arhp \
    arhp_main_2.0.0.2.py arhp_core.py arhp_plugin.py

# onefile 单文件
pyinstaller --noconfirm --windowed --onefile --name arhp \
    arhp_main_2.0.0.2.py arhp_core.py arhp_plugin.py
```

`arhp_plugin` 作为普通模块导入打包即可（不需要 `--add-data`），exe 旁边不再需要独立的 `arhp_plugin.py`。

---

## 兼容性说明

| 方向 | 兼容性 |
|------|--------|
| 本版创建的 `.arhp` → arhp **1.1.0.2** 读取 | ✅（Vandermonde RS + 扁平尾注 + 可选头 HMAC） |
| 本版创建的 `.arh2` → arh2 **1.0.0.2** 读取 | ✅（Cauchy-MDS，无 header_mac） |
| 旧版 arhp 1.1.0.2 / arh2 1.0.0.2 归档 → 本版读取 | ✅（含 v2 无尾注 .arhp 旧格式） |
| nonce 格式 | 读取端同时接受 v1.0.2.3+（8 字节前缀 + 4 字节序号）与更早（4 字节前缀 + 8 字节序号） |

---


## 许可证

GPL-3.0-or-later，详见 LICENSE.txt。

Copyright (C) MienArch 2026 · 面包图书馆 2026. 版权所有
