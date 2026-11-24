#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARHP Core — 压缩归档核心库（v2.0.0.2）。

Copyright (C) MienArch 2026.
面包图书馆 2026. 版权所有
本项目基于 GPL-3.0-or-later 许可证发布，详见 LICENSE.txt。

v2.0.0.2（bugfix + 安全加固）：
- 修复 _extract_zip 进度统计引用未定义变量 infos 的 NameError
  （zip 含 200 个以上文件时解压必崩）；
- zip 解压改用与 tar 一致的 _write_extracted_file() 原子写入：
  中断不再残留半文件，也不会直接截断/跟随已存在目标的硬链接；
- zip / 7z 创建统一改用 _write_archive_atomically() 原子写入
  （与 arh2/arhp 对齐：崩溃不留损坏归档、不提前截断旧文件、
  磁盘不足时保留原有归档）；
- 7z 解压新增成员预检：与 tar/zip 一致地拒绝 ../、绝对路径、
  Windows 盘符、重复成员名与文件/目录层级冲突，不再把路径安全
  完全交给第三方库；
- zip 创建保留符号链接（以 Unix 模式位存储链接本身，与 arh2/arhp
  的 tar 载体策略一致），不再静默跟随链接打包目标内容；
- 内存说明措辞修正：载荷分块处理的工作集受 mem_limit 控制，实际
  进程内存还包括 Python 对象、缓冲区和头/目录元数据开销；
- 版本号统一提升到 2.0.0.2。

v2.0.0.1（bugfix）：
- 修复 zip 解压不校验重复成员名的问题：与 tar 解压路径一致，
  _extract_zip 现在同样拒绝重复条目与文件/目录层级冲突，避免恶意
  或损坏 zip 中的重名条目在解压时静默互相覆盖（最后一项胜出）；
- 版本号统一提升到 2.0.0.1。

v2.0.0.0（ARH2 合并版，统一归档核心）：
- 支持 .arh2 / .arhp / .zip / .7z 四种格式。以高度优化的 ARH2 代码为
  基座（Cauchy-MDS 纠删码、受 RS 保护的中心化目录、原子写入、严格
  的头/加密参数校验、符号链接加固的解压路径），合并旧版 arhp 的
  流式内存模型与多格式能力，并完整保留对全部旧版 .arhp 归档
  （v2 无尾注格式与 v3 头保护格式，Vandermonde 纠删码）的读取能力；
- 新创建的 .arhp 仍为旧版可读的 v3 格式（Vandermonde RS + 头 HMAC
  认证 + 自描述尾注），arhp 1.1.0.2 可直接读取；新创建的 .arh2 与
  arh2 1.0.0.2 完全兼容；
- 分块校验 / Reed-Solomon 编码/解码全部按块/按列切片流式进行，载荷
  处理工作集由 mem_limit 参数控制（16M-1024M，默认 128M）；实际进
  程内存还包括 Python 对象、缓冲区和头/目录元数据开销；
- zip/7z 支持继承自 arhp 1.1.0.2（zip 标准库 deflate；7z 需 py7zr）。

安全语义澄清（沿用 v1.1.0.2 审计结论）：
- CRC32 与 Reed-Solomon 都是线性码：只能检测/修复“随机损坏”，
  不能防“恶意篡改”——攻击者可以重算 CRC 并伪造校验块，test 全绿。
  未加密归档不具备防篡改能力，本工具的“容错”仅指抗随机损坏；
- 加密归档（AES-256-GCM）载荷本就逐块认证；.arhp 加密归档的头额外
  纳入 HMAC-SHA256 认证（header_mac 字段），头被篡改会明确报错；
- .arh2 的头由 CRC32 + Cauchy-MDS RS 保护（与 arh2 1.0.0.2 兼容）。

格式一览：
- .arh2（ARH2 v1）：魔数 ARH2\x00\x01；Cauchy-MDS RS；尾注含归档头
  与中心化目录两套保护布局；列目录走中心化目录快路径，无需解压载荷；
- .arhp（ARHP v2/v3）：魔数 ARHP\x00\x01；Vandermonde RS；v3 尾注保护
  归档头；无中心目录，列目录需流式处理载荷；
- .zip：标准库 zipfile（deflate/store），不支持写入加密；
- .7z：py7zr（LZMA2/Copy），可选 AES-256 加密（需 py7zr>=0.20）。
"""

import argparse
import base64
import getpass
import json
import math
import os
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import zlib

__version__ = '2.0.0.2'
__license__ = 'GPL-3.0-or-later'
__all__ = ['ArchiveError', 'CryptoError', 'create_archive', 'extract_archive',
           'test_archive', 'open_archive', 'info_archive', 'list_archive',
           'detect_format', 'SUPPORTED_FORMATS', 'find_volumes',
           'split_volumes', 'clear_app_temp_cache', 'app_temp_dir',
           'find_resource', 'main']

# ======================================================================
# 资源定位（图标等）：兼容脚本运行与 PyInstaller frozen（onedir / onefile）
# ======================================================================

def app_dir():
    """程序所在目录：打包成 exe 后是 exe 所在目录，否则是源文件所在目录。"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def find_resource(name):
    """按顺序在以下位置查找资源文件，返回第一个存在的路径或 None：
    1. 程序所在目录（onedir exe 旁 / 脚本旁，适合随程序分发的 ARHP.png）；
    2. sys._MEIPASS（PyInstaller 打包进内部目录的资源）。
    """
    candidates = [os.path.join(app_dir(), name)]
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidates.append(os.path.join(meipass, name))
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


# ======================================================================
# 临时目录：所有临时文件统一存放位置
# ======================================================================

def app_temp_dir():
    """本程序所有临时文件的统一存放目录。

    Windows: %LOCALAPPDATA%\\MienArch\\ARHP
    其他系统: ~/.cache/MienArch/ARHP
    目录不存在时自动创建。

    安全说明：创建后校验最终目录不是符号链接。若攻击者预先在目标位置
    放置同名符号链接，后续临时文件会写到链接目标、缓存清理也会删除
    目标目录里的内容；此处直接拒绝使用被链接占用的目录。
    """
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA') or \
            os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
    else:
        base = os.environ.get('XDG_CACHE_HOME') or \
            os.path.join(os.path.expanduser('~'), '.cache')
    os.makedirs(base, exist_ok=True)
    parent = os.path.join(base, 'MienArch')
    d = os.path.join(parent, 'ARHP')
    # 同时检查应用名父目录和最终目录；否则攻击者可将 MienArch 本身
    # 预置为符号链接，绕过只检查最后一层的保护。
    for candidate in (parent, d):
        if os.path.lexists(candidate):
            if os.path.islink(candidate) or not os.path.isdir(candidate):
                raise ArchiveError(
                    '程序临时目录路径被符号链接或非目录占用，已拒绝使用: %s'
                    % candidate)
        else:
            os.mkdir(candidate)
    # lstat 不跟随链接：最终节点必须是真实目录（拦截链接以外的非常规文件）
    if not stat.S_ISDIR(os.lstat(d).st_mode):
        raise ArchiveError(
            '程序临时目录被符号链接或非常规文件占用，已拒绝使用: %s'
            '（请检查并手动删除该条目）' % d)
    return d


# 本程序在临时目录中创建条目的固定前缀；缓存清理只认这些前缀，
# 绝不整目录清空（用户可能把别的文件放进同一目录）。
_TEMP_PREFIXES = ('.arhp_', '.arhp_join_', '.arhp_payload_', '.arhp_restore_',
                  '.arhp_list_', '.arhp_build_', 'arhp_view_')


def clear_app_temp_cache():
    """清空程序临时目录中由本程序创建的缓存条目（解压等操作结束后调用）。

    - 只删除带 _TEMP_PREFIXES 固定前缀的条目，其他文件一律不动；
    - 符号链接只 unlink 链接本身，绝不跟随删除目标；
    - 单个条目删除失败时静默跳过，避免中断主流程。
    """
    d = app_temp_dir()
    try:
        names = os.listdir(d)
    except OSError:
        return
    for name in names:
        if not name.startswith(_TEMP_PREFIXES):
            continue
        p = os.path.join(d, name)
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass


# ======================================================================
# Reed-Solomon 纠删码 (GF(2^8)，本原多项式 0x11D)
# ======================================================================

class ReedSolomonError(Exception):
    pass


def xor_bytes(a, b):
    """等长 bytes 快速异或。"""
    if len(a) != len(b):
        raise ReedSolomonError('异或长度不一致: %d != %d' % (len(a), len(b)))
    return (int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little')).to_bytes(len(a), 'little')


# 纠删码标识：写入 .arh2 头/尾注与 .arhp 头（v2 旧归档无该字段，按
# Vandermonde 处理；旧版 arhp 读取器会把未知字段原样保留在头字典里，
# 不影响其 header_crc 重算，因此新写 .arhp 带此字段仍兼容旧读取端）。
CODEC_CAUCHY = 'cauchy-v1'
CODEC_VANDERMONDE = 'vandermonde-v1'


class ReedSolomon:
    """GF(2^8) 上的 Reed-Solomon 编解码，本原多项式 0x11D。

    支持两种校验矩阵：
    - Cauchy-MDS（coeff_cauchy）：任意可用分片组合均可恢复（.arh2）；
    - Vandermonde（coeff）：旧版 .arhp 使用的编码，保留以兼容 v2/v3
      旧归档的读取与新 .arhp 的写入（旧版 arhp 1.1.0.2 可读）。
    """

    def __init__(self, poly=0x11D):
        self.exp = [0] * 512
        self.log = [0] * 256
        x = 1
        for i in range(255):
            self.exp[i] = x
            self.log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= poly
        for i in range(255, 512):
            self.exp[i] = self.exp[i - 255]
        self._tables = {}

    # ---- 基本运算 ----
    def mul(self, a, b):
        if a == 0 or b == 0:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def inv(self, a):
        if a == 0:
            raise ReedSolomonError('GF 除零')
        return self.exp[255 - self.log[a]]

    def table(self, c):
        """返回 256 字节乘法表，配合 bytes.translate 使用（C 速度）。"""
        t = self._tables.get(c)
        if t is None:
            t = bytes(self.mul(c, b) for b in range(256))
            self._tables[c] = t
        return t

    def coeff(self, parity_idx, data_idx):
        """Vandermonde 系数 alpha^((j+1)*i)（旧版 .arhp 编码）。"""
        return self.exp[((parity_idx + 1) * data_idx) % 255]

    def coeff_cauchy(self, parity_idx, data_idx, n_data):
        """Cauchy-MDS 系数，保证任意可用分片组合均可恢复（.arh2）。"""
        row = n_data + parity_idx
        if not 0 <= data_idx < n_data or row >= 255 or parity_idx < 0:
            raise ReedSolomonError('Cauchy 校验矩阵索引越界')
        return self.inv(self.exp[data_idx] ^ self.exp[row])

    def coeff_any(self, codec, parity_idx, data_idx, n_data):
        """按编码标识取校验系数（流式编码/解码共用一个入口）。"""
        if codec == CODEC_CAUCHY:
            return self.coeff_cauchy(parity_idx, data_idx, n_data)
        if codec == CODEC_VANDERMONDE:
            return self.coeff(parity_idx, data_idx)
        raise ReedSolomonError('未知的 Reed-Solomon 编码标识: %r' % (codec,))

    # ---- 编码（整块，供头/目录等小块保护使用）----
    def encode(self, data_blocks, k, codec=CODEC_CAUCHY):
        """data_blocks: N 个等长 bytes；返回 k 个校验块 bytearray。"""
        if not data_blocks:
            raise ReedSolomonError('没有数据块')
        if not isinstance(k, int) or isinstance(k, bool) or k < 0:
            raise ReedSolomonError('校验块数量无效')
        n_data = len(data_blocks)
        if n_data + k > MAX_SHARDS:
            raise ReedSolomonError('数据块与校验块总数超过 GF(256) 上限')
        size = len(data_blocks[0])
        parity = [bytearray(size) for _ in range(k)]
        for i, block in enumerate(data_blocks):
            if not isinstance(block, bytes) or len(block) != size:
                raise ReedSolomonError('数据块类型或长度不一致')
            for j in range(k):
                c = self.coeff_any(codec, j, i, n_data)
                if c:
                    parity[j] = bytearray(xor_bytes(parity[j], block.translate(self.table(c))))
        return parity

    # ---- 解码（纠删，整块，供头/目录等小块保护使用）----
    def recover(self, data_blocks, parity_blocks, missing,
                codec=CODEC_CAUCHY):
        """data_blocks: list[bytes|None]；parity_blocks: list[bytes|None]。
        missing: 损坏/缺失的数据块索引列表。返回 {idx: bytes}。

        输入做防御性校验（索引越界/重复、校验块长度不一致直接报错），
        不依赖调用方兜底；超额丢失也在这里明确拒绝。
        """
        missing = list(missing)
        data_blocks = [bytes(b) if isinstance(b, bytearray) else b
                       for b in data_blocks]
        parity_blocks = [bytes(b) if isinstance(b, bytearray) else b
                         for b in parity_blocks]
        n_data = len(data_blocks)
        if any(not isinstance(i, int) or isinstance(i, bool)
               or i < 0 or i >= n_data for i in missing):
            raise ReedSolomonError('待恢复块索引越界: %r' % (missing,))
        if len(set(missing)) != len(missing):
            raise ReedSolomonError('待恢复块索引重复: %r' % (missing,))
        if not missing:
            return {}
        rows = [(j, p) for j, p in enumerate(parity_blocks) if p is not None]
        if len(missing) > len(rows):
            raise ReedSolomonError(
                '损坏 %d 块，超出可恢复上限 %d 块' % (len(missing), len(rows)))
        # 所有可用校验块必须等长（防御损坏输入，避免解码中途崩溃）
        if not rows:
            raise ReedSolomonError('没有可用校验块')
        size = len(rows[0][1])
        if any(not isinstance(p, bytes) or len(p) != size for _, p in rows):
            raise ReedSolomonError('校验块类型或长度不一致，无法恢复')
        for blk in data_blocks:
            if blk is not None and (not isinstance(blk, bytes) or len(blk) > size):
                raise ReedSolomonError('数据块类型或长度异常，无法恢复')

        # Cauchy-MDS 矩阵的任意 m 行、m 列子矩阵均可逆；Vandermonde 的
        # 奇异性会在下方 _gauss 中同样被检出并抛出明确错误，无需预消元。
        m = len(missing)
        chosen = tuple(rows[:m])

        # 方程：sum_{i in missing} coeff(j,i) * D_i = P_j - sum_{i 已知} coeff(j,i) * D_i
        A = [[self.coeff_any(codec, j, i, n_data) for i in missing]
             for j, _ in chosen]
        B = []
        for j, p in chosen:
            rhs = bytearray(p)
            for i, blk in enumerate(data_blocks):
                if blk is None:
                    continue
                if len(blk) < size:
                    # 最后一块可能短于 block_size，编码时按零填充，这里保持一致
                    blk = blk + b'\x00' * (size - len(blk))
                c = self.coeff_any(codec, j, i, n_data)
                if c:
                    rhs = bytearray(xor_bytes(rhs, blk.translate(self.table(c))))
            B.append(rhs)
        X = self._gauss(A, B)
        return {idx: bytes(x) for idx, x in zip(missing, X)}

    def _gauss(self, A, B):
        n = len(A)
        for col in range(n):
            piv = -1
            for r in range(col, n):
                if A[r][col]:
                    piv = r
                    break
            if piv < 0:
                raise ReedSolomonError('校验矩阵奇异，无法恢复')
            if piv != col:
                A[col], A[piv] = A[piv], A[col]
                B[col], B[piv] = B[piv], B[col]
            invc = self.inv(A[col][col])
            if invc != 1:
                A[col] = [self.mul(x, invc) for x in A[col]]
                B[col] = bytearray(B[col].translate(self.table(invc)))
            for r in range(n):
                if r != col and A[r][col]:
                    f = A[r][col]
                    A[r] = [x ^ self.mul(f, y) for x, y in zip(A[r], A[col])]
                    B[r] = bytearray(xor_bytes(B[r], B[col].translate(self.table(f))))
        return B


# ======================================================================
# zstd 流式读写封装，优先 pyzstd，缺失时使用 zstandard。
# ======================================================================

# zstd 实际支持的压缩级范围（负数 = 超快档，>19 需要 --ultra）
MIN_LEVEL = -7
MAX_LEVEL = 22
DEFAULT_LEVEL = 9
STORE_LEVEL = 0  # 仅存储（不压缩），由 archive 层处理


def _load():
    try:
        import pyzstd
        return 'pyzstd', pyzstd
    except ImportError:
        try:
            import zstandard
            return 'zstandard', zstandard
        except ImportError:
            raise ImportError('缺少 zstd 后端，请安装: pip install pyzstd')


def normalize_level(level):
    """把任意输入整理为合法 zstd 级别；0/None 返回默认级别。"""
    if not level:
        return DEFAULT_LEVEL
    level = int(level)
    return max(MIN_LEVEL, min(MAX_LEVEL, level))


def open_writer(fobj, level=DEFAULT_LEVEL):
    """返回可写入 zstd 流的上下文管理器文件对象。

    level=0 或 None 表示默认级别 9。
    """
    name, z = _load()
    level = normalize_level(level)
    if name == 'pyzstd':
        return z.ZstdFile(fobj, 'wb', level_or_option=level)
    return z.ZstdCompressor(level=level).stream_writer(fobj)


def open_reader(fobj):
    """返回可读取 zstd 流的上下文管理器文件对象。"""
    name, z = _load()
    if name == 'pyzstd':
        return z.ZstdFile(fobj, 'rb')
    return z.ZstandardDecompressor().stream_reader(fobj)


# ======================================================================
# 归档加密 (AES-256-GCM + PBKDF2-HMAC-SHA256 / Argon2id)
# ======================================================================

# 加密算法固定为分块 AES-256-GCM（4 MiB 一块，每块独立认证加密）；
# 密钥派生可选两种：
#   gcm      —— PBKDF2-HMAC-SHA256（60 万次迭代，兼容全部旧版本）；
#   argon2id —— Argon2id 内存硬派生（默认 3 轮 × 128 MiB × 4 线程），
#               显著抬高 GPU/ASIC 离线破解成本；需要 argon2-cffi；
# v1.0.2.3 起 nonce = 随机 8 字节前缀 + 4 字节大端块序号（总长 12 字节
# 不变）；更早版本为 4 字节前缀 + 8 字节序号，读取时两者都接受；
# 密文再进入分块/CRC/Reed-Solomon 流程：CRC+RS 负责纠错恢复，
# GCM 负责认证——RS 恢复出的块经 CRC 验证后与原始密文逐字节一致，
# 因此加密归档的比特级损坏同样可以被自动修复（先纠错、后认证）。

KDF_ITERATIONS = 600_000
CHUNK_SIZE = 4 * 1024 * 1024  # 每块明文大小，密文每块多 16 字节认证标签
_SALT_LEN = 16
_NONCE_LEN = 12  # AES-GCM 标准 nonce 长度
_NONCE_PREFIX_LEN = 8  # v1.0.2.3+ 写入：8 字节随机前缀 + 4 字节块序号
_LEGACY_NONCE_PREFIX_LEN = 4  # v1.0.2.2 及更早：4 字节前缀 + 8 字节序号
# 读取端接受两种前缀长度（旧版 .arhp 归档可能是 4 字节前缀）
_VALID_NONCE_PREFIX_LENS = (_NONCE_PREFIX_LEN, _LEGACY_NONCE_PREFIX_LEN)

# Argon2id 默认派生参数（可被头中 kdf_params 覆盖，读取时校验范围）
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 128 * 1024  # 128 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
# 读取侧安全上限：防止恶意头诱导超大内存/时间消耗
MAX_ARGON2_TIME_COST = 6
MAX_ARGON2_MEMORY_KIB = 256 * 1024  # 256 MiB；限制恶意归档的资源消耗
MAX_ARGON2_PARALLELISM = 8

# 可选加密方案：值为写入归档头 crypto.kdf 的标识
KDF_PBKDF2 = 'PBKDF2-HMAC-SHA256'
KDF_ARGON2ID = 'argon2id'
_CRYPTO_ALGO_CHOICES = ('gcm', 'argon2id')  # CLI/GUI 入参


class ArchiveError(Exception):
    pass


class CryptoError(ArchiveError):
    pass


def derive_key(password, salt, iterations=KDF_ITERATIONS):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    if isinstance(password, str):
        password = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def derive_key_argon2id(password, salt, time_cost=ARGON2_TIME_COST,
                        memory_kib=ARGON2_MEMORY_KIB,
                        parallelism=ARGON2_PARALLELISM):
    """Argon2id 内存硬密钥派生（需要 argon2-cffi）。"""
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        raise CryptoError('Argon2id 加密需要安装 argon2-cffi: pip install argon2-cffi')
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hash_secret_raw(
        password, salt,
        time_cost=time_cost, memory_cost=memory_kib, parallelism=parallelism,
        hash_len=ARGON2_HASH_LEN, type=Type.ID, version=19,
    )


def _strict_json_int(value, name, minimum, maximum=None):
    if not isinstance(value, int) or isinstance(value, bool):
        raise CryptoError('%s 必须为整数' % name)
    if value < minimum or (maximum is not None and value > maximum):
        raise CryptoError('%s 越界' % name)
    return value


def _validate_payload_crypto_info(info, payload_size=None):
    """校验归档中可控的 KDF/AEAD 参数，防止资源耗尽和宽松 base64 解析。"""
    try:
        if not isinstance(info, dict) or info.get('algo', 'AES-256-GCM') != 'AES-256-GCM':
            raise ValueError
        salt = base64.b64decode(info['salt'], validate=True)
        prefix = base64.b64decode(info['nonce_prefix'], validate=True)
        chunk_size = _strict_json_int(info.get('chunk_size', CHUNK_SIZE),
                                      'chunk_size', 1, MAX_CRYPTO_CHUNK_SIZE)
        num_chunks = _strict_json_int(info.get('num_chunks'), 'num_chunks', 0,
                                      0xFFFFFFFF)
        kdf_name = info.get('kdf', KDF_PBKDF2)
        if len(salt) != _SALT_LEN or len(prefix) not in _VALID_NONCE_PREFIX_LENS:
            raise ValueError
        if kdf_name == KDF_PBKDF2:
            _strict_json_int(info.get('iterations', KDF_ITERATIONS),
                             'PBKDF2 iterations', 1, MAX_KDF_ITERATIONS)
        elif kdf_name == KDF_ARGON2ID:
            params = info.get('kdf_params')
            if not isinstance(params, dict):
                raise ValueError
            time_cost = _strict_json_int(params.get('time', ARGON2_TIME_COST),
                                         'Argon2id time_cost', 1, MAX_ARGON2_TIME_COST)
            memory_kib = _strict_json_int(params.get('memory', ARGON2_MEMORY_KIB),
                                          'Argon2id memory', 8, MAX_ARGON2_MEMORY_KIB)
            parallelism = _strict_json_int(params.get('parallelism', ARGON2_PARALLELISM),
                                           'Argon2id parallelism', 1,
                                           MAX_ARGON2_PARALLELISM)
            if memory_kib < 8 * parallelism:
                raise ValueError
        else:
            raise ValueError
        if payload_size is not None:
            # 密文长度 = 明文长度 + 每块 16 字节标签；除最后一块外，
            # 每个密文块固定为 chunk_size + 16 字节。
            expected_chunks = ((payload_size + chunk_size + 15)
                               // (chunk_size + 16)) if payload_size else 0
            if num_chunks != expected_chunks:
                raise ValueError
        return salt, prefix, chunk_size, num_chunks, kdf_name
    except CryptoError:
        raise
    except Exception:
        raise CryptoError('归档头中加密参数损坏或超出安全范围')


def derive_key_auto(password, salt, kdf=KDF_PBKDF2, iterations=KDF_ITERATIONS,
                    kdf_params=None):
    """按归档头中的 kdf 字段分发密钥派生；参数先做范围校验。"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if kdf == KDF_PBKDF2:
        iterations = _strict_json_int(iterations, 'PBKDF2 iterations',
                                      1, MAX_KDF_ITERATIONS)
        return derive_key(password, salt, iterations)
    if kdf == KDF_ARGON2ID:
        params = kdf_params or {}
        try:
            time_cost = _strict_json_int(params.get('time', ARGON2_TIME_COST),
                                         'Argon2id time_cost', 1, MAX_ARGON2_TIME_COST)
            memory_kib = _strict_json_int(params.get('memory', ARGON2_MEMORY_KIB),
                                          'Argon2id memory', 8, MAX_ARGON2_MEMORY_KIB)
            parallelism = _strict_json_int(params.get('parallelism', ARGON2_PARALLELISM),
                                           'Argon2id parallelism', 1,
                                           MAX_ARGON2_PARALLELISM)
            if memory_kib < 8 * parallelism:
                raise ValueError
        except (TypeError, ValueError, CryptoError):
            raise CryptoError('归档头中 Argon2id 参数损坏或超出安全范围')
        return derive_key_argon2id(password, salt, time_cost, memory_kib,
                                   parallelism)
    raise CryptoError('归档头中加密 KDF 不受支持: %r' % (kdf,))


def _nonce(prefix, counter):
    """nonce = 前缀 + 大端块序号，总长固定 _NONCE_LEN 字节。

    序号宽度由前缀长度决定：新归档 4 字节（上限 2^32-1 块，约 16 PiB
    明文，实际不可能达到）；旧归档 8 字节。序号超出宽度直接报错。
    """
    n = _NONCE_LEN - len(prefix)
    if n < 1 or counter < 0 or counter >= (1 << (8 * n)):
        raise CryptoError('加密块序号超出 nonce 可表示范围')
    return prefix + counter.to_bytes(n, 'big')


def encrypt_file(src_path, dst_path, password, chunk_size=CHUNK_SIZE,
                 progress=None, total=None, crypto='gcm', return_key=False):
    """加密 src_path → dst_path，返回可写入 JSON 头的 KDF 参数字典。

    crypto: 'gcm'（PBKDF2-HMAC-SHA256）或 'argon2id'（Argon2id 内存硬派生），
    两者载荷加密均为 AES-256-GCM，仅密钥派生方式不同。
    return_key=True 时返回 (info, key)，key 用于 .arhp 归档头的
    HMAC 认证（header_mac），避免为算 HMAC 再派生一次密钥（Argon2id 很贵）。
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if (not isinstance(chunk_size, int) or isinstance(chunk_size, bool)
            or not 1 <= chunk_size <= MAX_CRYPTO_CHUNK_SIZE):
        raise CryptoError('加密分块大小必须是 1 至 %d 字节' % MAX_CRYPTO_CHUNK_SIZE)
    crypto = (crypto or 'gcm').lower()
    if crypto not in _CRYPTO_ALGO_CHOICES:
        raise CryptoError('不支持的加密方案: %r（支持 %s）'
                          % (crypto, '/'.join(_CRYPTO_ALGO_CHOICES)))
    salt = os.urandom(_SALT_LEN)
    prefix = os.urandom(_NONCE_PREFIX_LEN)
    if crypto == 'argon2id':
        kdf_name = KDF_ARGON2ID
        kdf_params = {'time': ARGON2_TIME_COST,
                      'memory': ARGON2_MEMORY_KIB,
                      'parallelism': ARGON2_PARALLELISM}
        key = derive_key_argon2id(password, salt,
                                  time_cost=kdf_params['time'],
                                  memory_kib=kdf_params['memory'],
                                  parallelism=kdf_params['parallelism'])
    else:
        kdf_name = KDF_PBKDF2
        kdf_params = None
        key = derive_key(password, salt)
    aes = AESGCM(key)
    done = 0
    counter = 0
    with open(src_path, 'rb') as fin, open(dst_path, 'wb') as fout:
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            fout.write(aes.encrypt(_nonce(prefix, counter), chunk, None))
            counter += 1
            done += len(chunk)
            if progress and total:
                progress(done, total)
    info = {
        'algo': 'AES-256-GCM',
        'kdf': kdf_name,
        'salt': base64.b64encode(salt).decode('ascii'),
        'nonce_prefix': base64.b64encode(prefix).decode('ascii'),
        'chunk_size': chunk_size,
        'num_chunks': counter,
    }
    if kdf_params is not None:
        info['kdf_params'] = kdf_params
    else:
        info['iterations'] = KDF_ITERATIONS
    if return_key:
        return info, key
    return info


def _header_mac_hex(key, hdr):
    """.arhp 加密归档头的 HMAC-SHA256 认证值（防篡改）。

    认证对象是规范化头 JSON（与 header_crc 同一字节序列，均排除
    header_crc / header_mac 字段自身）。未加密归档没有密钥可用，头仍只靠
    CRC32 + RS 保护——两者都是线性码，只能抵御随机损坏，不能防恶意篡改。
    """
    import hashlib
    import hmac
    return hmac.new(key, _canonical_header_json(hdr),
                    hashlib.sha256).hexdigest()


def decrypt_file(src_path, dst_path, kdf_info, password,
                 progress=None, total=None, header_auth=None):
    """解密 src_path → dst_path。密码错误或数据被篡改时抛 CryptoError。

    header_auth: .arhp 加密归档的头认证（(header_mac, 规范化头 JSON 字节)）。
    提供时先用派生密钥校验 HMAC，头被篡改立即报错，不进入解密。
    异常处理收窄：只有 GCM 认证失败（InvalidTag）才映射为“密码错误或
    数据被篡改”，内存错误/IO 故障等真实异常原样抛出。
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, prefix, chunk_size, declared_chunks, kdf_name = \
        _validate_payload_crypto_info(kdf_info)
    iterations = kdf_info.get('iterations', KDF_ITERATIONS)
    kdf_params = kdf_info.get('kdf_params')
    try:
        key = derive_key_auto(password, salt, kdf=kdf_name,
                              iterations=iterations, kdf_params=kdf_params)
    except CryptoError:
        raise
    except Exception:
        raise CryptoError('归档头中加密参数损坏')
    if header_auth is not None:
        import hashlib
        import hmac
        mac_hex, canonical = header_auth
        actual = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(actual, str(mac_hex)):
            raise CryptoError('归档头认证失败（HMAC 不匹配）：头数据被篡改'
                              '或密码错误')
    aes = AESGCM(key)
    src_size = os.path.getsize(src_path)
    # AES-GCM 无填充：密文 = 明文 + 16 字节标签，长度任意（不必是 16 的倍数）。
    # 分块边界：除最后一块外每块密文长度固定为 chunk_size + 16。
    n_chunks = -(-src_size // (chunk_size + 16)) if src_size else 0
    if declared_chunks != n_chunks:
        raise CryptoError('密文分块数量与归档头声明不一致')
    # 块数还必须在该前缀长度可表示的序号范围内，否则视为被篡改
    if n_chunks > (1 << (8 * (_NONCE_LEN - len(prefix)))) - 1:
        raise CryptoError('密文长度异常，归档被篡改或严重损坏')
    done = 0
    try:
        with open(src_path, 'rb') as fin, open(dst_path, 'wb') as fout:
            for i in range(n_chunks):
                if i < n_chunks - 1:
                    expect = chunk_size + 16
                else:
                    expect = src_size - (n_chunks - 1) * (chunk_size + 16)
                blob = fin.read(expect)
                if len(blob) != expect:
                    raise CryptoError('密文长度异常，归档被截断')
                plain = aes.decrypt(_nonce(prefix, i), blob, None)
                fout.write(plain)
                done += len(plain)
                if progress and total:
                    progress(done, total)
    except CryptoError:
        raise
    except InvalidTag:
        raise CryptoError('解密失败：密码错误或数据被篡改')
    return dst_path


# ======================================================================
# 小块数据加密（.arh2 中心化目录专用）
# ======================================================================

def _encrypt_blob(blob, password, crypto='gcm'):
    """加密中心化目录：独立盐/nonce，KDF 与载荷加密选项保持一致。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if isinstance(password, str):
        password = password.encode('utf-8')
    crypto = (crypto or 'gcm').lower()
    if crypto not in _CRYPTO_ALGO_CHOICES:
        raise CryptoError('不支持的中心目录加密方案: %r' % crypto)
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    if crypto == 'argon2id':
        kdf_params = {'time': ARGON2_TIME_COST,
                      'memory': ARGON2_MEMORY_KIB,
                      'parallelism': ARGON2_PARALLELISM}
        key = derive_key_argon2id(password, salt,
                                  time_cost=kdf_params['time'],
                                  memory_kib=kdf_params['memory'],
                                  parallelism=kdf_params['parallelism'])
        info = {'algo': 'AES-256-GCM', 'kdf': KDF_ARGON2ID,
                'kdf_params': kdf_params}
    else:
        key = derive_key(password, salt)
        info = {'algo': 'AES-256-GCM', 'kdf': KDF_PBKDF2,
                'iterations': KDF_ITERATIONS}
    info.update({'salt': base64.b64encode(salt).decode('ascii'),
                 'nonce': base64.b64encode(nonce).decode('ascii')})
    return AESGCM(key).encrypt(nonce, blob, None), info


def _validate_blob_crypto_info(info):
    """校验中心目录 AEAD 参数。"""
    try:
        if not isinstance(info, dict) or info.get('algo', 'AES-256-GCM') != 'AES-256-GCM':
            raise ValueError
        salt = base64.b64decode(info['salt'], validate=True)
        nonce = base64.b64decode(info['nonce'], validate=True)
        if len(salt) != _SALT_LEN or len(nonce) != _NONCE_LEN:
            raise ValueError
        kdf = info.get('kdf', KDF_PBKDF2)
        if kdf == KDF_PBKDF2:
            _strict_json_int(info.get('iterations', KDF_ITERATIONS),
                             '中心目录 PBKDF2 iterations', 1,
                             MAX_KDF_ITERATIONS)
            params = None
        elif kdf == KDF_ARGON2ID:
            params = info.get('kdf_params')
            if not isinstance(params, dict):
                raise ValueError
            time_cost = _strict_json_int(params.get('time', ARGON2_TIME_COST),
                                         '中心目录 Argon2id time_cost', 1,
                                         MAX_ARGON2_TIME_COST)
            memory_kib = _strict_json_int(params.get('memory', ARGON2_MEMORY_KIB),
                                          '中心目录 Argon2id memory', 8,
                                          MAX_ARGON2_MEMORY_KIB)
            parallelism = _strict_json_int(params.get('parallelism', ARGON2_PARALLELISM),
                                            '中心目录 Argon2id parallelism', 1,
                                            MAX_ARGON2_PARALLELISM)
            if memory_kib < 8 * parallelism:
                raise ValueError
        else:
            raise ValueError
        return salt, nonce, kdf
    except Exception:
        raise CryptoError('中心目录加密参数损坏或超出安全范围')


def _decrypt_blob(ct, info, password):
    """解密中心化目录。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce, kdf = _validate_blob_crypto_info(info)
    iterations = info.get('iterations', KDF_ITERATIONS)
    kdf_params = info.get('kdf_params')
    if isinstance(password, str):
        password = password.encode('utf-8')
    try:
        key = derive_key_auto(password, salt, kdf=kdf,
                              iterations=iterations, kdf_params=kdf_params)
        return AESGCM(key).decrypt(nonce, ct, None)
    except CryptoError:
        raise
    except Exception:
        raise CryptoError('中心目录解密失败：密码错误或数据被篡改')


# ======================================================================
# 归档格式常量
# ======================================================================

# .arh2（ARH2 v1）：魔数 + JSON 头 + 数据块 + RS 校验块 + 受保护头部 +
# 受保护的中心化目录 + 自描述尾注。头部和目录均使用 Cauchy-MDS RS。
# .arhp（ARHP v2/v3）：魔数 + JSON 头 + 数据块 + RS 校验块；
# v3（v1.1.0.0+ 创建）在 parity 之后追加头分块 + 头校验块 + 自描述尾注。

ARH2_MAGIC = b'ARH2\x00\x01'
ARH2_TRAILER_MAGIC = b'ARH2\x00\x02'
ARHP_MAGIC = b'ARHP\x00\x01'
ARHP_TRAILER_MAGIC = b'ARHP\x00\x02'
MAX_SHARDS = 255  # GF(256) 码字长度上限
MAX_HEADER = 64 * 1024 * 1024  # 头长度上限，防止恶意头
MAX_BLOCK_SIZE = 256 * 1024 * 1024  # 单次分块读写的安全上限
MAX_CRYPTO_CHUNK_SIZE = 256 * 1024 * 1024
MAX_KDF_ITERATIONS = 2_000_000

# 压缩/解压归档的内存限制：分块校验、Reed-Solomon 编解码全部按块/按列
# 切片流式进行，载荷处理工作集不超过该值。注意 mem_limit 只是流式处理
# 工作集的上限：bytes.translate/_xor_into 的临时对象、Python 对象管理开销、
# 头与中心化目录的整块保护处理（HEADER_BLOCK_SIZE 分块 + JSON 序列化）
# 都会带来额外的进程内存，实际峰值会高于该值。GUI 提供 16M-1024M 档位，
# 默认 128M。
MIN_MEM_LIMIT = 16 * 1024 * 1024
MAX_MEM_LIMIT = 1024 * 1024 * 1024
DEFAULT_MEM_LIMIT = 128 * 1024 * 1024


def _check_mem_limit(mem_limit):
    """校验并返回内存限制（字节）；越界直接报错，不静默改写。"""
    try:
        mem_limit = int(mem_limit)
    except (TypeError, ValueError):
        raise ArchiveError('内存限制必须是整数（字节数）')
    if not MIN_MEM_LIMIT <= mem_limit <= MAX_MEM_LIMIT:
        raise ArchiveError('内存限制超出支持范围: %s（允许 %s - %s，默认 %s）' % (
            mem_limit, _fmt_size(MIN_MEM_LIMIT), _fmt_size(MAX_MEM_LIMIT),
            _fmt_size(DEFAULT_MEM_LIMIT)))
    return mem_limit

# 头保护参数：头 JSON 按固定 64 KiB 等长分块（头通常远小于 1 MiB，
# 分块数 HB 很小）；头校验块数量取 HB 的 20%（下限 2、上限 16），
# 足以承受多块同时损坏；HB + HP 上限同样受 MAX_SHARDS 约束。
HEADER_BLOCK_SIZE = 64 * 1024
MAX_HEADER_PARITY = 16
MAX_TRAILER = 1024 * 1024  # 尾注长度上限（含 10 字节固定前缀）

# 头自校验字段：值为除该字段外整个头规范化 JSON 的 CRC32。
# .arhp 加密归档另含 header_mac（HMAC-SHA256），同样排除在规范化
# JSON 之外（认证值不能覆盖自身）；data_offset 是读取端注入的内存定位
# 字段（非归档内容），也必须排除，否则读取端重算的认证字节与写入端
# 不一致。
_HEADER_CRC_FIELD = 'header_crc'
_HEADER_MAC_FIELD = 'header_mac'
# data_offset / format / _trailer* 是读取端注入的内存定位字段（非归档内容），
# 必须排除在规范化 JSON 之外，否则读取端重算的 CRC/HMAC 与写入端不一致。
_HEADER_EXCLUDED_FIELDS = (_HEADER_CRC_FIELD, _HEADER_MAC_FIELD,
                           'data_offset', 'format', '_trailer',
                           '_trailer_len')

_WIN_ABS = re.compile(r'^[a-zA-Z]:[\\/]')


def _crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def _canonical_header_json(hdr):
    """头自校验/头 HMAC 认证用的规范化 JSON 字节：排除 header_crc 与
    header_mac 字段自身，键排序与分隔符固定，保证同一份头内容生成同样的
    字节——写入端与读取端各自重算即可得到逐字节一致的结果。"""
    h = {k: v for k, v in hdr.items() if k not in _HEADER_EXCLUDED_FIELDS}
    return json.dumps(h, separators=(',', ':'), sort_keys=True).encode('utf-8')


def _rep(progress, msg, pct):
    if progress:
        progress(msg, int(pct))


def _layout(payload_size, redundancy, block_size):
    """计算 (N 数据块数, K 校验块数, block_size)，N+K 不超过 255。"""
    payload_size = max(payload_size, 1)
    redundancy = max(0, min(50, int(redundancy)))
    block_size = int(block_size)
    if not 1 <= block_size <= MAX_BLOCK_SIZE:
        raise ArchiveError('分块大小超出支持范围: %s' % block_size)
    while True:
        n = -(-payload_size // block_size)
        k = max(1, int(round(n * redundancy / 100))) if redundancy else 0
        if redundancy and k < 1:
            k = 1
        if n + k <= MAX_SHARDS:
            return n, k, block_size
        if block_size >= MAX_BLOCK_SIZE:
            raise ArchiveError('归档过大，即使使用最大安全分块也无法生成恢复数据')
        block_size = min(block_size * 2, MAX_BLOCK_SIZE)


def _fmt_size(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return '%.1f %s' % (n, unit) if unit != 'B' else '%d B' % n
        n /= 1024


def _add_paths(tar, paths, collect=None):
    """把文件/目录加入 tar，并安全保留符号链接（包括目录符号链接）。

    collect 非 None 时同时收集 .arh2 中心目录元数据。符号链接目录必须
    作为链接本身存储，不能把 os.walk 对顶层目录链接的遍历结果打包进去。
    """
    def _emit(full, arcname):
        st = os.lstat(full)
        is_link = stat.S_ISLNK(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)
        normalized = _normalize_member_name(arcname).rstrip('/')
        if not normalized or normalized == '.':
            raise ArchiveError('输入路径无法生成有效归档名称: %r' % arcname)
        if collect is not None:
            collect.append({
                'name': normalized,
                'is_dir': is_dir,
                'size': 0 if (is_dir or is_link) else st.st_size,
                'mtime': int(st.st_mtime),
                'mode': st.st_mode & 0o7777,
                'linkname': os.readlink(full) if is_link else None,
            })
        tar.add(full, arcname=normalized, recursive=False)

    for p in paths:
        p = os.path.normpath(p)
        if os.path.islink(p):
            _emit(p, os.path.basename(p))
        elif os.path.isdir(p):
            base = os.path.dirname(os.path.abspath(p))
            for root, dirs, files in os.walk(p, topdown=True, followlinks=False):
                dirs.sort()
                files.sort()
                _emit(root, os.path.relpath(root, base))
                # os.walk 把目录符号链接放在 dirs 中但不会进入；显式存为链接。
                for name in list(dirs):
                    full = os.path.join(root, name)
                    if os.path.islink(full):
                        _emit(full, os.path.relpath(full, base))
                        dirs.remove(name)
                for name in files:
                    full = os.path.join(root, name)
                    _emit(full, os.path.relpath(full, base))
        else:
            _emit(p, os.path.basename(p))


def _path_key(path):
    """跨平台规范化路径：统一大小写并解析已存在的符号链接。"""
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _path_contains(parent, child):
    """child 是否等于 parent，或位于 parent 目录树内。"""
    parent_key, child_key = _path_key(parent), _path_key(child)
    if parent_key == child_key:
        return True
    try:
        return os.path.commonpath((parent_key, child_key)) == parent_key
    except ValueError:
        # Windows 不同盘符没有公共路径
        return False


def _check_paths(paths):
    """打包前统一校验输入路径（全部格式共用）。

    检查存在性（含符号链接）、重复、包含关系，以及按大小写折叠预检归档名
    冲突——不同目录下的同名条目在归档内会互相覆盖，必须在打包前拒绝。
    """
    missing = [p for p in paths if not os.path.lexists(p)]
    if missing:
        raise ArchiveError('以下输入路径不存在: %s' % ', '.join(missing))
    paths = [os.path.normpath(p) for p in paths]
    keys = [_path_key(p) for p in paths]
    if len(set(keys)) != len(keys):
        raise ArchiveError('输入路径有重复')
    # 同时添加“目录”和“目录内的条目”会让归档中出现重复子树。
    for i, p in enumerate(paths):
        if not os.path.isdir(p):
            continue
        for j, q in enumerate(paths):
            if i != j and _path_contains(p, q):
                raise ArchiveError('输入路径存在包含关系: %r 已包含 %r' % (p, q))

    # 在打包前检测完整归档路径冲突。必须按大小写折叠检查，因为归档
    # 可能在大小写不敏感的 Windows/macOS 文件系统上解压。
    names = {}

    def register(full, arcname, is_dir):
        name = _normalize_member_name(arcname).rstrip('/')
        key = name.casefold()
        if not name or name == '.' or key in names:
            raise ArchiveError('输入路径生成重复或无效的归档名称: %r' % name)
        parts = key.split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            if parent in names and not names[parent]:
                raise ArchiveError('输入路径存在文件/目录层级冲突: %r' % name)
        if not is_dir:
            prefix = key + '/'
            if any(existing.startswith(prefix) for existing in names):
                raise ArchiveError('输入路径存在文件/目录层级冲突: %r' % name)
        names[key] = bool(is_dir)

    for p in paths:
        if os.path.islink(p):
            register(p, os.path.basename(p), False)
        elif os.path.isdir(p):
            base = os.path.dirname(os.path.abspath(p))
            for root, dirs, files in os.walk(p, topdown=True, followlinks=False):
                dirs.sort()
                files.sort()
                register(root, os.path.relpath(root, base), True)
                for name in list(dirs):
                    full = os.path.join(root, name)
                    if os.path.islink(full):
                        register(full, os.path.relpath(full, base), False)
                        dirs.remove(name)
                for name in files:
                    full = os.path.join(root, name)
                    register(full, os.path.relpath(full, base), False)
        else:
            register(p, os.path.basename(p), False)
    return paths


def _check_output_location(paths, out_path):
    """避免输出归档把自身（或旧版本自身）也打包进去。"""
    if os.path.isdir(out_path):
        raise ArchiveError('输出路径不能是目录: %s' % out_path)
    out_key = _path_key(out_path)
    for p in paths:
        same_file = False
        if os.path.exists(out_path) and os.path.exists(p):
            try:
                same_file = os.path.samefile(out_path, p)
            except OSError:
                same_file = False
        if same_file or _path_key(p) == out_key:
            raise ArchiveError('输出路径不能与输入路径相同（包括硬链接）: %s' % out_path)
        if os.path.isdir(p) and _path_contains(p, out_path):
            raise ArchiveError('输出路径不能位于输入目录内: %s' % out_path)


# ---------------------------------------------------------------- 分卷 (volumes)

# 卷号 3 位以上数字：1-999 用三位零填充（.001-.999），1000 起用实际数字
# （.1000、.1001...），与 find_volumes 的扫描对应。
_VOL_RE = re.compile(r'^(.*)\.(\d{3,})$')


def _vol_name(base, i):
    """第 i 个分卷的文件名：1-999 三位零填充，1000 起直接用实际数字。"""
    return '%s.%03d' % (base, i) if i < 1000 else '%s.%d' % (base, i)


def split_volumes(archive_path, volume_size, progress=None):
    """把归档拆分为 name.ext.001 / .002 / ...，不覆盖任何既有分卷。

    卷号超过 999 时自动改用四位命名（.1000 起）。只有全部分卷写入成功
    后才删除原归档；失败时清理本次生成的分卷，保留原始单文件归档。
    目标位置已存在同名前缀分卷时拒绝拆分，避免覆盖或混合旧分卷。
    """
    volume_size = int(volume_size)
    if volume_size < 1:
        raise ArchiveError('分卷大小必须是正整数')
    total = os.path.getsize(archive_path)
    if total <= volume_size:
        return 0
    count = -(-total // volume_size)
    parent = os.path.dirname(os.path.abspath(archive_path)) or os.curdir
    prefix = os.path.basename(archive_path) + '.'
    existing_parts = [entry.path for entry in os.scandir(parent)
                      if entry.name.startswith(prefix)
                      and entry.name[len(prefix):].isdigit()
                      and len(entry.name[len(prefix):]) >= 3]
    if existing_parts:
        raise ArchiveError('检测到已有同名前缀分卷，拒绝覆盖或混合旧分卷: %s'
                           % ', '.join(existing_parts[:5]))
    created = []
    done = 0
    try:
        with open(archive_path, 'rb') as fin:
            for idx in range(1, count + 1):
                chunk = fin.read(volume_size)
                if not chunk:
                    raise ArchiveError('分卷源文件读取提前结束')
                vol = _vol_name(archive_path, idx)
                # xb 是原子排他创建，避免并发时覆盖他人文件。
                with open(vol, 'xb') as f:
                    created.append(vol)
                    f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())
                done += len(chunk)
                _rep(progress, '写入分卷 %d/%d（%s）' % (idx, count, vol),
                     int(95 * done / total))
            if fin.read(1):
                raise ArchiveError('分卷源文件在拆分期间发生变化')
        os.unlink(archive_path)
    except Exception:
        for p in created:
            try:
                os.unlink(p)
            except OSError:
                pass
        raise
    _rep(progress, '已拆分为 %d 个分卷' % count, 100)
    return count


def find_volumes(path):
    """定位并校验连续分卷；发现序号缺口时拒绝静默忽略后续分卷。

    若 path 属于多分卷归档（name.ext.NNN 之一，或基名 name.ext），
    返回按顺序排列的分卷路径列表；否则返回 None。
    """
    base = str(path)
    m = _VOL_RE.match(base)
    if m:
        base = m.group(1)
    elif os.path.isfile(base):
        # 完整归档文件存在时按普通文件处理，即使旁边恰有 .001 文件
        return None
    parent = os.path.dirname(os.path.abspath(base)) or os.curdir
    prefix = os.path.basename(base) + '.'
    numbers = []
    for entry in os.scandir(parent):
        if not entry.is_file(follow_symlinks=False) or not entry.name.startswith(prefix):
            continue
        suffix = entry.name[len(prefix):]
        if len(suffix) >= 3 and suffix.isdigit():
            numbers.append(int(suffix))
    numbers.sort()
    if not numbers:
        return None
    if numbers[0] != 1 or numbers != list(range(1, numbers[-1] + 1)):
        raise ArchiveError('分卷序号不连续或缺少 .001 起始分卷: %s' % base)
    return [_vol_name(base, i) for i in numbers]


class _ArchiveInput:
    """上下文管理器：path 为分卷归档时先合并为临时文件再交给调用方。

    用法:
        with _ArchiveInput(path, progress) as real_path:
            ... 处理 real_path ...
    退出时自动删除合并出的临时文件。
    """

    def __init__(self, path, progress=None):
        self.path = path
        self.progress = progress
        self.real_path = path
        self._tmp = None

    def __enter__(self):
        vols = find_volumes(self.path)
        if not vols:
            return self.real_path
        base = _VOL_RE.match(str(self.path))
        base = base.group(1) if base else str(self.path)
        ext = os.path.splitext(base)[1] or '.bin'
        fd, self._tmp = tempfile.mkstemp(prefix='.arhp_join_', suffix=ext,
                                         dir=app_temp_dir())
        os.close(fd)
        total = sum(os.path.getsize(v) for v in vols)
        done = 0
        _rep(self.progress, '合并 %d 个分卷...' % len(vols), 2)
        with open(self._tmp, 'wb') as out:
            for i, v in enumerate(vols):
                with open(v, 'rb') as f:
                    shutil.copyfileobj(f, out, 1 << 20)
                done += os.path.getsize(v)
                _rep(self.progress, '合并分卷 %d/%d' % (i + 1, len(vols)),
                     2 + int(5 * done / max(total, 1)))
        self.real_path = self._tmp
        return self.real_path

    def __exit__(self, *exc):
        if self._tmp:
            try:
                os.unlink(self._tmp)
            except OSError:
                pass
        return False


# ---------------------------------------------------------------- 创建

def _protect_blob(blob, what='数据', codec=CODEC_CAUCHY):
    """对一块 JSON 字节做 Reed-Solomon 保护（.arh2 归档头/中心化目录通用）。

    返回 (blocks, parity, layout)：
    - blocks: HB 个等长（HEADER_BLOCK_SIZE）数据块，末块零填充；
    - parity: HP 个校验块（同一 RS 编码，与载荷分片相互独立）；
    - layout: 写入尾注的自描述布局（codec/crc/len/bs/hb/hp/crcs/pcrc，
      读取时从文件尾自定位并逐块 CRC 校验，损坏则 RS 恢复）。
    """
    hb_size = HEADER_BLOCK_SIZE
    orig_len = len(blob)
    orig_crc = _crc(blob)  # 须在零填充前计算：比对对象是原始字节
    hb = -(-orig_len // hb_size)
    if orig_len % hb_size:
        blob = blob + b'\x00' * (hb * hb_size - orig_len)
    hp = max(2, min(MAX_HEADER_PARITY, (hb + 4) // 5))  # ≈20%，2–16 块
    if hb + hp > MAX_SHARDS:
        raise ArchiveError('%s过大，无法生成恢复数据' % what)
    blocks = [blob[i * hb_size:(i + 1) * hb_size] for i in range(hb)]
    rs = ReedSolomon()
    parity = [bytes(p) for p in rs.encode(blocks, hp, codec=codec)] if hp else []
    return blocks, parity, {
        'crc': orig_crc,   # 原始字节的 CRC32，读取时先比对
        'len': orig_len,
        'bs': hb_size,
        'hb': hb,
        'hp': hp,
        'codec': codec,
        'crcs': [_crc(b) for b in blocks],
        'pcrc': [_crc(p) for p in parity],
    }


def _protect_header_arhp(hj):
    """对 .arhp 头 JSON 字节做 Reed-Solomon 保护（v3 格式，旧版兼容）。

    返回 (header_blocks, header_parity, trailer_dict)：布局使用旧版 arhp
    的扁平键名（header_crc/hlen/hbs/hb/hp/h_crc/hp_crc），Vandermonde
    编码——arhp 1.1.0.2 可直接读取新创建的 .arhp 归档。
    """
    hb_size = HEADER_BLOCK_SIZE
    orig_len = len(hj)
    orig_crc = _crc(hj)  # 须在零填充前计算：比对对象是头 JSON 原始字节
    hb = -(-orig_len // hb_size)
    if orig_len % hb_size:
        hj = hj + b'\x00' * (hb * hb_size - orig_len)
    hp = max(2, min(MAX_HEADER_PARITY, (hb + 4) // 5))  # ≈20%，2–16 块
    if hb + hp > MAX_SHARDS:
        raise ArchiveError('归档头过大，无法生成头恢复数据')
    blocks = [hj[i * hb_size:(i + 1) * hb_size] for i in range(hb)]
    rs = ReedSolomon()
    parity = [bytes(p) for p in rs.encode(blocks, hp, codec=CODEC_VANDERMONDE)] if hp else []
    return blocks, parity, {
        'header_crc': orig_crc,  # 头 JSON 原始字节的 CRC32，读取时先比对
        'hlen': orig_len,
        'hbs': hb_size,
        'hb': hb,
        'hp': hp,
        'h_crc': [_crc(b) for b in blocks],
        'hp_crc': [_crc(p) for p in parity],
    }


def _write_parity(comp, parity_tmp, n, k, bs, payload_size, mem_limit,
                  progress, codec):
    """流式生成 k 个 Reed-Solomon 校验块并写入 parity_tmp。

    内存放得下就单遍累计（数据读一遍）；放不下就把校验块按列切片多遍
    累计（每遍完整读一遍数据，但单遍内存 ≤ mem_limit）。RS 逐字节位置
    独立，切片累计与整块累计数学上等价；最后一块短于 block_size 的部分
    按零填充参与运算（与解码端约定一致）。
    """
    rs = ReedSolomon()
    if k * bs + min(bs, mem_limit) <= mem_limit:
        # 单遍模式：k 个校验块全量驻留内存 + 一个读缓冲
        parity = [bytearray(bs) for _ in range(k)]
        chunk = max(1, min(bs, mem_limit - k * bs))
        with open(comp, 'rb') as fin:
            for i in range(n):
                real = min(bs, payload_size - i * bs)
                pos = 0
                while pos < real:
                    c = fin.read(min(chunk, real - pos))
                    if not c:
                        raise ArchiveError('读取压缩载荷失败（文件被截断）')
                    for j in range(k):
                        coef = rs.coeff_any(codec, j, i, n)
                        if coef:
                            _xor_into(parity[j], pos,
                                      c.translate(rs.table(coef)))
                    pos += len(c)
        with open(parity_tmp, 'wb') as pout:
            for j in range(k):
                pout.write(bytes(parity[j]))
        return
    # 分片模式：列切片多遍累计，工作集 = k 个切片缓冲 + 1 个读缓冲
    slice_len = max(1, mem_limit // (k + 1))
    total_slices = -(-bs // slice_len)
    with open(comp, 'rb') as fin, open(parity_tmp, 'w+b') as pout:
        pout.truncate(k * bs)
        for sn, s0 in enumerate(range(0, bs, slice_len)):
            L = min(slice_len, bs - s0)
            acc = [bytearray(L) for _ in range(k)]
            for i in range(n):
                real = min(bs, payload_size - i * bs)
                if s0 >= real:
                    continue
                fin.seek(i * bs + s0)
                c = _read_exact(fin, min(L, real - s0))
                for j in range(k):
                    coef = rs.coeff_any(codec, j, i, n)
                    if coef:
                        _xor_into(acc[j], 0, c.translate(rs.table(coef)))
            for j in range(k):
                pout.seek(j * bs + s0)
                pout.write(bytes(acc[j]))
            _rep(progress, '生成恢复数据（分片 %d/%d）' % (sn + 1, total_slices),
                 80 + int(8 * (sn + 1) / total_slices))


def _read_exact(f, size):
    """从文件对象恰好读 size 字节；不足时按实际长度返回。"""
    buf = bytearray()
    while len(buf) < size:
        chunk = f.read(size - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _xor_into(dst, pos, t):
    """dst[pos:pos+len(t)] ^= t（小端整数异或，C 速度；len(t) ≤ len(dst)-pos）。"""
    n = len(t)
    if n:
        cur = bytes(dst[pos:pos + n])
        dst[pos:pos + n] = (int.from_bytes(cur, 'little')
                            ^ int.from_bytes(t, 'little')).to_bytes(n, 'little')


def _write_archive_atomically(out_path, write_body):
    """在输出目录先写临时文件，成功后原子替换最终路径。

    write_body(out_file) 负责把完整归档写入临时文件；任何失败都保留原
    有文件（若有），临时文件被清理。新归档恢复常见文件权限，已有普通
    文件则保留其权限。
    """
    out_parent = os.path.dirname(os.path.abspath(out_path)) or os.curdir
    fd_out, out_tmp = tempfile.mkstemp(prefix='.arhp_build_', dir=out_parent)
    os.close(fd_out)
    try:
        try:
            old_mode = os.lstat(out_path).st_mode
            output_mode = stat.S_IMODE(old_mode) if stat.S_ISREG(old_mode) else 0o644
        except OSError:
            output_mode = 0o644
        os.chmod(out_tmp, output_mode)
        with open(out_tmp, 'wb') as out:
            write_body(out)
            out.flush()
            os.fsync(out.fileno())
        # 成功生成完整文件后再替换最终路径；失败时原归档保持不变。
        os.replace(out_tmp, out_path)
        out_tmp = None
    finally:
        if out_tmp is not None:
            try:
                os.unlink(out_tmp)
            except OSError:
                pass


def _stage_payload(paths, tmpdir, level, collect=None):
    """打包（可选 zstd 压缩）为载荷文件，返回 (comp_path, compression)。"""
    compression = 'store' if level == 0 else 'zstd'
    comp = os.path.join(tmpdir, 'payload.bin')
    try:
        with open(comp, 'wb') as raw:
            if compression == 'zstd':
                with open_writer(raw, level) as zw, \
                     tarfile.open(fileobj=zw, mode='w|') as tar:
                    _add_paths(tar, paths, collect=collect)
            else:
                with tarfile.open(fileobj=raw, mode='w|') as tar:
                    _add_paths(tar, paths, collect=collect)
    except ImportError as e:
        raise ArchiveError(str(e))
    return comp, compression


def _crypto_encrypt(src, dst, password, progress, crypto='gcm',
                    return_key=False):
    total = os.path.getsize(src)
    return encrypt_file(
        src, dst, password,
        progress=lambda d, t: _rep(progress, '加密中...',
                                   15 + 8 * d // max(t, 1)),
        total=total, crypto=crypto, return_key=return_key)


def _build_arh2(paths, out_path, level=9, redundancy=3, block_size=1 << 20,
                  password=None, crypto='gcm', cd_encrypt=False,
                  progress=None, mem_limit=DEFAULT_MEM_LIMIT):
    """创建 .arh2 归档（Cauchy-MDS RS + 中心化目录，目录可选加密）。

    与 arh2 1.0.0.2 创建的归档完全兼容。分块与恢复数据生成流式进行，
    载荷处理工作集不超过 mem_limit（进程总内存另含对象/元数据开销）。
    """
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    redundancy = min(max(int(redundancy), 0), 50)
    block_size = max(int(block_size), 4096)
    level = int(level)
    if not 0 <= level <= 22:
        raise ArchiveError('压缩级别必须是 0-22 的整数')
    # 中间产物统一放在程序临时目录（%LOCALAPPDATA%\MienArch\ARHP），
    # 而不是输出目录，避免污染用户选择的位置。
    tmpdir = tempfile.mkdtemp(prefix='.arhp_', dir=app_temp_dir())
    try:
        _rep(progress, '打包%s中...' % ('' if level == 0 else '并 Zstd 压缩'), 3)
        members = []  # .arh2 中心化目录的条目元数据（_add_paths 收集）
        comp, compression = _stage_payload(paths, tmpdir, level,
                                           collect=members)

        encrypted = bool(password)
        if encrypted:
            kdf_label = 'Argon2id' if (crypto or 'gcm').lower() == 'argon2id' \
                else 'PBKDF2'
            _rep(progress, 'AES-256-GCM 加密中（密钥派生: %s）...' % kdf_label, 15)
            enc = os.path.join(tmpdir, 'payload.enc')
            kdf_info = _crypto_encrypt(comp, enc, password, progress,
                                       crypto=crypto)
            os.replace(enc, comp)
        else:
            kdf_info = None

        payload_size = os.path.getsize(comp)
        method = 'rs'
        n, k, bs = _layout(payload_size, redundancy, block_size)
        if bs != block_size:
            # 自动调整分块大小时明确告知，不再静默改写
            _rep(progress, '分块数超过 %d 上限，分块大小已自动增大到 %s'
                 % (MAX_SHARDS, _fmt_size(bs)), 24)

        hdr = {
            'version': 1,
            'rs_codec': CODEC_CAUCHY,
            'method': method,
            'compression': compression,
            'zstd_level': level,
            'encrypted': encrypted,
            'crypto': kdf_info,
            'block_size': bs,
            'num_blocks': n,
            'num_parity': k,
            'payload_size': payload_size,
            'block_crc': [],
            'block_len': [],
            'parity_crc': [],
        }

        if k:
            _rep(progress, '分块并生成恢复数据...', 25)
        else:
            _rep(progress, '分块中...', 25)
        blocks_tmp = os.path.join(tmpdir, 'blocks.bin')
        parity_tmp = os.path.join(tmpdir, 'parity.bin')
        written = 0
        # 流式分块：读缓冲 ≤ mem_limit，CRC 增量计算，不整载单块
        io_chunk = max(1, min(bs, mem_limit))
        with open(comp, 'rb') as fin, open(blocks_tmp, 'wb') as fout:
            for i in range(n):
                real = min(bs, payload_size - i * bs)
                crc = 0
                got = 0
                while got < real:
                    chunk = fin.read(min(io_chunk, real - got))
                    if not chunk:
                        raise ArchiveError('读取压缩载荷失败（文件被截断）')
                    crc = zlib.crc32(chunk, crc)
                    fout.write(chunk)
                    got += len(chunk)
                hdr['block_crc'].append(crc & 0xFFFFFFFF)
                hdr['block_len'].append(real)
                written += real
                _rep(progress, '处理分块 %d/%d' % (i + 1, n),
                     25 + int(60 * written / max(payload_size, 1)))
            if written != payload_size or fin.read(1):
                raise ArchiveError('载荷在分块期间发生变化，已中止创建归档')
        if k:
            _write_parity(comp, parity_tmp, n, k, bs, payload_size,
                          mem_limit, progress, CODEC_CAUCHY)
            with open(parity_tmp, 'rb') as pf:
                for j in range(k):
                    crc = 0
                    got = 0
                    while got < bs:
                        chunk = pf.read(min(io_chunk, bs - got))
                        if not chunk:
                            break
                        crc = zlib.crc32(chunk, crc)
                        got += len(chunk)
                    hdr['parity_crc'].append(crc & 0xFFFFFFFF)

        # 头自校验：在所有头字段就绪后计算 CRC32
        hdr[_HEADER_CRC_FIELD] = _crc(_canonical_header_json(hdr))

        def _body(out):
            out.write(ARH2_MAGIC)
            hj = json.dumps(hdr, separators=(',', ':')).encode('utf-8')
            out.write(struct.pack('>Q', len(hj)))
            out.write(hj)
            with open(blocks_tmp, 'rb') as fin:
                shutil.copyfileobj(fin, out, 1 << 20)
            if k:
                with open(parity_tmp, 'rb') as pf:
                    shutil.copyfileobj(pf, out, 1 << 20)
            # 归档头 RS 保护——头分块 + 头校验块 + 自描述尾注
            _rep(progress, '生成归档头恢复数据...', 91)
            hblocks, hparity, hinfo = _protect_blob(hj, '归档头',
                                                    codec=CODEC_CAUCHY)
            for b in hblocks:
                out.write(b)
            for p in hparity:
                out.write(p)
            # 中心化目录（可选加密 + RS 保护），位于头保护区之后
            _rep(progress, '生成中心化目录...', 94)
            cj = json.dumps(members, separators=(',', ':')).encode('utf-8')
            cd_crypto = None
            if cd_encrypt:
                if not password:
                    raise ArchiveError('加密中心目录需要提供密码')
                _rep(progress, '加密中心化目录...', 95)
                cj, cd_crypto = _encrypt_blob(cj, password, crypto=crypto)
            cblocks, cparity, cinfo = _protect_blob(cj, '中心化目录',
                                                    codec=CODEC_CAUCHY)
            for b in cblocks:
                out.write(b)
            for p in cparity:
                out.write(p)
            cinfo['encrypted'] = cd_crypto is not None
            cinfo['crypto'] = cd_crypto
            tinfo = {'fmt': 'arh2', 'hdr': hinfo, 'cd': cinfo}
            tj = json.dumps(tinfo, separators=(',', ':')).encode('utf-8')
            out.write(tj)
            out.write(struct.pack('>I', _crc(tj)))    # 尾注 body CRC32
            out.write(struct.pack('>I', len(tj) + 4))  # tlen 含 4 字节 body CRC
            out.write(ARH2_TRAILER_MAGIC)              # 最末尾：从尾向前自定位

        _rep(progress, '写入归档...', 84)
        _write_archive_atomically(out_path, _body)
        _rep(progress, '完成', 100)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _build_arhp(paths, out_path, level=9, redundancy=3, block_size=1 << 20,
                password=None, crypto='gcm', progress=None,
                mem_limit=DEFAULT_MEM_LIMIT):
    """创建 .arhp 归档（v3 格式：归档头同样纳入 Reed-Solomon 保护）。

    使用 Vandermonde 纠删码与旧版扁平尾注布局，arhp 1.1.0.2 可正常读取；
    加密归档的头含 HMAC-SHA256 防篡改认证。分块校验与校验块生成全部
    流式进行，载荷处理工作集不超过 mem_limit（进程总内存另含对象/
    元数据开销）。
    """
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    redundancy = min(max(int(redundancy), 0), 50)
    block_size = int(block_size)
    if block_size < 4096:
        raise ArchiveError('分块大小不能小于 4096 字节: %s' % block_size)
    level = int(level)
    if not 0 <= level <= 22:
        raise ArchiveError('压缩级别必须是 0-22 的整数')
    # 中间产物统一放在程序临时目录（%LOCALAPPDATA%\MienArch\ARHP），
    # 而不是输出目录，避免污染用户选择的位置。
    tmpdir = tempfile.mkdtemp(prefix='.arhp_', dir=app_temp_dir())
    try:
        compression = 'store' if level == 0 else 'zstd'
        _rep(progress, '打包%s中...' % ('' if level == 0 else '并 Zstd 压缩'), 3)
        comp = os.path.join(tmpdir, 'payload.bin')
        try:
            with open(comp, 'wb') as raw:
                if compression == 'zstd':
                    with open_writer(raw, level) as zw, \
                         tarfile.open(fileobj=zw, mode='w|') as tar:
                        _add_paths(tar, paths)
                else:
                    with tarfile.open(fileobj=raw, mode='w|') as tar:
                        _add_paths(tar, paths)
        except ImportError as e:
            raise ArchiveError(str(e))

        encrypted = bool(password)
        key = None
        if encrypted:
            kdf_label = 'Argon2id' if (crypto or 'gcm').lower() == 'argon2id' \
                else 'PBKDF2'
            _rep(progress, 'AES-256-GCM 加密中（密钥派生: %s）...' % kdf_label, 15)
            enc = os.path.join(tmpdir, 'payload.enc')
            kdf_info, key = _crypto_encrypt(comp, enc, password, progress,
                                            crypto=crypto, return_key=True)
            os.replace(enc, comp)
        else:
            kdf_info = None

        payload_size = os.path.getsize(comp)
        method = 'rs'
        n, k, bs = _layout(payload_size, redundancy, block_size)
        if bs != block_size:
            # 自动调整分块大小时明确告知，不再静默改写
            _rep(progress, '分块数超过 %d 上限，分块大小已自动增大到 %s'
                 % (MAX_SHARDS, _fmt_size(bs)), 24)

        hdr = {
            'version': 3,
            'rs_codec': CODEC_VANDERMONDE,
            'method': method,
            'compression': compression,
            'zstd_level': level,
            'encrypted': encrypted,
            'crypto': kdf_info,
            'block_size': bs,
            'num_blocks': n,
            'num_parity': k,
            'payload_size': payload_size,
            'block_crc': [],
            'block_len': [],
            'parity_crc': [],
        }

        if k:
            _rep(progress, '分块并生成恢复数据...', 25)
        else:
            _rep(progress, '分块中...', 25)
        blocks_tmp = os.path.join(tmpdir, 'blocks.bin')
        parity_tmp = os.path.join(tmpdir, 'parity.bin')
        written = 0
        # 流式分块：读缓冲 ≤ mem_limit，CRC 增量计算，不再整载单块
        io_chunk = max(1, min(bs, mem_limit))
        with open(comp, 'rb') as fin, open(blocks_tmp, 'wb') as fout:
            for i in range(n):
                real = min(bs, payload_size - i * bs)
                crc = 0
                got = 0
                while got < real:
                    chunk = fin.read(min(io_chunk, real - got))
                    if not chunk:
                        raise ArchiveError('读取压缩载荷失败（文件被截断）')
                    crc = zlib.crc32(chunk, crc)
                    fout.write(chunk)
                    got += len(chunk)
                hdr['block_crc'].append(crc & 0xFFFFFFFF)
                hdr['block_len'].append(real)
                written += real
                _rep(progress, '处理分块 %d/%d' % (i + 1, n),
                     25 + int(60 * written / max(payload_size, 1)))
        if k:
            _write_parity(comp, parity_tmp, n, k, bs, payload_size,
                          mem_limit, progress, CODEC_VANDERMONDE)
            with open(parity_tmp, 'rb') as pf:
                for j in range(k):
                    crc = 0
                    got = 0
                    while got < bs:
                        chunk = pf.read(min(io_chunk, bs - got))
                        if not chunk:
                            break
                        crc = zlib.crc32(chunk, crc)
                        got += len(chunk)
                    hdr['parity_crc'].append(crc & 0xFFFFFFFF)

        # 加密归档的头纳入 HMAC-SHA256 认证（防篡改；未加密归档仅靠
        # CRC32+RS，仅防随机损坏，不防恶意篡改）
        if encrypted and key is not None:
            hdr[_HEADER_MAC_FIELD] = _header_mac_hex(key, hdr)

        # 头自校验：在所有头字段就绪后计算 CRC32
        hdr[_HEADER_CRC_FIELD] = _crc(_canonical_header_json(hdr))

        def _body(out):
            out.write(ARHP_MAGIC)
            hj = json.dumps(hdr, separators=(',', ':')).encode('utf-8')
            out.write(struct.pack('>Q', len(hj)))
            out.write(hj)
            with open(blocks_tmp, 'rb') as fin:
                shutil.copyfileobj(fin, out, 1 << 20)
            if k:
                with open(parity_tmp, 'rb') as pf:
                    shutil.copyfileobj(pf, out, 1 << 20)
            # v3：归档头纳入 RS 保护——头分块 + 头校验块 + 自描述尾注
            _rep(progress, '生成归档头恢复数据...', 94)
            hblocks, hparity, tinfo = _protect_header_arhp(hj)
            for b in hblocks:
                out.write(b)
            for p in hparity:
                out.write(p)
            tj = json.dumps(tinfo, separators=(',', ':')).encode('utf-8')
            out.write(tj)
            out.write(struct.pack('>I', _crc(tj)))    # 尾注 body CRC32
            out.write(struct.pack('>I', len(tj) + 4))  # tlen 含 4 字节 body CRC
            out.write(ARHP_TRAILER_MAGIC)              # 最末尾：从尾向前自定位

        _rep(progress, '写入归档...', 88)
        _write_archive_atomically(out_path, _body)
        _rep(progress, '完成', 100)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---- zip 创建 ----

def _create_zip(paths, out_path, level=9, password=None, progress=None):
    """创建 .zip 归档（标准库 zipfile，deflate / store）。

    标准库不支持写入加密 zip，传入密码时报错提示改用 .arh2/.arhp/.7z。
    符号链接策略与 arh2/arhp（tar 载体）一致：链接本身存入归档
    （Unix 高 16 位模式写入 S_IFLNK，链接目标作为条目内容），
    不跟随链接打包目标内容；目录符号链接同样按链接存储。
    整个归档经 _write_archive_atomically 原子写入：创建中途崩溃不
    留损坏文件，也不提前截断已存在的旧归档。
    """
    import zipfile
    if password:
        raise ArchiveError('zip 格式不支持加密（标准库限制），请改用 .arh2/.arhp/.7z')
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    level = max(0, min(9, int(level)))
    # 条目分类收集（用 lstat 语义判定符号链接，不被 os.path.isfile 跟随）：
    # entries: ('file'|'dir', 磁盘路径, 归档名)；links: (磁盘路径, 归档名)
    entries = []
    links = []
    for p in paths:
        if os.path.islink(p):
            links.append((p, os.path.basename(p)))
        elif os.path.isdir(p):
            base = os.path.dirname(os.path.abspath(p))
            for root, dirs, fnames in os.walk(p, followlinks=False):
                dirs.sort()
                fnames.sort()
                entries.append(('dir', root, os.path.relpath(root, base)))
                for name in list(dirs):
                    full = os.path.join(root, name)
                    if os.path.islink(full):
                        # 目录符号链接：os.walk 不会进入，按链接本身存储
                        links.append((full, os.path.relpath(full, base)))
                        dirs.remove(name)
                for name in fnames:
                    full = os.path.join(root, name)
                    if os.path.islink(full):
                        links.append((full, os.path.relpath(full, base)))
                    else:
                        entries.append(('file', full, os.path.relpath(full, base)))
        else:
            entries.append(('file', p, os.path.basename(p)))
    total = sum(os.path.getsize(full) for kind, full, _ in entries
                if kind == 'file')
    compression = zipfile.ZIP_STORED if level == 0 else zipfile.ZIP_DEFLATED
    compresslevel = None if level == 0 else max(1, level)
    done = 0
    count = 0

    def _body(out):
        nonlocal done, count
        with zipfile.ZipFile(out, 'w', compression=compression,
                             compresslevel=compresslevel) as zf:
            for kind, full, arc in entries:
                arcname = arc.replace(os.sep, '/')
                if kind == 'file':
                    zf.write(full, arcname)
                    count += 1
                    done += os.path.getsize(full)
                    _rep(progress, '已打包 %d 个文件' % count,
                         3 + int(95 * done / max(total, 1)))
                else:
                    # 目录项（保留空目录）
                    zf.writestr(arcname + '/', b'')
            for full, arc in links:
                # 符号链接：以 Unix 模式位（S_IFLNK）写入链接本身，
                # 链接目标文本作为条目内容，解压端可按链接还原
                zi = zipfile.ZipInfo(arc.replace(os.sep, '/'))
                zi.create_system = 3  # Unix，外部属性高 16 位为 st_mode
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(zi, os.readlink(full).encode('utf-8'))
                count += 1
                _rep(progress, '已打包 %d 个文件' % count,
                     3 + int(95 * done / max(total, 1)))

    _rep(progress, '打包中 (zip)...', 3)
    _write_archive_atomically(out_path, _body)
    _rep(progress, '完成，共 %d 个文件' % count, 100)
    return count


# ---- 7z 创建 ----

def _load_7z():
    try:
        import py7zr
        return py7zr
    except ImportError:
        raise ArchiveError('处理 .7z 需要安装 py7zr: pip install py7zr')


def _create_7z(paths, out_path, level=9, password=None, progress=None):
    """创建 .7z 归档（py7zr，LZMA2 / Copy）。

    level: 0 = 仅存储，1-9 = LZMA2 preset（>9 按 9 处理）；
    password: 非空则启用 py7zr 的 AES-256 加密（需 py7zr>=0.20）。
    整个归档经 _write_archive_atomically 原子写入：创建中途崩溃不
    留损坏文件，也不提前截断已存在的旧归档。
    """
    py7zr = _load_7z()
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    level = max(0, min(9, int(level)))
    if level == 0:
        filters = [{'id': py7zr.FILTER_COPY}]
    else:
        filters = [{'id': py7zr.FILTER_LZMA2, 'preset': level}]
    _rep(progress, '打包中 (7z LZMA2)...', 5)

    def _body(out):
        # 注意：py7zr 在传入 filters 时若不加 header_encryption=True，
        # password 会被静默忽略（数据不加密）。因此加密时必须显式开启头加密。
        # py7zr 接受可 seek 的文件对象作为 target，关闭时回写加密头，
        # 因此可安全地在临时文件上构建后再原子替换。
        with py7zr.SevenZipFile(out, 'w', password=password or None,
                                header_encryption=bool(password),
                                filters=filters) as zf:
            for p in paths:
                arc = os.path.basename(os.path.normpath(p))
                if os.path.isdir(p):
                    zf.writeall(p, arcname=arc)
                else:
                    zf.write(p, arcname=arc)

    _write_archive_atomically(out_path, _body)
    _rep(progress, '完成', 100)
    return None


def create_archive(paths, out_path, fmt=None, level=9, redundancy=3,
                   block_size=1 << 20, password=None,
                   volume_size=None, progress=None, crypto='gcm',
                   cd_encrypt=False, mem_limit=DEFAULT_MEM_LIMIT):
    """创建归档。按扩展名或 fmt 自动选择格式。

    paths: 文件/目录列表；out_path: 输出路径；
    fmt: 'arh2' / 'arhp' / 'zip' / '7z'，None 时按 out_path 扩展名判断
         （默认 arh2）；
    level: 压缩级别（arh2/arhp: 0-22，zip: 0-9，7z: 0-9；0 = 仅存储）；
    redundancy / block_size: 仅 .arh2/.arhp 使用（Reed-Solomon 恢复数据，
                             zip/7z 忽略）；
    volume_size: 分卷大小（字节），设置后输出为 name.ext.001/.002/... 分卷，
                 适用于全部四种格式；None 或归档不超过该大小时输出单文件；
    password: .arh2/.arhp 用 AES-256-GCM（密钥派生由 crypto 决定）；
              .7z 用 py7zr AES-256（需 py7zr>=0.20）；.zip 标准库不支持
              写入加密，传入密码会报错；
    crypto: 仅 .arh2/.arhp 生效——'gcm' = PBKDF2-HMAC-SHA256（默认，
            兼容旧版）；'argon2id' = Argon2id 内存硬派生（需 argon2-cffi）；
    cd_encrypt: 仅 .arh2——加密中心化目录（列目录也需要密码）；
    mem_limit: 内存限制（字节，16M-1024M，默认 128M）。.arh2/.arhp 的分块
               校验与 Reed-Solomon 编码按块/按列切片流式进行，载荷处理
               工作集不超此值；进程总内存另含 Python 对象、缓冲区与
               头/目录元数据开销；
    progress: callable(msg, percent)。
    """
    mem_limit = _check_mem_limit(mem_limit)
    fmt = (fmt or detect_format(out_path)).lower()
    if fmt == 'zip':
        result = _create_zip(paths, out_path, level=level, password=password,
                             progress=progress)
    elif fmt == '7z':
        result = _create_7z(paths, out_path, level=level, password=password,
                            progress=progress)
    elif fmt == 'arh2':
        _build_arh2(paths, out_path, level=level,
                    redundancy=redundancy, block_size=block_size,
                    password=password, crypto=crypto, cd_encrypt=cd_encrypt,
                    progress=progress, mem_limit=mem_limit)
        result = None
    elif fmt == 'arhp':
        _build_arhp(paths, out_path, level=level,
                    redundancy=redundancy, block_size=block_size,
                    password=password, crypto=crypto,
                    progress=progress, mem_limit=mem_limit)
        result = None
    else:
        raise ArchiveError('不支持的归档格式: %s（支持 arh2/arhp/zip/7z）' % fmt)
    if volume_size:
        split_volumes(out_path, volume_size, progress=progress)
    return result


# ---------------------------------------------------------------- 读取

def _header_int(value, name, minimum, maximum=None):
    """读取严格 JSON 整数；拒绝布尔值、浮点数、字符串与越界值。"""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ArchiveError('归档头字段 %s 必须为整数' % name)
    if value < minimum or (maximum is not None and value > maximum):
        raise ArchiveError('归档头字段 %s 越界: %s' % (name, value))
    return value


def _validate_tables(hdr):
    """校验分块表/校验块表/连续布局（.arh2 与 .arhp 共用）。"""
    block_size = _header_int(hdr.get('block_size'), 'block_size', 1, MAX_BLOCK_SIZE)
    num_blocks = _header_int(hdr.get('num_blocks'), 'num_blocks', 1, MAX_SHARDS)
    num_parity = _header_int(hdr.get('num_parity'), 'num_parity', 0,
                             MAX_SHARDS - num_blocks)
    payload_size = _header_int(hdr.get('payload_size'), 'payload_size', 0)

    block_crc = hdr.get('block_crc')
    block_len = hdr.get('block_len')
    parity_crc = hdr.get('parity_crc')
    if (not isinstance(block_crc, list) or not isinstance(block_len, list)
            or len(block_crc) != num_blocks or len(block_len) != num_blocks):
        raise ArchiveError('归档头中数据块表缺失或长度不一致')
    if not isinstance(parity_crc, list) or len(parity_crc) != num_parity:
        raise ArchiveError('归档头中校验块表缺失或长度不一致')

    parsed_len = []
    parsed_crc = []
    for i, (ln, crc) in enumerate(zip(block_len, block_crc)):
        parsed_len.append(_header_int(ln, 'block_len[%d]' % i, 0, block_size))
        parsed_crc.append(_header_int(crc, 'block_crc[%d]' % i, 0, 0xFFFFFFFF))
    parsed_parity = []
    for j, crc in enumerate(parity_crc):
        parsed_parity.append(_header_int(crc, 'parity_crc[%d]' % j, 0, 0xFFFFFFFF))

    if sum(parsed_len) != payload_size:
        raise ArchiveError('归档头中分块长度与载荷大小不一致')
    expected_blocks = max(1, -(-payload_size // block_size))
    if num_blocks != expected_blocks:
        raise ArchiveError('归档头中数据块数量与载荷长度不匹配')
    if payload_size:
        for i, ln in enumerate(parsed_len):
            expected = block_size if i < num_blocks - 1 else \
                payload_size - block_size * (num_blocks - 1)
            if ln != expected:
                raise ArchiveError('归档头中分块长度不符合连续布局')

    hdr['block_size'] = block_size
    hdr['num_blocks'] = num_blocks
    hdr['num_parity'] = num_parity
    hdr['payload_size'] = payload_size
    hdr['block_len'] = parsed_len
    hdr['block_crc'] = parsed_crc
    hdr['parity_crc'] = parsed_parity


def _validate_crypto_header(hdr, fmt):
    """校验加密参数块（.arh2 用严格 AEAD 校验，.arhp 旧头做宽松兼容校验）。"""
    crypto_info = hdr.get('crypto')
    if not isinstance(crypto_info, dict):
        raise ArchiveError('加密归档缺少加密参数')
    if fmt == 'arh2':
        _validate_payload_crypto_info(crypto_info,
                                      payload_size=hdr.get('payload_size'))
        return
    # 旧版 .arhp：头中无 num_chunks 等字段，做结构兼容校验
    kdf_name = crypto_info.get('kdf', KDF_PBKDF2)
    if kdf_name not in (KDF_PBKDF2, KDF_ARGON2ID):
        raise ArchiveError('归档头中加密 KDF 不受支持: %r' % (kdf_name,))
    if kdf_name == KDF_ARGON2ID and \
            not isinstance(crypto_info.get('kdf_params'), dict):
        raise ArchiveError('归档头中 Argon2id 参数缺失或损坏')
    try:
        salt = base64.b64decode(crypto_info['salt'], validate=True)
        prefix = base64.b64decode(crypto_info['nonce_prefix'], validate=True)
    except Exception:
        raise CryptoError('归档头中加密参数损坏')
    if len(salt) != _SALT_LEN or len(prefix) not in _VALID_NONCE_PREFIX_LENS:
        raise CryptoError('归档头中加密参数损坏')


def _validate_header_arh2(hdr):
    """.arh2 头校验（version=1，Cauchy-MDS，中心目录尾注必填）。"""
    if not isinstance(hdr, dict):
        raise ArchiveError('归档头类型错误')

    _header_int(hdr.get('version'), 'version', 1, 1)
    method = hdr.get('method')
    if method != 'rs':
        raise ArchiveError('归档头中恢复方法无效: %r（仅支持内置 Reed-Solomon）' % method)
    compression = hdr.get('compression', 'zstd')
    if compression not in ('zstd', 'store'):
        raise ArchiveError('归档头中压缩方式无效: %r' % compression)
    zstd_level = _header_int(hdr.get('zstd_level', DEFAULT_LEVEL),
                             'zstd_level', 0, MAX_LEVEL)
    if ((compression == 'store' and zstd_level != 0)
            or (compression == 'zstd' and zstd_level < 1)):
        raise ArchiveError('归档头中的压缩等级与压缩方式不匹配')
    encrypted = hdr.get('encrypted', False)
    if not isinstance(encrypted, bool):
        raise ArchiveError('归档头中 encrypted 必须为布尔值')
    rs_codec = hdr.get('rs_codec')
    if rs_codec != CODEC_CAUCHY:
        raise ArchiveError('归档头中 Reed-Solomon 编码标识无效')

    _validate_tables(hdr)
    if encrypted:
        _validate_crypto_header(hdr, 'arh2')

    # 头自校验字段必须存在且有效。
    if hdr.get(_HEADER_CRC_FIELD) is None:
        raise ArchiveError('归档头缺少 header_crc')
    header_crc = _header_int(hdr.get(_HEADER_CRC_FIELD),
                             _HEADER_CRC_FIELD, 0, 0xFFFFFFFF)
    if _crc(_canonical_header_json(hdr)) != header_crc:
        raise ArchiveError('归档头校验失败（header_crc 不匹配），'
                           '头数据已损坏，无法安全读取')
    # 不注入 rs_codec：规范化 JSON 必须与写入端逐字节一致（头 HMAC/
    # header_crc 的验证对象是存储的头字段；旧归档无此字段，注入会
    # 改变 HMAC 输入导致验证失败）。读取处统一用 .get 取默认编码。


def _validate_header_arhp(hdr):
    """.arhp 头校验（v2/v3，Vandermonde；v2 旧归档无 header_crc 则跳过）。"""
    if not isinstance(hdr, dict):
        raise ArchiveError('归档头类型错误')

    version = _header_int(hdr.get('version'), 'version', 2, 3)
    method = hdr.get('method')
    if method != 'rs':
        raise ArchiveError('归档头中恢复方法无效: %r（仅支持内置 Reed-Solomon）' % method)
    compression = hdr.get('compression', 'zstd')
    if compression not in ('zstd', 'store'):
        raise ArchiveError('归档头中压缩方式无效: %r' % compression)

    _validate_tables(hdr)
    if hdr.get('encrypted'):
        _validate_crypto_header(hdr, 'arhp')

    # 头自校验（v1.0.2.3+ 写入；旧归档无此字段则跳过，保持向后兼容）
    if hdr.get(_HEADER_CRC_FIELD) is not None:
        header_crc = _header_int(hdr.get(_HEADER_CRC_FIELD),
                                 _HEADER_CRC_FIELD, 0, 0xFFFFFFFF)
        if _crc(_canonical_header_json(hdr)) != header_crc:
            raise ArchiveError('归档头校验失败（header_crc 不匹配），'
                               '头数据已损坏，无法安全读取')
    # 编码标识：旧归档无 rs_codec 字段，按 Vandermonde 处理
    rs_codec = hdr.get('rs_codec', CODEC_VANDERMONDE)
    if rs_codec != CODEC_VANDERMONDE:
        raise ArchiveError('归档头中 Reed-Solomon 编码标识无效: %r' % (rs_codec,))
    # 不注入 rs_codec / version，理由同上（HMAC 输入须与存储头一致）


def _read_trailer(f, file_size, trailer_magic):
    """读取尾注并校验 CRC。返回 (trailer_dict, trailer_total_len)；
    末尾无尾注魔数的旧格式归档（.arhp v2）返回 (None, 0)。"""
    if file_size < len(trailer_magic) + 4:
        return None, 0
    f.seek(file_size - len(trailer_magic))
    if f.read(len(trailer_magic)) != trailer_magic:
        return None, 0
    f.seek(file_size - len(trailer_magic) - 4)
    (tlen,) = struct.unpack('>I', f.read(4))
    if tlen <= 4 or tlen > MAX_TRAILER:
        raise ArchiveError('归档尾注长度异常 (%d 字节)，文件可能已损坏' % tlen)
    total = len(trailer_magic) + 4 + tlen
    if total > file_size:
        raise ArchiveError('归档尾注被截断，文件可能已损坏')
    f.seek(file_size - total)
    tj = f.read(tlen)
    if len(tj) != tlen:
        raise ArchiveError('归档尾注被截断，文件可能已损坏')
    body, tcrc = tj[:-4], struct.unpack('>I', tj[-4:])[0]
    if _crc(body) != tcrc:
        raise ArchiveError('归档尾注校验失败（CRC 不匹配），文件可能已损坏')
    try:
        t = json.loads(body.decode('utf-8'))
    except Exception:
        raise ArchiveError('归档尾注损坏（JSON 解析失败）')
    if not isinstance(t, dict):
        raise ArchiveError('归档尾注类型错误')
    return t, total


def _protected_blob_span(layout, what='数据'):
    """严格校验尾注保护布局并返回保护区总字节数（.arh2 头/目录通用）。"""
    try:
        hlen = _header_int(layout.get('len'), what + '.len', 1, MAX_HEADER)
        hbs = _header_int(layout.get('bs'), what + '.bs', 1, MAX_BLOCK_SIZE)
        hb = _header_int(layout.get('hb'), what + '.hb', 1, MAX_SHARDS)
        hp = _header_int(layout.get('hp'), what + '.hp', 2, MAX_HEADER_PARITY)
        crc = _header_int(layout.get('crc'), what + '.crc', 0, 0xFFFFFFFF)
        codec = layout.get('codec')
        crcs, pcrc = layout.get('crcs'), layout.get('pcrc')
    except AttributeError:
        raise ArchiveError('归档尾注中%s布局类型错误' % what)
    if (hbs != HEADER_BLOCK_SIZE or hb + hp > MAX_SHARDS
            or hb != -(-hlen // hbs)
            or codec != CODEC_CAUCHY
            or not isinstance(crcs, list) or len(crcs) != hb
            or not isinstance(pcrc, list) or len(pcrc) != hp):
        raise ArchiveError('归档尾注中%s布局越界或损坏' % what)
    for i, value in enumerate(crcs):
        _header_int(value, '%s.crcs[%d]' % (what, i), 0, 0xFFFFFFFF)
    for i, value in enumerate(pcrc):
        _header_int(value, '%s.pcrc[%d]' % (what, i), 0, 0xFFFFFFFF)
    return (hb + hp) * hbs


def _recover_blob(f, region_end, layout, what='数据'):
    """从 region_end 向前读 (hb+hp) 个等长块：逐块 CRC 校验，损坏块用
    Reed-Solomon 恢复，返回修复后的原始字节（.arh2 归档头/中心化目录通用）。

    region_end: 保护区之后的文件偏移（头保护区 = 尾注起点；
    目录保护区 = 头保护区起点）。
    """
    _protected_blob_span(layout, what)
    hlen = layout['len']
    hbs = layout['bs']
    hb = layout['hb']
    hp = layout['hp']
    hcrc = layout['crc']
    crcs = layout['crcs']
    pcrc = layout['pcrc']

    start = region_end - (hb + hp) * hbs
    if start < 14:  # 至少要有 magic + hlen 的空间
        raise ArchiveError('归档%s区域位置异常，文件可能已损坏' % what)
    f.seek(start)
    blocks, missing = [], []
    for i in range(hb):
        blk = f.read(hbs)
        if len(blk) != hbs or _crc(blk) != crcs[i]:
            blocks.append(None)
            missing.append(i)
        else:
            blocks.append(blk)
    par = []
    for j in range(hp):
        pb = f.read(hbs)
        if len(pb) != hbs or _crc(pb) != pcrc[j]:
            par.append(None)
        else:
            par.append(pb)

    if not missing:
        blob = b''.join(blocks)[:hlen]
    else:
        ok = sum(1 for p in par if p is not None)
        if len(missing) > ok:
            raise ArchiveError('%s损坏 %d 块，超出可恢复上限 %d 块，无法安全读取'
                               % (what, len(missing), ok))
        rec = ReedSolomon().recover(blocks, par, missing, codec=CODEC_CAUCHY)
        for i, b in rec.items():
            if _crc(bytes(b)) != crcs[i]:
                raise ArchiveError('%s恢复数据未通过 CRC 校验，无法安全读取' % what)
            blocks[i] = b
        blob = b''.join(blocks)[:hlen]
    if _crc(blob) != hcrc:
        raise ArchiveError('%s恢复结果校验失败，无法安全读取' % what)
    return blob


def _recover_header_arhp(f, file_size, trailer, trailer_len):
    """.arhp v3：头 JSON 与尾注记录不一致时，用头校验块做 RS 恢复（Vandermonde）。

    返回修复后的头 JSON 字节；损坏超出可恢复上限时抛出 ArchiveError。
    """
    try:
        hlen = int(trailer['hlen'])
        hbs = int(trailer['hbs'])
        hb = int(trailer['hb'])
        hp = int(trailer['hp'])
        h_crc = trailer['h_crc']
        hp_crc = trailer['hp_crc']
    except (KeyError, TypeError, ValueError):
        raise ArchiveError('归档尾注中头保护布局缺失或损坏')
    if (not 1 <= hlen <= MAX_HEADER
            or hbs != HEADER_BLOCK_SIZE
            or not 1 <= hb <= MAX_SHARDS
            or not 0 <= hp <= MAX_SHARDS - hb
            or not isinstance(h_crc, list) or len(h_crc) != hb
            or not isinstance(hp_crc, list) or len(hp_crc) != hp):
        raise ArchiveError('归档尾注中头保护布局越界或损坏')
    h_crc = [_header_int(c, 'h_crc[%d]' % i, 0, 0xFFFFFFFF)
             for i, c in enumerate(h_crc)]
    hp_crc = [_header_int(c, 'hp_crc[%d]' % j, 0, 0xFFFFFFFF)
              for j, c in enumerate(hp_crc)]

    # 头分块区域位于尾注之前：(hb + hp) 个等长块
    region_end = file_size - trailer_len
    start = region_end - (hb + hp) * hbs
    if start < 14:  # 至少要有 magic + hlen 的空间
        raise ArchiveError('归档头保护区域位置异常，文件可能已损坏')
    f.seek(start)
    blocks, missing = [], []
    for i in range(hb):
        blk = f.read(hbs)
        if len(blk) != hbs or _crc(blk) != h_crc[i]:
            blocks.append(None)
            missing.append(i)
        else:
            blocks.append(blk)
    par = []
    for j in range(hp):
        pb = f.read(hbs)
        if len(pb) != hbs or _crc(pb) != hp_crc[j]:
            par.append(None)
        else:
            par.append(pb)

    if not missing:
        fixed = b''.join(blocks)[:hlen]
    else:
        ok = sum(1 for p in par if p is not None)
        if len(missing) > ok:
            raise ArchiveError('归档头损坏 %d 块，超出可恢复上限 %d 块，'
                               '归档无法安全读取' % (len(missing), ok))
        rec = ReedSolomon().recover(blocks, par, missing,
                                    codec=CODEC_VANDERMONDE)
        for i, b in rec.items():
            if _crc(bytes(b)) != h_crc[i]:
                raise ArchiveError('归档头恢复数据未通过 CRC 校验，无法安全读取')
            blocks[i] = b
        fixed = b''.join(blocks)[:hlen]
    if _crc(fixed) != trailer['header_crc']:
        raise ArchiveError('归档头恢复结果校验失败，无法安全读取')
    return fixed


def _open_archive_impl(path, fmt):
    """读取并校验 .arh2 / .arhp 归档头，返回 header 字典。

    短读时抛出清晰的 ArchiveError；头部损坏时使用对应编码的 RS 分片恢复。
    """
    magic = ARH2_MAGIC if fmt == 'arh2' else ARHP_MAGIC
    trailer_magic = ARH2_TRAILER_MAGIC if fmt == 'arh2' else ARHP_TRAILER_MAGIC
    with open(path, 'rb') as f:
        if f.read(6) != magic:
            raise ArchiveError('不是 %s 归档: %s' % (fmt.upper(), path))
        raw = f.read(8)
        if len(raw) != 8:
            raise ArchiveError('归档头被截断: %s' % path)
        (hlen,) = struct.unpack('>Q', raw)
        if hlen <= 0 or hlen > MAX_HEADER:
            raise ArchiveError('归档头长度异常 (%d 字节)，文件可能已损坏' % hlen)
        hj = f.read(hlen)
        if len(hj) != hlen:
            raise ArchiveError('归档头被截断: %s' % path)
        data_offset = f.tell()
        f.seek(0, os.SEEK_END)
        file_size = f.tell()

        hdr = None
        if fmt == 'arh2':
            trailer, trailer_len = _read_trailer(f, file_size, trailer_magic)
            trailer_start = file_size - trailer_len
            if (not isinstance(trailer, dict) or trailer.get('fmt') != 'arh2'
                    or not isinstance(trailer.get('hdr'), dict)
                    or not isinstance(trailer.get('cd'), dict)):
                raise ArchiveError('ARH2 尾注缺少有效的头部/中心目录布局')
            hl = trailer['hdr']
            cd = trailer['cd']
            if not isinstance(cd.get('encrypted'), bool):
                raise ArchiveError('中心目录 encrypted 字段必须为布尔值')
            if cd['encrypted']:
                _validate_blob_crypto_info(cd.get('crypto'))
            elif cd.get('crypto') not in (None, {}):
                raise ArchiveError('未加密中心目录不应包含加密参数')
            cd_codec = cd.get('codec')
            hdr_codec = hl.get('codec')
            if cd_codec != hdr_codec or cd_codec != CODEC_CAUCHY:
                raise ArchiveError('头部与中心目录 RS 编码标识不一致')
            cd_span = _protected_blob_span(cd, '中心化目录')
            header_region_end = trailer_start - cd_span
            _protected_blob_span(hl, '归档头')
            if header_region_end < 14:
                raise ArchiveError('ARH2 头部保护区位置异常')
            if _crc(hj) != hl['crc']:
                hj = _recover_blob(f, header_region_end, hl, '归档头')
            try:
                hdr = json.loads(hj.decode('utf-8'))
            except Exception:
                # 极端情况：直接读到的头 CRC 巧合通过但 JSON 损坏（或 crcs
                # 表被同步伪造）。此时 RS 保护区里可能有与 hj 不同的副本，
                # 再尝试恢复一次；仍失败才放弃。
                try:
                    hdr = json.loads(
                        _recover_blob(f, header_region_end, hl, '归档头').decode('utf-8'))
                except ArchiveError:
                    raise
                except Exception:
                    raise ArchiveError('归档头损坏（JSON 解析失败）')
            _validate_header_arh2(hdr)
            hdr['format'] = 'arh2'
            payload_end = data_offset + hdr['payload_size'] + \
                hdr['num_parity'] * hdr['block_size']
            if payload_end > file_size:
                raise ArchiveError('归档数据区或校验区被截断')
            header_span = _protected_blob_span(hl, '归档头')
            expected_header_start = header_region_end - header_span
            if expected_header_start != payload_end:
                raise ArchiveError('归档数据/头保护/中心目录区域边界不连续')
            # 暂存尾注（.arh2 列目录快路径用）；须在 _validate_header 之后
            # 再挂到 hdr 上，避免参与 header_crc 的规范化 JSON 计算
            hdr['_trailer'] = trailer
            hdr['_trailer_len'] = trailer_len
        else:
            # .arhp：v3 有头保护尾注；v2（≤1.0.2.3）无尾注，跳过头保护
            trailer, trailer_len = _read_trailer(f, file_size, trailer_magic)
            if trailer is not None:
                t_hcrc = trailer.get('header_crc')
                if (not isinstance(t_hcrc, int) or isinstance(t_hcrc, bool)
                        or not 0 <= t_hcrc <= 0xFFFFFFFF):
                    raise ArchiveError('归档尾注中头校验值损坏')
                if _crc(hj) != t_hcrc:
                    hj = _recover_header_arhp(f, file_size, trailer,
                                              trailer_len)
            try:
                hdr = json.loads(hj.decode('utf-8'))
            except Exception:
                raise ArchiveError('归档头损坏（JSON 解析失败）')
            _validate_header_arhp(hdr)
            hdr['format'] = 'arhp'
            payload_end = data_offset + hdr['payload_size']
            if payload_end > file_size:
                raise ArchiveError('归档数据区被截断')

        hdr['data_offset'] = data_offset
        return hdr


def open_archive(path):
    """读取并校验 .arh2 / .arhp 归档头，返回 header 字典。"""
    fmt = detect_format(path)
    if fmt in ('zip', '7z'):
        raise ArchiveError('open_archive 仅适用于 .arh2 / .arhp: %s' % path)
    return _open_archive_impl(path, fmt)


def _block_offsets(hdr):
    """各数据块在归档数据区的起始偏移（按真实长度连续布局）。"""
    offs = []
    pos = hdr['data_offset']
    for ln in hdr['block_len']:
        offs.append(pos)
        pos += ln
    return offs


def _crc_stream(f, size, mem_limit):
    """流式计算 f 当前位置起 size 字节的 CRC32；返回 (crc, 实读长度)。"""
    crc = 0
    got = 0
    while got < size:
        chunk = f.read(min(mem_limit, size - got))
        if not chunk:
            break
        crc = zlib.crc32(chunk, crc)
        got += len(chunk)
    return crc & 0xFFFFFFFF, got


def _verify_blocks_to(f, hdr, out, mem_limit, progress, offsets):
    """流式校验全部分块并顺序写入 out（损坏块留洞、稍后回填）。

    返回损坏块索引列表。峰值内存 ≈ min(mem_limit, block_size)。
    """
    missing = []
    nbad = 0
    total = max(hdr['payload_size'], 1)
    done = 0
    for i in range(hdr['num_blocks']):
        real = hdr['block_len'][i]
        crc = 0
        got = 0
        while got < real:
            chunk = f.read(min(mem_limit, real - got))
            if not chunk:
                break
            crc = zlib.crc32(chunk, crc)
            out.write(chunk)
            got += len(chunk)
        if got != real or (crc & 0xFFFFFFFF) != hdr['block_crc'][i]:
            missing.append(i)
            nbad += 1
            # 坏块区域在载荷文件中留洞，待 RS 恢复后回填
            #（out 是载荷临时文件，偏移须相对数据区起点）
            out.seek(offsets[i] - hdr['data_offset'] + real)
        done += real
        _rep(progress, '校验分块 %d/%d%s' % (
            i + 1, hdr['num_blocks'], '（已发现 %d 个损坏）' % nbad if nbad else ''),
            5 + int(20 * done / total))
    return missing


def _gf_matrix_inv(rs, A):
    """GF(2^8) 方阵求逆（Gauss-Jordan，供多块恢复复用同一逆矩阵）。
    奇异时抛 ReedSolomonError。"""
    n = len(A)
    M = [list(A[r]) + [1 if c == r else 0 for c in range(n)] for r in range(n)]
    for col in range(n):
        piv = -1
        for r in range(col, n):
            if M[r][col]:
                piv = r
                break
        if piv < 0:
            raise ReedSolomonError('校验矩阵奇异，无法恢复')
        if piv != col:
            M[col], M[piv] = M[piv], M[col]
        invc = rs.inv(M[col][col])
        if invc != 1:
            M[col] = [rs.mul(x, invc) for x in M[col]]
        for r in range(n):
            if r != col and M[r][col]:
                fctr = M[r][col]
                M[r] = [x ^ rs.mul(fctr, y) for x, y in zip(M[r], M[col])]
    return [row[n:] for row in M]


def _gf_matrix_mul(rs, M, B):
    """GF(2^8) 矩阵 M 乘以列向量组 B（每列一个等长 bytearray）。
    逐字节位置独立计算，返回 m 个 bytearray。"""
    m = len(M)
    out = []
    for r in range(m):
        acc = None
        for c in range(m):
            coef = M[r][c]
            if not coef:
                continue
            t = bytes(B[c]).translate(rs.table(coef))
            if acc is None:
                acc = bytearray(t)
            else:
                _xor_into(acc, 0, t)
        if acc is None:
            acc = bytearray(len(B[0]))
        out.append(acc)
    return out


def _recover_missing(f, hdr, out, missing, mem_limit, progress, offsets):
    """用 Reed-Solomon 校验块流式恢复损坏块并回填 out。

    峰值内存 ≈ min(mem_limit, (m+1) × block_size)，m = 损坏块数：
    内存够则整块求解；不够则按列切片循环（每片把已知块重读一遍，
    单遍内存仍不超限制）。恢复出的块逐块通过 CRC 复核后才允许使用。
    编码（Cauchy-MDS / Vandermonde）取自归档头的 rs_codec 字段。
    """
    n = hdr['num_blocks']
    bs = hdr['block_size']
    codec = hdr.get('rs_codec', CODEC_VANDERMONDE)
    m = len(missing)
    parity_off = offsets[-1] + hdr['block_len'][-1]  # 数据区结束 = 校验区开始
    # 先确定可用校验块（流式 CRC，不整载入内存）
    rows = []
    for j in range(hdr['num_parity']):
        f.seek(parity_off + j * bs)
        crc, got = _crc_stream(f, bs, mem_limit)
        if got == bs and crc == hdr['parity_crc'][j]:
            rows.append(j)
        if len(rows) >= m:
            break
    if len(rows) < m:
        raise ArchiveError('损坏 %d 块，超出可恢复上限 %d 块，归档无法修复'
                           % (m, len(rows)))
    rows = rows[:m]
    missing_set = set(missing)
    rs = ReedSolomon()
    A = [[rs.coeff_any(codec, rows[j], i, n) for i in missing] for j in range(m)]
    A_inv = _gf_matrix_inv(rs, A)
    # 列切片循环：工作集 = m 个 RHS 缓冲 + 1 个读缓冲 ≤ mem_limit
    slice_len = max(1, mem_limit // (m + 1))
    total_slices = -(-bs // slice_len)
    for sn, s0 in enumerate(range(0, bs, slice_len)):
        L = min(slice_len, bs - s0)
        B = []
        for j in rows:
            f.seek(parity_off + j * bs + s0)
            pb = _read_exact(f, L)
            if len(pb) < L:
                pb += b'\x00' * (L - len(pb))
            B.append(bytearray(pb))
        for i in range(n):
            if i in missing_set:
                continue
            real = hdr['block_len'][i]
            if s0 >= real:
                continue  # 尾块不足部分按零参与运算（零对 XOR 无贡献）
            f.seek(offsets[i] + s0)
            blk = _read_exact(f, min(L, real - s0))
            for jj in range(m):
                c = rs.coeff_any(codec, rows[jj], i, n)
                if c:
                    _xor_into(B[jj], 0, blk.translate(rs.table(c)))
        X = _gf_matrix_mul(rs, A_inv, B)
        for idx, xi in zip(missing, X):
            real = hdr['block_len'][idx]
            if s0 >= real:
                continue
            out.seek(offsets[idx] - hdr['data_offset'] + s0)
            out.write(bytes(xi[:min(L, real - s0)]))
        _rep(progress, 'Reed-Solomon 修复分片 %d/%d（共 %d 个损坏块）'
             % (sn + 1, total_slices, m), 25 + int(20 * (sn + 1) / total_slices))
    # 恢复结果必须逐块通过 CRC，防止恢复出错误数据被当作用户数据解包
    for idx in missing:
        real = hdr['block_len'][idx]
        out.seek(offsets[idx] - hdr['data_offset'])
        crc, got = _crc_stream(out, real, mem_limit)
        if got != real or crc != hdr['block_crc'][idx]:
            raise ArchiveError('恢复数据未通过 CRC 校验，归档无法安全修复')


def _repair_payload(path, hdr, progress, mem_limit):
    """流式校验/修复全部分块，把载荷写入临时文件并返回其路径。

    峰值内存不超过 mem_limit。临时文件由调用方负责删除。
    """
    offsets = _block_offsets(hdr)
    fd, payload = tempfile.mkstemp(prefix='.arhp_payload_', dir=app_temp_dir())
    try:
        with os.fdopen(fd, 'w+b') as out:
            out.truncate(hdr['payload_size'])  # 预分配，损坏块留洞后回填
            with open(path, 'rb') as f:
                f.seek(hdr['data_offset'])
                missing = _verify_blocks_to(f, hdr, out, mem_limit, progress,
                                            offsets)
                if not missing:
                    return payload
                if not hdr['num_parity']:
                    raise ArchiveError(
                        '%d 个数据块损坏且无法恢复（归档未生成恢复数据）'
                        % len(missing))
                _recover_missing(f, hdr, out, missing, mem_limit, progress,
                                 offsets)
        return payload
    except Exception:
        try:
            os.unlink(payload)
        except OSError:
            pass
        raise


def _safe_target(outdir, name, check_existing=True):
    """返回安全目标路径，并拒绝绝对路径、盘符、路径穿越及符号链接父路径。

    除词法校验外，还检查现存路径组件：防止归档写入时跟随输出目录中
    预先放置的符号链接，或跟随前序归档条目创建的符号链接越出目标树。
    测试归档（不写盘）只执行与文件系统状态无关的词法检查。
    """
    raw_name = str(name)
    name = raw_name.replace('\\', '/')
    parts = [p for p in name.split('/') if p not in ('', '.')]
    if (not parts or name.startswith('/') or re.match(r'^[a-zA-Z]:', name)
            or '..' in parts or '\x00' in name):
        raise ArchiveError('归档内包含不安全路径: %r' % raw_name)
    if len(name) > 4096 or any(len(p) > 255 for p in parts):
        raise ArchiveError('归档内路径长度超出安全范围: %r' % raw_name)
    if any(':' in p for p in parts):  # Windows ADS / drive 语法，跨平台统一拒绝
        raise ArchiveError('归档内包含不安全路径组件: %r' % raw_name)
    root = os.path.realpath(os.path.abspath(outdir))
    target = root
    for index, part in enumerate(parts):
        target = os.path.join(target, part)
        if check_existing and os.path.lexists(target):
            if os.path.islink(target):
                raise ArchiveError('解压目标路径包含符号链接，已拒绝写入: %s' % target)
            if index < len(parts) - 1 and not os.path.isdir(target):
                raise ArchiveError('解压目标父路径不是目录: %s' % target)
    try:
        if os.path.commonpath((root, os.path.abspath(target))) != root:
            raise ArchiveError('归档内包含越界路径: %r' % raw_name)
    except ValueError:
        raise ArchiveError('归档内包含跨盘符路径: %r' % raw_name)
    return target


def _write_extracted_file(target, source, mode=None, mtime=None):
    """在目标同目录写临时文件并原子替换，避免跟随目标文件硬链接。"""
    parent = os.path.dirname(target) or os.curdir
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix='.arhp_extract_', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as dst:
            shutil.copyfileobj(source, dst, 1 << 20)
            dst.flush()
            os.fsync(dst.fileno())
        # 权限掩码收紧为 0o777——不原样恢复 setuid/setgid/sticky 位，
        # 避免解压即植入特权文件
        os.chmod(tmp_path, (mode & 0o777) if mode is not None else 0o644)
        if mtime is not None:
            try:
                os.utime(tmp_path, (mtime, mtime))
            except (OSError, OverflowError, ValueError):
                pass
        # replace 会替换目录项本身，而不是写入可能存在的硬链接目标。
        os.replace(tmp_path, target)
        tmp_path = None
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


class _CountingReader:
    """包装文件对象，统计读取进度。"""

    def __init__(self, f, total, cb):
        self.f = f
        self.total = max(total, 1)
        self.cb = cb
        self.done = 0
        self._last_pct = -1

    def read(self, size=-1):
        b = self.f.read(size)
        self.done += len(b)
        pct = int(100 * self.done / self.total)
        if pct != self._last_pct:  # 进度节流，避免每次 read 都回调刷屏
            self._last_pct = pct
            self.cb(pct)
        return b


class _NullCtx:
    """把任意读对象包成上下文管理器（仅存储模式用）。"""

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        return self.f

    def __exit__(self, *exc):
        return False


def _decrypt_payload(payload, hdr, password, progress):
    """加密载荷解密到 <payload>.dec 并返回解密结果路径（明文载荷）。

    .arhp 加密归档解密前先校验归档头 HMAC（若归档含 header_mac），头被
    篡改立即报错；解密失败时清理两个临时文件。
    """
    dec = payload + '.dec'
    total = hdr.get('payload_size', 0)
    header_auth = None
    mac = hdr.get(_HEADER_MAC_FIELD)
    if mac:
        # 读取端重算的规范化头 JSON 与写入端逐字节一致（同一份头内容）
        header_auth = (str(mac), _canonical_header_json(hdr))
    try:
        decrypt_file(payload, dec, hdr.get('crypto') or {}, password,
                     progress=lambda d, t: _rep(progress, 'AES-256-GCM 解密中...',
                                                50 + 8 * d // max(t, 1)),
                     total=total, header_auth=header_auth)
    except Exception:
        for p in (payload, dec):
            try:
                os.unlink(p)
            except OSError:
                pass
        raise
    os.unlink(payload)
    return dec


def _norm_members(members):
    """把用户给出的成员名规范化为 tar 内统一使用的相对路径形式。"""
    if not members:
        return None
    out = set()
    for m in members:
        m = str(m).replace('\\', '/').lstrip('/')
        while m.endswith('/'):
            m = m[:-1]
        if m:
            out.add(m)
    return out or None


def _member_match(name, members):
    """name 是否命中 members 选择集（自身命中，或位于选中的目录之下）。"""
    if members is None:
        return True
    if name in members:
        return True
    return any(name.startswith(d + '/') for d in members)


def _normalize_member_name(raw):
    """把 tar 成员名规范化为统一相对路径形式。

    只剥离 './' 前缀序列（GNU tar 常见写法），不能用 lstrip('./')——
    它会剥掉顶层隐藏条目的前导点（'.ssh' → 'ssh'），导致列表显示名
    与磁盘真实文件名不一致。
    """
    name = str(raw).replace('\\', '/')
    while name.startswith('./'):
        name = name[2:]
    return name


def _register_member_name(name, is_dir, seen, source='归档'):
    """拒绝归档内大小写折叠后的重名与文件/目录层级冲突。

    重复目录条目（部分兼容性 ZIP 会重复写目录头）允许出现一次以上；
    文件重名一律拒绝，避免解压时静默覆盖。
    """
    key = _normalize_member_name(name).rstrip('/').casefold()
    if not key:
        return False
    previous = seen.get(key)
    if previous is not None:
        if is_dir and previous is True:
            return False
        raise ArchiveError('%s包含重复成员名: %r' % (source, name))
    parts = key.split('/')
    for i in range(1, len(parts)):
        parent = '/'.join(parts[:i])
        if parent in seen and not seen[parent]:
            raise ArchiveError('%s包含文件/目录层级冲突: %r' % (source, name))
    if not is_dir:
        prefix = key + '/'
        if any(existing.startswith(prefix) for existing in seen):
            raise ArchiveError('%s包含文件/目录层级冲突: %r' % (source, name))
    seen[key] = bool(is_dir)
    return True


def _extract_tar(tar, outdir, progress, write, members=None):
    """遍历 tar 流并安全写出。返回处理的普通文件数（含硬链接条目）。"""
    count = 0
    dirs = []
    seen_names = {}
    hardlinks = []  # (目标路径, 源成员路径, 条目名)，收尾阶段统一还原
    for m in tar:
        name = _normalize_member_name(m.name).rstrip('/')
        if not name or name == '.':
            continue  # tar 常见的 './' 目录项，无实际内容
        if not _member_match(name, members):
            continue
        is_dir = m.isdir()
        if not _register_member_name(name, is_dir, seen_names, 'tar 归档'):
            continue
        target = _safe_target(outdir, name, check_existing=write)
        if m.isdir():
            if write:
                os.makedirs(target, exist_ok=True)
                dirs.append((target, m.mtime))
        elif m.issym():
            if write:
                link = str(m.linkname).replace('\\', '/')
                dest = os.path.normpath(os.path.join(os.path.dirname(target), link))
                root = os.path.realpath(os.path.abspath(outdir))
                try:
                    real_dest = os.path.realpath(os.path.abspath(dest))
                    inside = os.path.commonpath([root, real_dest]) == root
                except ValueError:
                    inside = False  # Windows 跨盘符等情况按不安全链接跳过
                if inside:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    if os.path.lexists(target):
                        os.remove(target)
                    os.symlink(m.linkname, target)
        elif m.islnk():
            # 硬链接（tar 内指向另一成员）：以 os.link 还原（失败退化为
            # 复制内容），目标尚未解压（前向引用）的留到收尾重试，
            # 仍缺失则明确报错——绝不静默丢弃条目。
            if write:
                try:
                    src = _safe_target(outdir, _normalize_member_name(m.linkname))
                except ArchiveError:
                    src = None
                if src is not None:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    hardlinks.append((target, src, name))
            count += 1
        elif m.isreg():
            if write:
                src = tar.extractfile(m)
                if src is None:
                    continue
                with src:
                    _write_extracted_file(target, src, mode=m.mode, mtime=m.mtime)
            else:
                src = tar.extractfile(m)
                if src is not None:
                    with src:
                        while src.read(1 << 20):
                            pass
            count += 1
            if count % 200 == 0:
                _rep(progress, '已还原 %d 个文件' % count, 95)
    if write:
        # 目录 mtime 最后设置（子文件写入会刷新目录时间）
        for d, mt in reversed(dirs):
            try:
                os.utime(d, (mt, mt))
            except OSError:
                pass
        # 硬链接收尾：此时前向引用的目标成员也已写出
        for target, src, name in hardlinks:
            if os.path.lexists(target):
                os.remove(target)
            try:
                os.link(src, target)
            except OSError:
                if os.path.isfile(src):
                    shutil.copyfile(src, target)
                else:
                    raise ArchiveError('硬链接目标缺失: %s -> %s'
                                       % (name, os.path.basename(src)))
    return count


def _restore(path, hdr, outdir, progress, write, password=None, members=None,
             mem_limit=DEFAULT_MEM_LIMIT):
    """校验/修复分块（流式，载荷工作集 ≤ mem_limit）、按需解密，解包 tar。

    write=False 时只做测试。members: 只处理给定名称（文件或目录子树）
    的条目；None 表示全部。返回处理的普通文件数。
    """
    members = _norm_members(members)
    if write:
        os.makedirs(outdir, exist_ok=True)
    payload_path = _repair_payload(path, hdr, progress, mem_limit)
    try:
        if hdr.get('encrypted'):
            if not password:
                raise ArchiveError('该归档已加密，需要提供密码（-p/--password）')
            _rep(progress, 'AES-256-GCM 解密校验中...', 48)
            payload_path = _decrypt_payload(payload_path, hdr, password,
                                            progress)
        with open(payload_path, 'rb') as pf:
            # 总量取实际载荷文件大小：加密归档的 payload_size 是密文大小，
            # 而这里读的是解密后的明文文件
            counter = _CountingReader(pf, os.path.getsize(payload_path),
                                      lambda p: _rep(progress, '解压中...',
                                                     60 + p * 35 // 100))
            if hdr.get('compression', 'zstd') == 'store':
                src_ctx = _NullCtx(counter)
            else:
                src_ctx = open_reader(counter)
            with src_ctx as zr, tarfile.open(fileobj=zr, mode='r|') as tar:
                return _extract_tar(tar, outdir, progress, write, members)
    finally:
        # 载荷临时文件（mkstemp 产生，位于 app_temp_dir）用完即删，避免缓存堆积
        if payload_path:
            try:
                os.unlink(payload_path)
            except OSError:
                pass


def extract_archive(path, outdir='.', progress=None, password=None,
                    members=None, mem_limit=DEFAULT_MEM_LIMIT):
    """解压归档到 outdir，自动修复可修复的损坏。返回解压出的文件数。

    path: .arh2 / .arhp / .zip / .7z（按扩展名自动识别）；支持多分卷归档
    （给出任一分卷或基名均可，会自动合并到临时目录后解压）；
    members: 可选，只解压这些条目（文件或目录子树）；
    mem_limit: 内存限制（字节，16M-1024M，默认 128M），.arh2/.arhp 分块
               校验/修复按块流式进行，载荷工作集不超此值。
    """
    mem_limit = _check_mem_limit(mem_limit)
    with _ArchiveInput(path, progress) as real_path:
        return _extract_archive(real_path, outdir, progress=progress,
                                password=password, members=members,
                                mem_limit=mem_limit)


def _extract_archive(path, outdir='.', progress=None, password=None,
                     members=None, mem_limit=DEFAULT_MEM_LIMIT):
    """extract_archive 的实现（path 已是真实单文件路径）。"""
    fmt = detect_format(path)
    if fmt == 'zip':
        return _extract_zip(path, outdir, progress=progress, password=password,
                            members=members)
    if fmt == '7z':
        return _extract_7z(path, outdir, progress=progress, password=password,
                           members=members)
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    count = _restore(path, hdr, outdir, progress, write=True,
                     password=password, members=members, mem_limit=mem_limit)
    _rep(progress, '完成，共 %d 个文件' % count, 100)
    return count


def test_archive(path, progress=None, password=None,
                 mem_limit=DEFAULT_MEM_LIMIT):
    """测试归档完整性（含修复能力与加密认证），不写出文件。

    返回归档内普通文件数。支持多分卷归档（任一分卷或基名均可）。
    """
    mem_limit = _check_mem_limit(mem_limit)
    with _ArchiveInput(path, progress) as real_path:
        return _test_archive(real_path, progress=progress, password=password,
                             mem_limit=mem_limit)


def _test_archive(path, progress=None, password=None,
                  mem_limit=DEFAULT_MEM_LIMIT):
    """test_archive 的实现（path 已是真实单文件路径）。"""
    fmt = detect_format(path)
    if fmt == 'zip':
        return _test_zip(path, progress=progress, password=password)
    if fmt == '7z':
        return _test_7z(path, progress=progress, password=password)
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    count = _restore(path, hdr, '.', progress, write=False, password=password,
                     mem_limit=mem_limit)
    _rep(progress, '归档完好，共 %d 个文件' % count, 100)
    return count


# ---- zip 解压 / 测试 ----

def _zip_pwd(password):
    if isinstance(password, str):
        return password.encode('utf-8')
    return password


def _extract_zip(path, outdir, progress=None, password=None, members=None):
    import zipfile
    import time as _time
    members = _norm_members(members)
    os.makedirs(outdir, exist_ok=True)
    pwd = _zip_pwd(password)
    count = 0
    seen_names = {}
    _rep(progress, '解压中 (zip)...', 5)
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        total = max(len(infos), 1)
        for info in infos:
            name = str(info.filename).replace('\\', '/').lstrip('/')
            is_dir = name.endswith('/')
            if is_dir:
                name = name.rstrip('/')
            if not _member_match(name, members):
                continue
            # 与 tar 解压路径一致：重复成员名/文件目录层级冲突一律拒绝，
            # 避免恶意或损坏 zip 让条目静默互相覆盖
            if not _register_member_name(name, is_dir, seen_names, 'zip 归档'):
                continue
            target = _safe_target(outdir, name)
            if is_dir:
                os.makedirs(target, exist_ok=True)
                continue
            # 符号链接条目（Unix 模式位 S_IFLNK，由本程序/兼容工具写入）：
            # 按链接本身还原，并像 tar 路径一样校验链接目标不越出解压目录
            if stat.S_ISLNK(info.external_attr >> 16):
                try:
                    with zf.open(info, pwd=pwd) as f:
                        linkname = f.read().decode('utf-8')
                except RuntimeError as e:
                    raise ArchiveError('解压失败（%s）：%s'
                                       % (name, '密码错误或需要密码'
                                          if 'password' in str(e).lower() else e))
                except (zipfile.BadZipFile, zlib.error):
                    raise ArchiveError('CRC/压缩数据校验失败: %s' % name)
                dest = os.path.normpath(os.path.join(os.path.dirname(target),
                                                     linkname))
                root = os.path.realpath(os.path.abspath(outdir))
                try:
                    real_dest = os.path.realpath(os.path.abspath(dest))
                    inside = os.path.commonpath([root, real_dest]) == root
                except ValueError:
                    inside = False  # Windows 跨盘符等情况按不安全链接跳过
                if inside:
                    os.makedirs(os.path.dirname(target) or outdir,
                                exist_ok=True)
                    if os.path.lexists(target):
                        os.remove(target)
                    os.symlink(linkname, target)
                    count += 1
                continue
            try:
                src = zf.open(info, pwd=pwd)
            except RuntimeError as e:
                raise ArchiveError('解压失败（%s）：%s'
                                   % (name, '密码错误或需要密码' if 'password' in str(e).lower() else e))
            # 与 tar 解压一致的原子写入：写同目录临时文件后 os.replace，
            # 中断不留半文件、不直接截断/跟随已存在目标的硬链接
            mtime = None
            try:
                mtime = _time.mktime(info.date_time + (0, 0, -1))
            except (OverflowError, ValueError, OSError):
                mtime = None
            try:
                with src:
                    _write_extracted_file(target, src, mtime=mtime)
            except RuntimeError as e:
                raise ArchiveError('解压失败（%s）：%s'
                                   % (name, '密码错误或需要密码' if 'password' in str(e).lower() else e))
            except (zipfile.BadZipFile, zlib.error):
                raise ArchiveError('CRC/压缩数据校验失败: %s' % name)
            count += 1
            if count % 200 == 0:
                _rep(progress, '已解压 %d 个文件' % count,
                     5 + int(90 * count / total))
    _rep(progress, '完成，共 %d 个文件' % count, 100)
    return count


def _test_zip(path, progress=None, password=None):
    import zipfile
    pwd = _zip_pwd(password)
    count = 0
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        total = max(len(infos), 1)
        for info in infos:
            if info.is_dir():
                continue
            try:
                with zf.open(info, pwd=pwd) as f:
                    while f.read(1 << 20):
                        pass
            except RuntimeError as e:
                raise ArchiveError('测试失败（%s）：%s' % (info.filename, e))
            except (zipfile.BadZipFile, zlib.error):
                raise ArchiveError('CRC/压缩数据校验失败: %s' % info.filename)
            count += 1
            _rep(progress, '已测试 %d 个文件' % count, int(95 * count / total))
    _rep(progress, '归档完好，共 %d 个文件' % count, 100)
    return count


# ---- 7z 解压 / 测试 ----

def _check_7z_password(zf, password):
    """py7zr 加密归档未给密码时抛出可读的 ArchiveError。"""
    try:
        if zf.needs_password() and not password:
            raise ArchiveError('该 7z 归档已加密，需要提供密码（-p/--password）')
    except AttributeError:
        pass  # 旧版 py7zr 无 needs_password，让底层自行报错


def _is_7z_bad_header_error(exc):
    """识别 py7zr 的头损坏/密码错误异常（各版本异常位置可能不同）。"""
    try:
        import py7zr
        cls = getattr(py7zr, 'Bad7zFile', None)
        if cls is None:
            cls = getattr(getattr(py7zr, 'exceptions', py7zr), 'Bad7zFile', None)
        return isinstance(cls, type) and isinstance(exc, cls)
    except Exception:
        return False


def _is_7z_password_or_header_error(exc, password):
    """py7zr 对错误密码可能抛 Bad7zFile 或 TypeError("Unknown field")。"""
    if _is_7z_bad_header_error(exc):
        return True
    if not password:
        return False
    msg = str(exc).lower()
    return isinstance(exc, TypeError) and 'unknown field' in msg


def _7z_password_exc():
    """py7zr 各版本“需要密码”异常类元组（用于 except 子句）。"""
    try:
        import py7zr
        excs = []
        for name in ('PasswordRequired', 'PasswordRequiredException'):
            e = getattr(getattr(py7zr, 'exceptions', py7zr), name, None)
            if isinstance(e, type) and issubclass(e, Exception):
                excs.append(e)
        # 找不到专用异常时返回空元组；绝不能回退成 Exception，否则会误报所有损坏。
        return tuple(excs)
    except Exception:
        return ()


def _validate_7z_names(items, source='7z 归档', register=True):
    """7z 解压前的成员名统一预检（与 tar/zip 解压建立同一安全边界）。

    不让路径安全完全依赖 py7zr 的实现细节：逐项拒绝 '../'、绝对路径、
    Windows 盘符路径、重复成员名与文件/目录层级冲突。名称检查是词法级
    的，与是否实际写盘无关。items 可以是 py7zr FileInfo 对象（按
    is_directory 属性判定目录）或纯名称字符串；register=False 时只做
    词法校验、不登记重名/冲突（用于用户选择集的补充校验）。
    """
    seen_names = {}
    for item in items:
        is_dir = bool(getattr(item, 'is_directory', False))
        name = str(getattr(item, 'filename', item)).replace('\\', '/').lstrip('/')
        if name.endswith('/'):
            name = name.rstrip('/')
            is_dir = True
        if not name:
            continue
        # 词法安全检查（与 _safe_target 对齐；最终写入前还会逐路径复查）
        if (name.startswith('/') or re.match(r'^[a-zA-Z]:', name)
                or '..' in name.split('/') or '\x00' in name):
            raise ArchiveError('%s内包含不安全路径: %r' % (source, name))
        if register and not _register_member_name(name, is_dir, seen_names,
                                                  source):
            continue  # 重复目录项（兼容性写法），允许出现
    return seen_names


def _extract_7z(path, outdir, progress=None, password=None, members=None):
    py7zr = _load_7z()
    os.makedirs(outdir, exist_ok=True)
    members = _norm_members(members)
    _rep(progress, '解压中 (7z)...', 10)
    count = 0
    try:
        with py7zr.SevenZipFile(path, 'r', password=password or None) as zf:
            _check_7z_password(zf, password)
            # 解压前对全部成员名做统一预检（重复/层级冲突/越界路径），
            # 拒绝在写出任何文件之前——避免部分解压后才报错
            _validate_7z_names(zf.list())
            if members:
                # 用户选择集只做词法补充校验（重名/冲突已在全量预检覆盖）
                _validate_7z_names(sorted(members), source='选择集',
                                   register=False)
                zf.extract(path=outdir, targets=sorted(members), recursive=True)
            else:
                zf.extractall(path=outdir)
            try:
                count = sum(1 for f in zf.list()
                            if not getattr(f, 'is_directory', False))
            except Exception:
                count = 0
    except ArchiveError:
        raise
    except _7z_password_exc():
        raise ArchiveError('该 7z 归档已加密，需要提供密码（-p/--password）')
    except Exception as e:
        msg = str(e)
        if ('password' in msg.lower()
                or _is_7z_password_or_header_error(e, password)):
            raise ArchiveError('7z 解压失败：密码错误或归档头已损坏')
        raise ArchiveError('7z 解压失败: %s' % msg)
    _rep(progress, '完成，共 %d 个文件' % count, 100)
    return count


def _test_7z(path, progress=None, password=None):
    py7zr = _load_7z()
    _rep(progress, '测试中 (7z)...', 10)
    try:
        with py7zr.SevenZipFile(path, 'r', password=password or None) as zf:
            _check_7z_password(zf, password)
            ok = zf.test()
            if ok is False:
                raise ArchiveError('7z 归档 CRC 校验失败')
    except ArchiveError:
        raise
    except _7z_password_exc():
        raise ArchiveError('该 7z 归档已加密，需要提供密码（-p/--password）')
    except Exception as e:
        msg = str(e)
        if ('password' in msg.lower()
                or _is_7z_password_or_header_error(e, password)):
            raise ArchiveError('7z 测试失败：密码错误或归档头已损坏')
        raise ArchiveError('7z 测试失败: %s' % msg)
    _rep(progress, '归档完好', 100)
    return 0


# ---------------------------------------------------------------- 信息 / 列目录

SUPPORTED_FORMATS = ('arh2', 'arhp', 'zip', '7z')
_FORMAT_EXT = {'.arh2': 'arh2', '.arhp': 'arhp', '.zip': 'zip', '.7z': '7z'}


def detect_format(path):
    """按扩展名识别归档格式，返回 'arh2' / 'arhp' / 'zip' / '7z'。

    无法识别时抛出 ArchiveError。
    """
    ext = os.path.splitext(str(path))[1].lower()
    fmt = _FORMAT_EXT.get(ext)
    if not fmt:
        raise ArchiveError('无法识别的归档格式: %s（支持 .arh2 / .arhp / .zip / .7z）' % path)
    return fmt


def info_archive(path):
    """返回归档信息字典（不解压载荷）。支持全部四种格式，
    以及多分卷归档（任一分卷或基名均可）。"""
    with _ArchiveInput(path) as real_path:
        return _info_archive(real_path)


def _info_archive(path):
    """info_archive 的实现（path 已是真实单文件路径）。"""
    fmt = detect_format(path)
    size = os.path.getsize(path)
    if fmt == 'zip':
        import zipfile
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
        n_files = sum(1 for i in infos if not i.is_dir())
        encrypted = any(bool(i.flag_bits & 0x1) for i in infos)
        return {'path': path, 'size': size, 'format': 'zip',
                'method': 'deflate/store', 'compression': 'deflate',
                'zstd_level': None, 'encrypted': encrypted,
                'num_files': n_files, 'num_dirs': len(infos) - n_files,
                'unpacked_size': sum(i.file_size for i in infos),
                'packed_size': sum(i.compress_size for i in infos)}
    if fmt == '7z':
        py7zr = _load_7z()
        try:
            with py7zr.SevenZipFile(path, 'r') as zf:
                try:
                    encrypted = bool(zf.needs_password())
                except Exception:
                    encrypted = False
                files = zf.list()
        except _7z_password_exc():
            encrypted = True
            files = []
        n_files = sum(1 for f in files if not getattr(f, 'is_directory', False))
        return {'path': path, 'size': size, 'format': '7z',
                'method': 'LZMA2', 'compression': 'lzma2',
                'zstd_level': None, 'encrypted': encrypted,
                'num_files': n_files, 'num_dirs': len(files) - n_files,
                'unpacked_size': sum(getattr(f, 'uncompressed', 0) or 0 for f in files),
                'packed_size': None}
    hdr = open_archive(path)
    crypto_info = hdr.get('crypto') if isinstance(hdr.get('crypto'), dict) else {}
    kdf_label = {KDF_PBKDF2: 'AES-256-GCM (PBKDF2)',
                 KDF_ARGON2ID: 'AES-256-GCM (Argon2id)'}.get(
        crypto_info.get('kdf', KDF_PBKDF2), 'AES-256-GCM')
    if fmt == 'arh2':
        trailer = hdr.get('_trailer') or {}
        cd = trailer.get('cd') if isinstance(trailer.get('cd'), dict) else {}
        return {
            'path': path,
            'size': size,
            'format': 'arh2',
            'version': hdr.get('version'),
            'rs_codec': hdr.get('rs_codec'),
            'header_protected': True,
            'central_directory': True,
            'cd_encrypted': bool(cd.get('encrypted')),
            'header_mac': bool(hdr.get(_HEADER_MAC_FIELD)),
            'method': hdr.get('method'),
            'compression': hdr.get('compression', 'zstd'),
            'zstd_level': hdr.get('zstd_level'),
            'encrypted': hdr.get('encrypted', False),
            'crypto_kdf': kdf_label if hdr.get('encrypted') else None,
            'block_size': hdr.get('block_size'),
            'num_blocks': hdr.get('num_blocks'),
            'num_parity': hdr.get('num_parity'),
            'payload_size': hdr.get('payload_size'),
        }
    return {
        'path': path,
        'size': size,
        'format': 'arhp',
        'version': hdr.get('version'),
        'rs_codec': hdr.get('rs_codec'),
        'header_protected': hdr.get('version', 0) >= 3,
        'central_directory': False,
        'cd_encrypted': False,
        'header_mac': bool(hdr.get(_HEADER_MAC_FIELD)),
        'method': hdr.get('method'),
        'compression': hdr.get('compression', 'zstd'),
        'zstd_level': hdr.get('zstd_level'),
        'encrypted': hdr.get('encrypted', False),
        'crypto_kdf': kdf_label if hdr.get('encrypted') else None,
        'block_size': hdr.get('block_size'),
        'num_blocks': hdr.get('num_blocks'),
        'num_parity': hdr.get('num_parity'),
        'payload_size': hdr.get('payload_size'),
    }


def list_archive(path, progress=None, password=None,
                 mem_limit=DEFAULT_MEM_LIMIT):
    """列出归档内容（像 7-Zip 的列目录/预览），返回条目字典列表。

    每个条目: {'name', 'size', 'compressed', 'mtime', 'is_dir', 'crc',
               'method', 'encrypted'}
    - .arh2 走受保护的中心化目录快路径，无需解压载荷；
    - .arhp 的 tar 载荷无中心目录，需流式处理载荷（加密时含解密）——
      这是该格式的固有成本，info 命令不受影响；
    - compressed 为 None 表示该格式不记录单项压缩后大小；
    - mtime 为 float 时间戳（unix），未知为 None；
    - crc 为 32 位整数或 None；method 为算法名字符串或 None。
    需要密码的加密归档必须传入 password。
    支持多分卷归档（任一分卷或基名均可）。
    mem_limit: 内存限制（字节，16M-1024M，默认 128M），仅影响 .arh2/.arhp
               分块校验/修复的载荷工作集。
    """
    mem_limit = _check_mem_limit(mem_limit)
    with _ArchiveInput(path, progress) as real_path:
        return _list_archive(real_path, progress=progress, password=password,
                             mem_limit=mem_limit)


def _list_archive(path, progress=None, password=None,
                  mem_limit=DEFAULT_MEM_LIMIT):
    """list_archive 的实现（path 已是真实单文件路径）。"""
    fmt = detect_format(path)
    if fmt == 'zip':
        return _list_zip(path)
    if fmt == '7z':
        return _list_7z(path, password=password)
    if fmt == 'arh2':
        return _list_arh2(path, progress=progress, password=password)
    return _list_arhp(path, progress=progress, password=password,
                      mem_limit=mem_limit)


# ---- ARH2 中心化目录快速列举 ----

def _list_arh2(path, progress=None, password=None):
    """.arh2 列目录：读取受 RS 保护的中心化目录，无需解压载荷。"""
    hdr = open_archive(path)
    trailer = hdr.get('_trailer')
    entries = _read_central_directory(path, trailer, hdr, password)
    _rep(progress, '共 %d 个条目（中心化目录）' % len(entries), 100)
    return entries


def _read_central_directory(path, trailer, hdr, password):
    """读取 .arh2 中心化目录：RS 保护（自动修复损坏块）+ 可选解密。

    返回 7-Zip 风格的条目字典列表。
    目录是冗余副本，extract/test 仍以 tar 流为权威；此处仍做名称
    规范化与白名单字段校验，防止损坏目录导致下游异常。
    """
    cd = trailer.get('cd')
    if not isinstance(cd, dict):
        raise ArchiveError('归档尾注中中心化目录布局损坏')
    file_size = os.path.getsize(path)
    region_end = file_size - int(hdr.get('_trailer_len') or 0)
    with open(path, 'rb') as f:
        blob = _recover_blob(f, region_end, cd, '中心化目录')
    if cd.get('encrypted'):
        if not password:
            raise ArchiveError('该归档的中心目录已加密，需要提供密码（-p/--password）')
        blob = _decrypt_blob(blob, cd.get('crypto') or {}, password)
    try:
        raw = json.loads(blob.decode('utf-8'))
    except Exception:
        raise ArchiveError('中心化目录损坏（JSON 解析失败）')
    if not isinstance(raw, list):
        raise ArchiveError('中心化目录类型错误')
    method = ('zstd 级别 %s' % hdr.get('zstd_level', '?')) \
        if hdr.get('compression', 'zstd') == 'zstd' else 'store'
    encrypted = bool(hdr.get('encrypted'))
    entries = []
    seen_names = {}
    for index, e in enumerate(raw):
        if not isinstance(e, dict) or not isinstance(e.get('name'), str):
            raise ArchiveError('中心化目录条目 %d 损坏' % index)
        raw_name = e['name']
        name = _normalize_member_name(raw_name)
        if (not name or name == '.' or name.startswith('/')
                or re.match(r'^[a-zA-Z]:', name) or '\x00' in name
                or '..' in name.split('/') or len(name) > 4096):
            raise ArchiveError('中心化目录包含不安全成员名: %r' % raw_name)
        is_dir = e.get('is_dir')
        if not isinstance(is_dir, bool):
            raise ArchiveError('中心化目录条目 is_dir 类型错误')
        if is_dir:
            name = name.rstrip('/')
        elif name.endswith('/'):
            raise ArchiveError('中心化目录文件名不应以斜杠结尾')
        parts = name.split('/')
        if any(not part or part in ('.', '..') or ':' in part for part in parts):
            raise ArchiveError('中心化目录成员路径不规范: %r' % raw_name)
        if not _register_member_name(name, is_dir, seen_names, '中心化目录'):
            raise ArchiveError('中心化目录包含重复目录项: %r' % name)
        size = e.get('size')
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ArchiveError('中心化目录条目大小无效: %r' % name)
        if is_dir and size != 0:
            raise ArchiveError('中心化目录目录项大小必须为 0: %r' % name)
        mtime = e.get('mtime')
        if (not isinstance(mtime, (int, float)) or isinstance(mtime, bool)
                or not math.isfinite(float(mtime))):
            raise ArchiveError('中心化目录条目时间无效: %r' % name)
        mode = e.get('mode')
        if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
            raise ArchiveError('中心化目录条目权限无效: %r' % name)
        linkname = e.get('linkname')
        if linkname is not None and (not isinstance(linkname, str)
                                     or len(linkname) > 4096 or '\x00' in linkname):
            raise ArchiveError('中心化目录符号链接目标无效: %r' % name)
        if linkname is not None and (is_dir or size != 0):
            raise ArchiveError('中心化目录符号链接元数据矛盾: %r' % name)
        entries.append({
            'name': name,
            'size': 0 if is_dir else size,
            'compressed': None,
            'mtime': float(mtime),
            'is_dir': is_dir,
            'crc': None,
            'method': method,
            'encrypted': encrypted,
        })
    return entries


def _list_arhp(path, progress=None, password=None,
               mem_limit=DEFAULT_MEM_LIMIT):
    """列出 .arhp 内容：流式校验/修复分块 → 解密 → 流式读 tar 头信息。

    峰值内存不超过 mem_limit。
    """
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    method = 'zstd 级别 %s' % hdr['zstd_level'] \
        if hdr.get('compression', 'zstd') == 'zstd' else 'store'
    encrypted = bool(hdr.get('encrypted'))
    entries = []
    payload_path = _repair_payload(path, hdr, progress, mem_limit)
    try:
        _rep(progress, '列出归档内容...', 45)
        if hdr.get('encrypted'):
            if not password:
                raise ArchiveError('该归档已加密，需要提供密码（-p/--password）')
            payload_path = _decrypt_payload(payload_path, hdr, password,
                                            progress)
        with open(payload_path, 'rb') as pf:
            # 总量取实际载荷文件大小（加密归档 payload_size 为密文大小）
            counter = _CountingReader(pf, os.path.getsize(payload_path),
                                      lambda p: _rep(progress, '列出归档内容...',
                                                     45 + p * 50 // 100))
            if hdr.get('compression', 'zstd') == 'store':
                src_ctx = _NullCtx(counter)
            else:
                src_ctx = open_reader(counter)
            with src_ctx as zr, tarfile.open(fileobj=zr, mode='r|') as tar:
                for m in tar:
                    # 硬链接（islnk）也列出（此前被静默跳过）
                    if not (m.isdir() or m.isreg() or m.issym() or m.islnk()):
                        continue
                    name = _normalize_member_name(m.name)
                    if not name or name == '.':
                        continue
                    entries.append({
                        'name': name.rstrip('/') if m.isdir() else name,
                        'size': 0 if m.isdir() else m.size,
                        'compressed': None,  # tar 流不记录单项压缩后大小
                        'mtime': float(m.mtime) if m.mtime else None,
                        'is_dir': m.isdir(),
                        'crc': None,
                        'method': method,
                        'encrypted': encrypted,
                    })
    finally:
        # 载荷临时文件（mkstemp 产生，位于 app_temp_dir）用完即删，避免缓存堆积
        if payload_path:
            try:
                os.unlink(payload_path)
            except OSError:
                pass
    _rep(progress, '共 %d 个条目' % len(entries), 100)
    return entries


def _list_zip(path):
    import zipfile
    import time as _time
    entries = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = str(info.filename).replace('\\', '/').lstrip('/')
            is_dir = name.endswith('/')
            if is_dir:
                name = name.rstrip('/')
            methods = {zipfile.ZIP_STORED: 'store', zipfile.ZIP_DEFLATED: 'deflate',
                       getattr(zipfile, 'ZIP_BZIP2', 12): 'bzip2',
                       getattr(zipfile, 'ZIP_LZMA', 14): 'lzma'}
            try:
                mtime = _time.mktime(info.date_time + (0, 0, -1))
            except Exception:
                mtime = None
            entries.append({
                'name': name,
                'size': info.file_size,
                'compressed': info.compress_size,
                'mtime': mtime,
                'is_dir': is_dir,
                'crc': info.CRC,
                'method': methods.get(info.compress_type, str(info.compress_type)),
                'encrypted': bool(info.flag_bits & 0x1),
            })
    return entries


def _list_7z(path, password=None):
    import datetime
    py7zr = _load_7z()
    entries = []
    try:
        with py7zr.SevenZipFile(path, 'r', password=password or None) as zf:
            for f in zf.list():
                name = str(f.filename).replace('\\', '/').lstrip('/')
                is_dir = bool(getattr(f, 'is_directory', False))
                if is_dir:
                    name = name.rstrip('/')
                # 修改时间：py7zr 各版本字段不一，尽力取
                mtime = None
                for attr in ('creationtime', 'lastwritetime', 'mtime'):
                    v = getattr(f, attr, None)
                    if v is None:
                        continue
                    if isinstance(v, datetime.datetime):
                        try:
                            mtime = v.timestamp()
                        except Exception:
                            mtime = None
                    elif isinstance(v, (int, float)):
                        mtime = float(v) if v > 10**9 else None
                    if mtime:
                        break
                entries.append({
                    'name': name,
                    'size': getattr(f, 'uncompressed', 0) or 0,
                    'compressed': getattr(f, 'compressed', None),
                    'mtime': mtime,
                    'is_dir': is_dir,
                    'crc': getattr(f, 'crc32', None),
                    'method': getattr(f, 'compress_type', None) or '7z',
                    'encrypted': bool(getattr(f, 'is_encrypted', False)),
                })
    except ArchiveError:
        raise
    except _7z_password_exc():
        raise ArchiveError('该 7z 归档已加密，需要提供密码（-p/--password）')
    except Exception as e:
        if _is_7z_password_or_header_error(e, password):
            raise ArchiveError('7z 密码错误或归档头已损坏')
        raise
    return entries


# ======================================================================
# 命令行入口
# ======================================================================

# 用法::
#     arhp create -o out.arh2|out.arhp|out.zip|out.7z [选项] 文件/目录...
#     arhp extract 归档 [-o 目录] [-p 密码] [--only 名称...]
#     arhp test 归档 [-p 密码]
#     arhp info 归档
#     arhp list 归档 [-p 密码]      # 列出归档内容（预览）
#     arhp gui                      # 由主程序注入 run_gui 后启动图形界面
#
# 不带参数运行时（双击主程序）默认进 GUI（由主程序注入）；
# --headless 强制纯命令行模式（无参数时打印帮助）。


def _parse_size(s):
    s = str(s).strip().upper()
    mult = 1
    for suf, m in (('K', 1 << 10), ('M', 1 << 20), ('G', 1 << 30)):
        if s.endswith(suf):
            mult = m
            s = s[:-1]
            break
    return int(float(s) * mult)


def _mem_limit_arg(value):
    """解析 CLI --memory 参数：16M-1024M，默认 128M；越界直接退出。"""
    if value is None:
        return DEFAULT_MEM_LIMIT
    try:
        n = _parse_size(value)
    except (TypeError, ValueError):
        raise SystemExit('内存限制无效: %s（示例: 64M、512M）' % value)
    if not MIN_MEM_LIMIT <= n <= MAX_MEM_LIMIT:
        raise SystemExit('内存限制超出范围: %s（允许 16M - 1024M，默认 128M）'
                         % value)
    return n


def _progress(msg, pct):
    out = sys.stdout
    if out is None:  # pythonw 等无控制台环境
        return
    out.write('\r%3d%%  %-60s' % (pct, msg))
    out.flush()


def _get_password(args, confirm=False):
    """从 --password / ARHP_PASSWORD / 交互输入获取密码。"""
    pw = getattr(args, 'password', None)
    if pw:
        return pw
    pw = os.environ.get('ARHP_PASSWORD')
    if pw:
        return pw
    if not sys.stdin or not sys.stdin.isatty():
        return None
    pw = getpass.getpass('密码: ')
    if confirm:
        pw2 = getpass.getpass('确认密码: ')
        if pw != pw2:
            raise SystemExit('两次输入的密码不一致')
    return pw or None


def _build_parser():
    parser = argparse.ArgumentParser(
        prog='arhp',
        description='ARHP 压缩归档工具 — .arh2(Cauchy-MDS+中心化目录) / .arhp / '
                    'zip / 7z，zstd(0-22级) + AES-256-GCM 加密 + Reed-Solomon '
                    '恢复数据 (GPL-3.0+)')
    parser.add_argument('--headless', action='store_true',
                        help='强制命令行模式（不带子命令时打印帮助而不是启动 GUI）')
    sub = parser.add_subparsers(dest='cmd')

    c = sub.add_parser('create', aliases=['c'], help='创建归档（.arh2/.arhp/.zip/.7z）')
    c.add_argument('files', nargs='+', help='要打包的文件或目录')
    c.add_argument('-o', '--output', required=True, help='输出归档路径（扩展名决定格式，默认 .arh2）')
    c.add_argument('-f', '--format', choices=SUPPORTED_FORMATS, default=None,
                   help='归档格式（默认按输出扩展名判断）')
    c.add_argument('-l', '--level', type=int, default=9,
                   help='压缩级别（arh2/arhp: 0-22；zip/7z: 0-9；0 = 仅存储）')
    c.add_argument('-r', '--redundancy', type=int, default=3,
                   help='恢复数据百分比 0-50 (仅 .arh2/.arhp；默认 3；0 = 不生成)')
    c.add_argument('-b', '--block-size', default='1M', help='分块大小, 如 256K/1M/4M (仅 .arh2/.arhp)')
    c.add_argument('-V', '--volumes', default=None, metavar='SIZE',
                   help='分卷大小, 如 32M/650M/4480M；输出 name.ext.001/.002/... 分卷')
    c.add_argument('-m', '--memory', default=None, metavar='SIZE',
                   help='内存限制 16M-1024M（默认 128M），如 64M/512M；'
                        '分块校验/Reed-Solomon 按块流式进行，载荷工作集不超此值')
    c.add_argument('-p', '--password', default=None,
                   help='加密密码（.arh2/.arhp/.7z；也可用环境变量 ARHP_PASSWORD）')
    c.add_argument('--crypto', choices=_CRYPTO_ALGO_CHOICES, default='gcm',
                   help='.arh2/.arhp 加密方案：gcm = AES-256-GCM + PBKDF2（默认，'
                        '兼容旧版）；argon2id = AES-256-GCM + Argon2id '
                        '内存硬派生（需 argon2-cffi）')
    c.add_argument('--cd-encrypt', action='store_true',
                   help='仅 .arh2：加密中心化目录（列目录也需要密码）')
    c.add_argument('--encrypt', action='store_true', help='交互输入加密密码')

    x = sub.add_parser('extract', aliases=['x'], help='解压归档')
    x.add_argument('archive')
    x.add_argument('-o', '--output', default='.', help='输出目录')
    x.add_argument('-p', '--password', default=None, help='解密密码')
    x.add_argument('-m', '--memory', default=None, metavar='SIZE',
                   help='内存限制 16M-1024M（默认 128M），如 64M/512M')
    x.add_argument('--only', nargs='+', default=None, metavar='NAME',
                   help='只解压指定条目（文件或目录子树）')

    t = sub.add_parser('test', aliases=['t'], help='测试归档完整性')
    t.add_argument('archive')
    t.add_argument('-p', '--password', default=None, help='解密密码')
    t.add_argument('-m', '--memory', default=None, metavar='SIZE',
                   help='内存限制 16M-1024M（默认 128M），如 64M/512M')

    i = sub.add_parser('info', aliases=['i'], help='查看归档信息')
    i.add_argument('archive')

    l = sub.add_parser('list', aliases=['l', 'ls'], help='列出归档内容（预览）')
    l.add_argument('archive')
    l.add_argument('-p', '--password', default=None, help='解密密码')
    l.add_argument('-m', '--memory', default=None, metavar='SIZE',
                   help='内存限制 16M-1024M（默认 128M），如 64M/512M')

    sub.add_parser('gui', help='启动图形界面（由主程序注入）')
    return parser


def _run_gui_or_help(parser, default_gui, run_gui):
    """无子命令时：默认进 GUI（双击场景）；--headless 或 GUI 不可用时打印帮助。"""
    if default_gui and run_gui is not None:
        run_gui()
        return
    parser.print_help()


def _print_entry_list(entries):
    """按 7-Zip 风格打印列目录结果。"""
    print('%-12s %12s %12s  %-19s  %s' % ('属性', '大小', '压缩后', '修改时间', '名称'))
    total_u = total_c = 0
    for e in entries:
        attr = 'D' if e['is_dir'] else '.'
        mtime = ''
        if e['mtime']:
            import datetime
            try:
                mtime = datetime.datetime.fromtimestamp(e['mtime']).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                mtime = ''
        comp = '-' if e['compressed'] is None else _fmt_size(e['compressed'])
        print('%-12s %12s %12s  %-19s  %s' % (
            attr, _fmt_size(e['size']), comp, mtime, e['name']))
        print('    算法: %-10s CRC: %s%s' % (e.get('method') or '-',
                                            ('%08X' % e['crc']) if e.get('crc') is not None else '-',
                                            '  [加密]' if e.get('encrypted') else ''))
        total_u += e['size']
        total_c += e['compressed'] or 0
    print('-' * 72)
    print('共 %d 个条目，解压后 %s%s' % (
        len(entries), _fmt_size(total_u),
        '' if not total_c else '，压缩后 %s' % _fmt_size(total_c)))


def _print_info(info):
    """按格式打印 info 结果。"""
    print('文件:        %s' % info['path'])
    print('归档格式:    %s' % info['format'])
    print('归档大小:    %s' % _fmt_size(info['size']))
    if info['format'] in ('arh2', 'arhp'):
        print('载荷大小:    %s (压缩后%s)' % (
            _fmt_size(info['payload_size']),
            '' if info['compression'] == 'zstd' else '，未压缩'))
        if info['compression'] == 'zstd':
            print('压缩:        zstd 级别 %s' % info['zstd_level'])
        else:
            print('压缩:        仅存储')
        codec_label = {'cauchy-v1': 'Cauchy-MDS', 'vandermonde-v1': 'Vandermonde'}.get(
            info.get('rs_codec'), info.get('rs_codec') or '-')
        print('纠删码:      %s' % codec_label)
        print('恢复数据:    方法 %s, %d 个校验块 (%.1f%%)' % (
            info['method'], info['num_parity'],
            100.0 * info['num_parity'] / max(info['num_blocks'], 1)))
        print('分块:        %d 个数据块 × %s' % (
            info['num_blocks'], _fmt_size(info['block_size'])))
        print('格式版本:    v%s%s' % (info.get('version'),
              '（归档头含 RS 保护）' if info.get('header_protected') else '（旧格式）'))
        if info['format'] == 'arh2':
            print('中心目录:    %s' % ('已加密' if info.get('cd_encrypted') else '未加密'))
        if info.get('header_mac'):
            print('头认证:      HMAC-SHA256 防篡改')
    else:
        print('包含:        %d 个文件, %d 个目录' % (info.get('num_files', 0),
                                                  info.get('num_dirs', 0)))
        print('解压后大小:  %s' % _fmt_size(info.get('unpacked_size')))
    if info['encrypted']:
        print('加密:        是 (%s)' % (info.get('crypto_kdf') or 'AES-256-GCM'))
    else:
        print('加密:        否')


def main(argv=None, default_gui=True, run_gui=None):
    """命令行入口。

    run_gui: 图形界面启动函数（由主程序 arhp_main 注入）；为 None 时
    无子命令且未指定 --headless 将打印帮助而不是启动 GUI。
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    cmd = args.cmd
    if cmd is None:
        _run_gui_or_help(parser, default_gui and not args.headless, run_gui)
        return

    try:
        if cmd in ('create', 'c'):
            password = _get_password(args, confirm=args.encrypt)
            if args.encrypt and not password:
                raise SystemExit('加密归档必须提供密码')
            output_fmt = (args.format or detect_format(args.output)).lower()
            if output_fmt == 'zip' and password:
                raise SystemExit('zip 格式不支持加密，请改用 .arh2/.arhp/.7z 输出')
            if output_fmt in ('zip', '7z') and args.crypto != 'gcm':
                raise SystemExit('--crypto 仅对 .arh2/.arhp 格式有效')
            if args.cd_encrypt and output_fmt != 'arh2':
                raise SystemExit('--cd-encrypt 仅对 .arh2 格式有效')
            create_archive(args.files, args.output, fmt=output_fmt, level=args.level,
                           redundancy=args.redundancy,
                           block_size=_parse_size(args.block_size),
                           password=password, crypto=args.crypto,
                           cd_encrypt=args.cd_encrypt,
                           volume_size=_parse_size(args.volumes) if args.volumes else None,
                           progress=_progress,
                           mem_limit=_mem_limit_arg(getattr(args, 'memory', None)))
            print('\n已创建: %s' % args.output)
            vols = find_volumes(args.output)
            if vols:
                print('已拆分为 %d 个分卷: %s ... %s'
                      % (len(vols), os.path.basename(vols[0]),
                         os.path.basename(vols[-1])))
        elif cmd in ('extract', 'x'):
            count = extract_archive(args.archive, args.output, progress=_progress,
                                    password=_get_password(args), members=args.only,
                                    mem_limit=_mem_limit_arg(getattr(args, 'memory', None)))
            print('\n已解压 %s到: %s'
                  % ('%d 个文件 ' % count if count is not None else '',
                     args.output))
        elif cmd in ('test', 't'):
            test_archive(args.archive, progress=_progress,
                         password=_get_password(args),
                         mem_limit=_mem_limit_arg(getattr(args, 'memory', None)))
            print()
        elif cmd in ('list', 'l', 'ls'):
            entries = list_archive(args.archive, progress=_progress,
                                   password=_get_password(args),
                                   mem_limit=_mem_limit_arg(getattr(args, 'memory', None)))
            _print_entry_list(entries)
        elif cmd in ('info', 'i'):
            _print_info(info_archive(args.archive))
        elif cmd == 'gui':
            if run_gui is None:
                print('GUI 由主程序提供，请运行 arhp_main 启动图形界面。',
                      file=sys.stderr)
                sys.exit(1)
            run_gui()
    except SystemExit:
        raise
    except Exception as e:
        print('\n错误: %s' % e, file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main(default_gui=False)
