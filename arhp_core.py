#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARHP Core — 压缩归档核心库（v1.1.0.2）。

Copyright (C) MienArch 2026.
面包图书馆 2026. 版权所有
本项目基于 GPL-3.0-or-later 许可证发布，详见 LICENSE.txt。

- 兼容性：v1.1.0.2 可正常读取全部旧版归档；但 ≤1.1.0.1 的版本读取
  v1.1.0.2+ 创建的“加密”归档会因 header_crc 校验失败而拒绝读取
  （头中新增 header_mac 字段所致）——未加密旧归档互读不受影响。

v1.1.0.2 改动（内存模型重构 + 正确性修复）：
- 内存模型重构（此前为最致命短板）：_load_blocks() 会把全部分块
  一次性读进内存（10 GiB 归档 ≈ 10+ GiB 峰值 RAM）。现在校验、
  Reed-Solomon 编码/解码全部按块/按列切片流式进行，峰值内存由
  mem_limit 参数控制（16M-1024M，默认 128M）；内存放不下时校验块
  按列切片多遍累计，单遍内存仍不超限制。归档修复结果（含 RS 恢复
  出的块）逐块通过 CRC 复核后才允许使用；
- 新增 mem_limit 参数（create/extract/test/list 及 CLI --memory）；
- 加密归档头 HMAC-SHA256 认证（见上“安全语义澄清”）；
- 修复 extract_archive() 实际返回 None 与 docstring 不符：现在返回
  解压出的文件数（zip/7z 同样返回）；
- 修复分卷超过 999 时命名/定位错乱：第 1000 卷起用 .1000 四位命名，
  卷名正则放宽为 \\d{3,}，find_volumes 可正确定位任意卷号；
- 修复 split_volumes 中途失败留下半成品分卷：失败时自动清理已写出
  的分卷，原归档保持不动；
- 修复解压时原样恢复 setuid/setgid/sticky 位：权限掩码收紧为 0o777；
- 修复 tar 硬链接条目被静默跳过：现在以 os.link 还原（失败退化为
  复制内容），目标缺失时明确报错；列目录也能列出硬链接条目；
- 修复 decrypt_file 宽 except 把内存错误等真实故障误报为“密码错误”：
  现在只把 GCM 认证失败（InvalidTag）映射为密码/篡改错误，其余异常
  原样抛出；
- 参数不再被静默改写：block_size < 4096 直接报错（不再抬到 4096）；
  块数超 255 上限自动增大分块时会通过进度消息明确告知；
- 临时目录加固：makedirs 后用 lstat 校验最终节点必须是真实目录
  （同时拦截符号链接与其他非常规文件，缩小 TOCTOU 窗口）；
- 已知结构限制（暂不改格式）：arhp 的 tar 载荷无中心目录，list /
  test / extract 都必须完整处理载荷流（加密时含解密），几十 GB 的
  加密包列目录需要把数据完整过一遍——这是当前格式的固有成本，
  info 命令不受影响。




"""

__version__ = '1.1.0.2'
__license__ = 'GPL-3.0-or-later'

import argparse
import base64
import getpass
import json
import os
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import zlib


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
    1. 程序所在目录（onedir exe 旁 / 脚本旁，适合随程序分发的 arhp.png）；
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
    d = os.path.join(base, 'MienArch', 'ARHP')
    os.makedirs(d, exist_ok=True)
    # lstat 不跟随链接：最终节点必须是真实目录（v1.1.0.2 收紧——原 islink
    # 检查与 makedirs 之间存在 TOCTOU 窗口，且拦不住链接以外的非常规文件）
    if not stat.S_ISDIR(os.lstat(d).st_mode):
        raise ArchiveError(
            '程序临时目录被符号链接或非常规文件占用，已拒绝使用: %s'
            '（请检查并手动删除该条目）' % d)
    return d


# 本程序在临时目录中创建条目的固定前缀；缓存清理只认这些前缀，
# 绝不整目录清空（用户可能把别的文件放进同一目录）。
_TEMP_PREFIXES = ('.arhp_', '.arhp_join_', '.arhp_payload_', '.arhp_restore_',
                  '.arhp_list_', 'arhp_view_')


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
# Reed-Solomon 纠删码 (GF(2^8))   —— 原 rs.py
# ======================================================================

__all__ = ['ArchiveError', 'create_archive', 'extract_archive', 'test_archive',
           'open_archive', 'info_archive', 'list_archive',
           'detect_format', 'SUPPORTED_FORMATS', 'clear_app_temp_cache']


class ReedSolomonError(Exception):
    pass


def xor_bytes(a, b):
    """等长 bytes 快速异或。"""
    if len(a) != len(b):
        raise ReedSolomonError('异或长度不一致: %d != %d' % (len(a), len(b)))
    return (int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little')).to_bytes(len(a), 'little')


class ReedSolomon:
    """GF(2^8) 上的 Reed-Solomon 编解码，本原多项式 0x11D。"""

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
        """校验行 j 对数据块 i 的 Vandermonde 系数 alpha^((j+1)*i)。"""
        return self.exp[((parity_idx + 1) * data_idx) % 255]

    # ---- 编码 ----
    def encode(self, data_blocks, k):
        """data_blocks: N 个等长 bytes；返回 k 个校验块 bytearray。"""
        if not data_blocks:
            raise ReedSolomonError('没有数据块')
        size = len(data_blocks[0])
        parity = [bytearray(size) for _ in range(k)]
        for i, block in enumerate(data_blocks):
            if len(block) != size:
                raise ReedSolomonError('数据块长度不一致')
            for j in range(k):
                c = self.coeff(j, i)
                if c:
                    parity[j] = bytearray(xor_bytes(parity[j], block.translate(self.table(c))))
        return parity

    # ---- 解码（纠删）----
    def recover(self, data_blocks, parity_blocks, missing):
        """data_blocks: list[bytes|None]；parity_blocks: list[bytes|None]。
        missing: 损坏/缺失的数据块索引列表。返回 {idx: bytes}。

        输入做防御性校验（索引越界/重复、校验块长度不一致直接报错），
        不依赖调用方兜底；超额丢失也在这里明确拒绝。
        """
        missing = list(missing)
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
        size = len(rows[0][1])
        if any(len(p) != size for _, p in rows):
            raise ReedSolomonError('校验块长度不一致，无法恢复')
        # 高斯消元需要方阵：恰好取 len(missing) 个校验行
        rows = rows[:len(missing)]
        # 方程：sum_{i in missing} coeff(j,i) * D_i = P_j - sum_{i 已知} coeff(j,i) * D_i
        A = [[self.coeff(j, i) for i in missing] for j, _ in rows]
        B = []
        for j, p in rows:
            rhs = bytearray(p)
            for i, blk in enumerate(data_blocks):
                if blk is None:
                    continue
                if len(blk) != size:
                    # 最后一块可能短于 block_size，编码时按零填充，这里保持一致
                    blk = blk + b'\x00' * (size - len(blk))
                c = self.coeff(j, i)
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
# zstd 流式读写封装，优先 pyzstd，兼容 zstandard   —— 原 zstdio.py
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
# 归档加密 (AES-256-GCM + PBKDF2-HMAC-SHA256 / Argon2id)   —— 原 crypto.py
# ======================================================================

# 加密算法固定为分块 AES-256-GCM（4 MiB 一块，每块独立认证加密）；
# 密钥派生可选两种（--crypto，v1.1.0.0+）：
#   gcm      —— PBKDF2-HMAC-SHA256（60 万次迭代），兼容全部旧版本；
#   argon2id —— Argon2id 内存硬派生（默认 3 轮 × 128 MiB × 4 线程），
#               显著抬高 GPU/ASIC 离线破解成本；需要 argon2-cffi；
# v1.0.2.3 起 nonce = 随机 8 字节前缀 + 4 字节大端块序号（总长 12 字节
# 不变）；更早版本为 4 字节前缀 + 8 字节序号，读取时两者都接受；
# 密文再进入分块/CRC/Reed-Solomon 流程：CRC+RS 负责纠错恢复，
# GCM 负责认证——RS 恢复出的块经 CRC 验证后与原始密文逐字节一致，
# 因此加密归档的比特级损坏同样可以被自动修复（先纠错、后认证）；
# 加密只作用于载荷；归档头本身自 v1.1.0.0 起同样纳入 Reed-Solomon
# 保护（见下方"归档格式核心 v3"），不再处于纠错盲区。

KDF_ITERATIONS = 600_000
CHUNK_SIZE = 4 * 1024 * 1024  # 每块明文大小，密文每块多 16 字节认证标签
_SALT_LEN = 16
_NONCE_LEN = 12  # AES-GCM 标准 nonce 长度
_NONCE_PREFIX_LEN = 8  # v1.0.2.3+ 写入：8 字节随机前缀 + 4 字节块序号
_LEGACY_NONCE_PREFIX_LEN = 4  # v1.0.2.2 及更早：4 字节前缀 + 8 字节序号
_VALID_NONCE_PREFIX_LENS = (_NONCE_PREFIX_LEN, _LEGACY_NONCE_PREFIX_LEN)

# Argon2id 默认派生参数（可被头中 kdf_params 覆盖，读取时校验范围）
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 128 * 1024  # 128 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
# 读取侧安全上限：防止恶意头诱导超大内存/时间消耗
MAX_ARGON2_TIME_COST = 64
MAX_ARGON2_MEMORY_KIB = 4 * 1024 * 1024  # 4 GiB
MAX_ARGON2_PARALLELISM = 64

# 可选加密方案（.arhp 专用）：值为写入归档头 crypto.kdf 的标识
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
    """Argon2id 内存硬密钥派生（v1.1.0.0+）。需要 argon2-cffi。"""
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


def derive_key_auto(password, salt, kdf=KDF_PBKDF2, iterations=KDF_ITERATIONS,
                    kdf_params=None):
    """按归档头中的 kdf 字段分发密钥派生；参数先做范围校验。"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if kdf == KDF_PBKDF2:
        if not 1 <= iterations <= MAX_KDF_ITERATIONS:
            raise CryptoError('归档头中 KDF 迭代次数异常')
        return derive_key(password, salt, iterations)
    if kdf == KDF_ARGON2ID:
        params = kdf_params or {}
        try:
            time_cost = int(params.get('time', ARGON2_TIME_COST))
            memory_kib = int(params.get('memory', ARGON2_MEMORY_KIB))
            parallelism = int(params.get('parallelism', ARGON2_PARALLELISM))
        except (TypeError, ValueError):
            raise CryptoError('归档头中 Argon2id 参数损坏')
        if not 1 <= time_cost <= MAX_ARGON2_TIME_COST:
            raise CryptoError('归档头中 Argon2id time_cost 越界')
        if not 8 <= memory_kib <= MAX_ARGON2_MEMORY_KIB:
            raise CryptoError('归档头中 Argon2id memory 越界')
        if not 1 <= parallelism <= MAX_ARGON2_PARALLELISM:
            raise CryptoError('归档头中 Argon2id parallelism 越界')
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
    return_key=True 时返回 (info, key)，key 用于 v1.1.0.2 起的归档头
    HMAC 认证（header_mac），避免为算 HMAC 再派生一次密钥（Argon2id 很贵）。
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    """v1.1.0.2：加密归档头的 HMAC-SHA256 认证值（防篡改）。

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

    header_auth: v1.1.0.2 加密归档的头认证（(header_mac, 规范化头 JSON 字节)）。
    提供时先用派生密钥校验 HMAC，头被篡改立即报错，不进入解密。
    异常处理收窄：只有 GCM 认证失败（InvalidTag）才映射为“密码错误或
    数据被篡改”，内存错误/IO 故障等真实异常原样抛出（v1.1.0.2 修复
    此前宽 except 把真实故障误报为密码错的问题）。
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        salt = base64.b64decode(kdf_info['salt'])
        prefix = base64.b64decode(kdf_info['nonce_prefix'])
        chunk_size = int(kdf_info.get('chunk_size', CHUNK_SIZE))
        iterations = int(kdf_info.get('iterations', KDF_ITERATIONS))
        kdf_name = kdf_info.get('kdf', KDF_PBKDF2)
        kdf_params = kdf_info.get('kdf_params')
        if kdf_name not in (KDF_PBKDF2, KDF_ARGON2ID):
            raise ValueError
        if kdf_name == KDF_ARGON2ID and not isinstance(kdf_params, dict):
            raise ValueError
        if (len(salt) != _SALT_LEN
                or len(prefix) not in _VALID_NONCE_PREFIX_LENS
                or not 1 <= chunk_size <= MAX_CRYPTO_CHUNK_SIZE):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise CryptoError('归档头中加密参数损坏')
    key = derive_key_auto(password, salt, kdf=kdf_name,
                          iterations=iterations, kdf_params=kdf_params)
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
# 归档格式核心 v3   —— 原 archive.py
# ======================================================================

# 文件布局（大端）::
#
#   v2（≤1.0.2.3 创建，v1.1.0.0 仍可读取）::
#
#     magic      6B   b"ARHP\x00\x01"
#     hlen       8B   uint64，头长度
#     header     JSON，包含分块表、CRC、恢复参数、加密参数
#     data       N 个分块（按真实长度连续存放；zstd 流或加密后的密文）
#     parity     K 个 Reed-Solomon 校验块（等长 block_size）
#
#   v3（v1.1.0.0+ 创建；头 JSON 中 version=3）在 parity 之后追加::
#
#     hblocks    HB 个头分块（头 JSON 按 header_block_size 等长分块，
#                末块零填充；与载荷块相互独立的两套 RS 分片）
#     hparity    HP 个头校验块（Reed-Solomon，等长 header_block_size）
#     trailer    尾注：JSON + CRC32(JSON)(4B) + tlen(4B) + magic2(6B)，
#                位于文件最末尾。魔数 + 长度在最尾部，从文件尾向前
#                即可自定位整个尾注，无需解析头——头损坏时照样可以
#                读出头的分块布局与每块 CRC，对头分块做 RS 恢复。
#
# compression == 'zstd'  载荷为 zstd 流（级别 1-22）
# compression == 'store' 载荷为原始 tar（level=0，仅存储不压缩）
# encrypted   == true    载荷为 AES-256-GCM 密文，需密码解密后再解 tar/zstd
#
# method 固定为 'rs'：恢复数据为内嵌的 Reed-Solomon 校验块（单文件自足）

MAGIC = b'ARHP\x00\x01'
TRAILER_MAGIC = b'ARHP\x00\x02'  # v3 尾注魔数（位于文件最末尾 10+tlen 字节处）
MAX_SHARDS = 255  # GF(2^8) Vandermonde 上限
MAX_HEADER = 64 * 1024 * 1024  # 头长度上限，防止恶意头
MAX_BLOCK_SIZE = 256 * 1024 * 1024  # 单次分块读写的安全上限
MAX_CRYPTO_CHUNK_SIZE = 256 * 1024 * 1024
MAX_KDF_ITERATIONS = 10_000_000

# 压缩/解压归档的内存限制（v1.1.0.2）：分块校验、Reed-Solomon 编解码
# 全部按块/按列切片流式进行，峰值内存不超过该值（元数据与单个读写
# 缓冲另计小量）。GUI 提供 16M-1024M 档位，默认 128M。
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

# v3 头保护参数：头 JSON 按固定 64 KiB 等长分块（头通常远小于 1 MiB，
# 分块数 HB 很小）；头校验块数量取 HB 的 20%（下限 2、上限 16），
# 足以承受多块同时损坏；HB + HP 上限同样受 MAX_SHARDS 约束。
HEADER_BLOCK_SIZE = 64 * 1024
MAX_HEADER_PARITY = 16
MAX_TRAILER = 1024 * 1024  # 尾注长度上限（含 10 字节固定前缀）

# v1.0.2.3+：头自校验字段，值为除该字段外整个头规范化 JSON 的 CRC32。
# v1.1.0.0 起头本身有 Reed-Solomon 冗余（v3 格式），该字段仍保留：
# v3 读取以尾注中的 header_crc 为准（同一算法、同一规范化 JSON）。
# v1.1.0.2+：加密归档另含 header_mac（HMAC-SHA256），同样排除在规范化
# JSON 之外（认证值不能覆盖自身）；data_offset 是读取端注入的内存定位
# 字段（非归档内容），也必须排除，否则读取端重算的认证字节与写入端
# 不一致。
_HEADER_CRC_FIELD = 'header_crc'
_HEADER_MAC_FIELD = 'header_mac'
_HEADER_EXCLUDED_FIELDS = (_HEADER_CRC_FIELD, _HEADER_MAC_FIELD, 'data_offset')

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


def _add_paths(tar, paths):
    """把文件/目录加入 tar。修复 v1 缺陷：空目录现在会被保留。"""
    for p in paths:
        p = os.path.normpath(p)
        if os.path.isdir(p):
            base = os.path.dirname(os.path.abspath(p))
            for root, dirs, files in os.walk(p):
                # 先加目录项本身，保证空目录不丢失
                tar.add(root, arcname=os.path.relpath(root, base), recursive=False)
                for name in sorted(files):
                    full = os.path.join(root, name)
                    tar.add(full, arcname=os.path.relpath(full, base), recursive=False)
        else:
            tar.add(p, arcname=os.path.basename(p), recursive=False)


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
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise ArchiveError('以下输入路径不存在: %s' % ', '.join(missing))
    paths = [os.path.normpath(p) for p in paths]
    keys = [_path_key(p) for p in paths]
    if len(set(keys)) != len(keys):
        raise ArchiveError('输入路径有重复')
    # 同时添加“目录”和“目录内的条目”会让归档中出现重复子树，解压时互相覆盖。
    for i, p in enumerate(paths):
        if not os.path.isdir(p):
            continue
        for j, q in enumerate(paths):
            if i != j and _path_contains(p, q):
                raise ArchiveError('输入路径存在包含关系: %r 已包含 %r' % (p, q))
    # 不同来源的同名顶层条目在归档内共用同一个归档名（均为 basename），
    # 解压时互相覆盖，其中一个的内容被静默丢弃；zip 还会触发标准库
    # Duplicate name 警告。打包前即检测并报错。
    arcnames = [os.path.basename(p) for p in paths]
    dup = sorted({n for n in arcnames if arcnames.count(n) > 1})
    if dup:
        raise ArchiveError('输入路径存在同名条目: %s（同名文件/目录会在归档内'
                           '冲突，请改名后再打包）' % ', '.join(dup))
    return paths


def _check_output_location(paths, out_path):
    """避免输出归档把自身（或旧版本自身）也打包进去。"""
    if os.path.isdir(out_path):
        raise ArchiveError('输出路径不能是目录: %s' % out_path)
    out_key = _path_key(out_path)
    for p in paths:
        if _path_key(p) == out_key:
            raise ArchiveError('输出路径不能与输入路径相同: %s' % out_path)
        if os.path.isdir(p) and _path_contains(p, out_path):
            raise ArchiveError('输出路径不能位于输入目录内: %s' % out_path)


# ---------------------------------------------------------------- 分卷 (volumes)

# v1.1.0.2 修复：卷号放宽为 3 位以上数字。此前超过 999 卷时写出 .1000，
# 而正则 \d{3} 会把它解析成基名 xx.1 + 卷号 000，导致卷定位错乱。
_VOL_RE = re.compile(r'^(.*)\.(\d{3,})$')


def _vol_name(base, i):
    """第 i 个分卷的文件名：1-999 用三位零填充（.001-.999），
    1000 起直接用实际数字（.1000、.1001...），与 find_volumes 对应。"""
    return '%s.%03d' % (base, i) if i < 1000 else '%s.%d' % (base, i)


def split_volumes(archive_path, volume_size, progress=None):
    """把已生成的单个归档拆分为 name.ext.001 / .002 / ... 分卷。

    volume_size 为整数字节数；归档不超过该大小时不拆分并返回 0，
    否则删除原文件、保留分卷并返回分卷数。
    v1.1.0.2：拆分中途失败时自动清理已写出的半成品分卷，原归档保持不动。
    """
    volume_size = int(volume_size)
    if volume_size < 1:
        raise ArchiveError('分卷大小必须是正整数')
    total = os.path.getsize(archive_path)
    if total <= volume_size:
        return 0
    count = -(-total // volume_size)
    done = 0
    idx = 0
    written = []
    try:
        with open(archive_path, 'rb') as fin:
            while True:
                chunk = fin.read(volume_size)
                if not chunk:
                    break
                idx += 1
                vol = _vol_name(archive_path, idx)
                with open(vol, 'wb') as f:
                    f.write(chunk)
                written.append(vol)
                done += len(chunk)
                _rep(progress, '写入分卷 %d/%d（%s）' % (idx, count, vol),
                     int(95 * done / total))
        os.unlink(archive_path)
    except Exception:
        for vol in written:
            try:
                os.unlink(vol)
            except OSError:
                pass
        raise
    _rep(progress, '已拆分为 %d 个分卷' % count, 100)
    return count


def find_volumes(path):
    """若 path 属于多分卷归档（name.ext.NNN 之一，或基名 name.ext），
    返回按顺序排列的分卷路径列表；否则返回 None。"""
    base = str(path)
    m = _VOL_RE.match(base)
    if m:
        base = m.group(1)
    elif os.path.isfile(base):
        # 完整归档文件存在时按普通文件处理，即使旁边恰有 .001 文件
        return None
    if not os.path.isfile(base + '.001'):
        return None
    vols = []
    i = 1
    while os.path.isfile(_vol_name(base, i)):
        vols.append(_vol_name(base, i))
        i += 1
    return vols


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

def create_archive(paths, out_path, fmt=None, level=9, redundancy=3,
                   block_size=1 << 20, password=None,
                   volume_size=None, progress=None, crypto='gcm',
                   mem_limit=DEFAULT_MEM_LIMIT):
    """创建归档。按扩展名或 fmt 自动选择格式。

    paths: 文件/目录列表；out_path: 输出路径；
    fmt: 'arhp' / 'zip' / '7z'，None 时按 out_path 扩展名判断（默认 arhp）；
    level: 压缩级别（arhp: 0-22，zip: 0-9，7z: 0-9；0 = 仅存储）；
    redundancy / block_size: 仅 .arhp 使用（Reed-Solomon 恢复数据，zip/7z 忽略）；
    volume_size: 分卷大小（字节），设置后输出为 name.ext.001/.002/... 分卷，
                 适用于全部三种格式；None 或归档不超过该大小时输出单文件；
    password: .arhp 用 AES-256-GCM（密钥派生由 crypto 决定）；.7z 用 py7zr
              AES-256（需 py7zr>=0.20）；.zip 标准库不支持写入加密，传入
              密码会报错；
    crypto: 仅 .arhp 生效——'gcm' = PBKDF2-HMAC-SHA256（默认，兼容旧版），
            'argon2id' = Argon2id 内存硬派生（需 argon2-cffi）；
    mem_limit: 内存限制（字节，16M-1024M，默认 128M）。.arhp 的分块校验与
               Reed-Solomon 编码按块/按列切片流式进行，峰值内存不超此值；
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
    elif fmt == 'arhp':
        result = _create_arhp(paths, out_path, level=level,
                              redundancy=redundancy, block_size=block_size,
                              password=password, crypto=crypto,
                              progress=progress, mem_limit=mem_limit)
    else:
        raise ArchiveError('不支持的归档格式: %s（支持 arhp/zip/7z）' % fmt)
    if volume_size:
        split_volumes(out_path, volume_size, progress=progress)
    return result


def _protect_header(hj):
    """对头 JSON 字节做 Reed-Solomon 保护（v3 格式）。

    返回 (header_blocks, header_parity, trailer_dict)：
    - header_blocks: HB 个等长（HEADER_BLOCK_SIZE）数据块，末块零填充；
    - header_parity: HP 个校验块（同一 RS 编码，与载荷分片独立）；
    - trailer_dict: 写入尾注的自描述布局（含每块 CRC，读取时定位/校验用）。
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
    parity = [bytes(p) for p in rs.encode(blocks, hp)] if hp else []
    return blocks, parity, {
        'header_crc': orig_crc,  # 头 JSON 原始字节的 CRC32，读取时先比对
        'hlen': orig_len,
        'hbs': hb_size,
        'hb': hb,
        'hp': hp,
        'h_crc': [_crc(b) for b in blocks],
        'hp_crc': [_crc(p) for p in parity],
    }


def _create_arhp(paths, out_path, level=9, redundancy=3, block_size=1 << 20,
                 password=None, crypto='gcm', progress=None,
                 mem_limit=DEFAULT_MEM_LIMIT):
    """创建 .arhp 归档（v3 格式：归档头同样纳入 Reed-Solomon 保护）。

    分块校验与校验块生成全部流式进行，峰值内存不超过 mem_limit
    （v1.1.0.2 前校验块全量驻留内存：50% 冗余 + 大分块可轻松吃光 RAM）。
    """
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    redundancy = min(max(int(redundancy), 0), 50)
    # v1.1.0.2：不再静默把 block_size 抬到 4096，直接报错
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
                                            crypto=crypto)
            os.replace(enc, comp)
        else:
            kdf_info = None

        payload_size = os.path.getsize(comp)
        method = 'rs'
        n, k, bs = _layout(payload_size, redundancy, block_size)
        if bs != block_size:
            # v1.1.0.2：自动调整分块大小时明确告知，不再静默改写
            _rep(progress, '分块数超过 %d 上限，分块大小已自动增大到 %s'
                 % (MAX_SHARDS, _fmt_size(bs)), 24)

        hdr = {
            'version': 3,
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
                          mem_limit, progress)
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

        # v1.1.0.2：加密归档的头纳入 HMAC-SHA256 认证（防篡改；
        # 未加密归档仅靠 CRC32+RS，仅防随机损坏，不防恶意篡改）
        if encrypted and key is not None:
            hdr[_HEADER_MAC_FIELD] = _header_mac_hex(key, hdr)

        # 头自校验：在所有头字段就绪后计算 CRC32
        hdr[_HEADER_CRC_FIELD] = _crc(_canonical_header_json(hdr))

        _rep(progress, '写入归档...', 88)
        with open(out_path, 'wb') as out, open(blocks_tmp, 'rb') as fin:
            out.write(MAGIC)
            hj = json.dumps(hdr, separators=(',', ':')).encode('utf-8')
            out.write(struct.pack('>Q', len(hj)))
            out.write(hj)
            shutil.copyfileobj(fin, out, 1 << 20)
            if k:
                with open(parity_tmp, 'rb') as pf:
                    shutil.copyfileobj(pf, out, 1 << 20)
            # v3：归档头纳入 RS 保护——头分块 + 头校验块 + 自描述尾注
            _rep(progress, '生成归档头恢复数据...', 94)
            hblocks, hparity, tinfo = _protect_header(hj)
            for b in hblocks:
                out.write(b)
            for p in hparity:
                out.write(p)
            tj = json.dumps(tinfo, separators=(',', ':')).encode('utf-8')
            out.write(tj)
            out.write(struct.pack('>I', _crc(tj)))    # 尾注 body CRC32
            out.write(struct.pack('>I', len(tj) + 4))  # tlen 含 4 字节 body CRC
            out.write(TRAILER_MAGIC)                   # 最末尾：从尾向前自定位

        _rep(progress, '完成', 100)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _write_parity(comp, parity_tmp, n, k, bs, payload_size, mem_limit,
                  progress):
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
                        coef = rs.coeff(j, i)
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
                    coef = rs.coeff(j, i)
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


def _crypto_encrypt(src, dst, password, progress, crypto='gcm'):
    total = os.path.getsize(src)
    return encrypt_file(src, dst, password,
                        progress=lambda d, t: _rep(progress, '加密中...',
                                                   15 + 8 * d // max(t, 1)),
                        total=total, crypto=crypto, return_key=True)


# ---- zip 创建 ----

def _create_zip(paths, out_path, level=9, password=None, progress=None):
    """创建 .zip 归档（标准库 zipfile，deflate / store）。

    标准库不支持写入加密 zip，传入密码时报错提示改用 .arhp / .7z。
    """
    import zipfile
    if password:
        raise ArchiveError('zip 格式不支持加密（标准库限制），请改用 .arhp 或 .7z')
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    level = max(0, min(9, int(level)))
    files = []
    for p in paths:
        if os.path.isdir(p):
            base = os.path.dirname(os.path.abspath(p))
            for root, dirs, fnames in os.walk(p):
                files.append((root, os.path.relpath(root, base)))
                for name in fnames:
                    full = os.path.join(root, name)
                    files.append((full, os.path.relpath(full, base)))
        else:
            files.append((p, os.path.basename(p)))
    total = sum(os.path.getsize(f) for f, _ in files if os.path.isfile(f))
    compression = zipfile.ZIP_STORED if level == 0 else zipfile.ZIP_DEFLATED
    compresslevel = None if level == 0 else max(1, level)
    done = 0
    count = 0
    _rep(progress, '打包中 (zip)...', 3)
    with zipfile.ZipFile(out_path, 'w', compression=compression,
                         compresslevel=compresslevel) as zf:
        for full, arc in files:
            if os.path.isfile(full):
                zf.write(full, arc.replace(os.sep, '/'))
                count += 1
                done += os.path.getsize(full)
                _rep(progress, '已打包 %d 个文件' % count,
                     3 + int(95 * done / max(total, 1)))
            elif os.path.isdir(full):
                # 目录项（保留空目录）
                zf.writestr(arc.replace(os.sep, '/') + '/', b'')
            # 其余情况（断链/失效符号链接、特殊文件）跳过，
            # 避免被误存为目录条目
    _rep(progress, '完成，共 %d 个文件' % count, 100)


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
    # 注意：py7zr 在传入 filters 时若不加 header_encryption=True，
    # password 会被静默忽略（数据不加密）。因此加密时必须显式开启头加密。
    with py7zr.SevenZipFile(out_path, 'w', password=password or None,
                            header_encryption=bool(password),
                            filters=filters) as zf:
        for p in paths:
            arc = os.path.basename(os.path.normpath(p))
            if os.path.isdir(p):
                zf.writeall(p, arcname=arc)
            else:
                zf.write(p, arcname=arc)
    _rep(progress, '完成', 100)


# ---------------------------------------------------------------- 读取

def _header_int(value, name, minimum, maximum=None):
    """读取并校验归档头整数；拒绝 None、布尔值与越界值。"""
    if isinstance(value, bool):
        raise ArchiveError('归档头字段 %s 类型错误' % name)
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ArchiveError('归档头字段 %s 缺失或不是整数' % name)
    if value < minimum or (maximum is not None and value > maximum):
        raise ArchiveError('归档头字段 %s 越界: %s' % (name, value))
    return value


def _validate_header(hdr):
    """在访问分块表前做结构校验，避免损坏头导致二次异常或超大 read()。"""
    if not isinstance(hdr, dict):
        raise ArchiveError('归档头类型错误')

    method = hdr.get('method')
    if method != 'rs':
        raise ArchiveError('归档头中恢复方法无效: %r（仅支持内置 Reed-Solomon）' % method)
    compression = hdr.get('compression', 'zstd')
    if compression not in ('zstd', 'store'):
        raise ArchiveError('归档头中压缩方式无效: %r' % compression)

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
    if payload_size:
        for i, ln in enumerate(parsed_len):
            expected = block_size if i < num_blocks - 1 else \
                payload_size - block_size * (num_blocks - 1)
            if ln != expected:
                raise ArchiveError('归档头中分块长度不符合连续布局')
    if hdr.get('encrypted'):
        crypto_info = hdr.get('crypto')
        if not isinstance(crypto_info, dict):
            raise ArchiveError('加密归档缺少加密参数')
        kdf_name = crypto_info.get('kdf', KDF_PBKDF2)
        if kdf_name not in (KDF_PBKDF2, KDF_ARGON2ID):
            raise ArchiveError('归档头中加密 KDF 不受支持: %r' % (kdf_name,))
        if kdf_name == KDF_ARGON2ID and \
                not isinstance(crypto_info.get('kdf_params'), dict):
            raise ArchiveError('归档头中 Argon2id 参数缺失或损坏')

    # 头自校验（v1.0.2.3+ 写入；旧归档无此字段则跳过，保持向后兼容）
    if hdr.get(_HEADER_CRC_FIELD) is not None:
        header_crc = _header_int(hdr.get(_HEADER_CRC_FIELD),
                                 _HEADER_CRC_FIELD, 0, 0xFFFFFFFF)
        if _crc(_canonical_header_json(hdr)) != header_crc:
            raise ArchiveError('归档头校验失败（header_crc 不匹配），'
                               '头数据已损坏，无法安全读取')

    hdr['block_size'] = block_size
    hdr['num_blocks'] = num_blocks
    hdr['num_parity'] = num_parity
    hdr['payload_size'] = payload_size
    hdr['block_len'] = parsed_len
    hdr['block_crc'] = parsed_crc
    hdr['parity_crc'] = parsed_parity


def _read_trailer(f, file_size):
    """读取 v3 尾注（文件最末尾的自描述结构）。

    返回 (trailer_dict, trailer_total_len)；旧格式归档（末尾无尾注魔数）
    返回 (None, 0)。尾注布局（从文件尾向前）：magic2(6B) + tlen(4B)
    + JSON + CRC32(JSON)(4B)，其中 tlen = len(JSON) + 4。
    """
    if file_size < len(TRAILER_MAGIC) + 4:
        return None, 0
    f.seek(file_size - len(TRAILER_MAGIC))
    if f.read(len(TRAILER_MAGIC)) != TRAILER_MAGIC:
        return None, 0
    f.seek(file_size - len(TRAILER_MAGIC) - 4)
    (tlen,) = struct.unpack('>I', f.read(4))
    if tlen <= 4 or tlen > MAX_TRAILER:
        raise ArchiveError('归档尾注长度异常 (%d 字节)，文件可能已损坏' % tlen)
    total = len(TRAILER_MAGIC) + 4 + tlen
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


def _recover_header(f, file_size, trailer, trailer_len, hj):
    """v3：头 JSON 与尾注记录不一致时，用头校验块做 Reed-Solomon 恢复。

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
        rec = ReedSolomon().recover(blocks, par, missing)
        for i, b in rec.items():
            if _crc(bytes(b)) != h_crc[i]:
                raise ArchiveError('归档头恢复数据未通过 CRC 校验，无法安全读取')
            blocks[i] = b
        fixed = b''.join(blocks)[:hlen]
    if _crc(fixed) != trailer['header_crc']:
        raise ArchiveError('归档头恢复结果校验失败，无法安全读取')
    return fixed


def open_archive(path):
    """读取并校验 .arhp 归档头，返回 header 字典。

    修复 v1 缺陷：短读时抛出清晰的 ArchiveError 而不是 struct.error。
    v1.1.0.0+：识别 v3 尾注；头 CRC 不一致时自动用头校验块 RS 恢复。
    """
    with open(path, 'rb') as f:
        if f.read(6) != MAGIC:
            raise ArchiveError('不是 ARHP 归档: %s' % path)
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

        trailer, trailer_len = _read_trailer(f, file_size)
        if trailer is not None:
            # v3：先按尾注校验头 CRC，损坏则用头校验块恢复
            t_hcrc = trailer.get('header_crc')
            if (not isinstance(t_hcrc, int) or isinstance(t_hcrc, bool)
                    or not 0 <= t_hcrc <= 0xFFFFFFFF):
                raise ArchiveError('归档尾注中头校验值损坏')
            if _crc(hj) != t_hcrc:
                hj = _recover_header(f, file_size, trailer, trailer_len, hj)
        try:
            hdr = json.loads(hj.decode('utf-8'))
        except Exception:
            raise ArchiveError('归档头损坏（JSON 解析失败）')
        _validate_header(hdr)
        if hdr['payload_size'] > file_size - data_offset:
            raise ArchiveError('归档数据区被截断')
        hdr['data_offset'] = data_offset
        return hdr


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
    """
    n = hdr['num_blocks']
    bs = hdr['block_size']
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
    A = [[rs.coeff(rows[j], i) for i in missing] for j in range(m)]
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
                c = rs.coeff(rows[jj], i)
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

    峰值内存不超过 mem_limit（v1.1.0.2 前会把全部分块一次性读进内存，
    大归档直接压垮内存——这是旧版最致命的架构短板）。临时文件由调用方
    负责删除。
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


def _safe_target(outdir, name):
    """修复 v1 缺陷：同时拦截反斜杠与 Windows 盘符路径。"""
    name = str(name).replace('\\', '/')
    parts = [p for p in name.split('/') if p not in ('', '.')]
    if not parts or name.startswith('/') or _WIN_ABS.match(str(name)) or '..' in parts:
        raise ArchiveError('归档内包含不安全路径: %r' % name)
    return os.path.join(outdir, *parts)


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


def _decrypt_payload(payload, hdr, password, progress):
    """加密载荷解密到 <payload>.dec 并返回解密结果路径（明文载荷）。

    v1.1.0.2：解密前先校验归档头 HMAC（若归档含 header_mac），头被
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


def _restore(path, hdr, outdir, progress, write, password=None, members=None,
             mem_limit=DEFAULT_MEM_LIMIT):
    """校验/修复分块（流式，峰值内存 ≤ mem_limit）、按需解密，解包 tar。

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


class _NullCtx:
    """把任意读对象包成上下文管理器（仅存储模式用）。"""

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        return self.f

    def __exit__(self, *exc):
        return False


def _normalize_member_name(raw):
    """把 tar/zip 成员名规范化为统一相对路径形式。

    只剥离 './' 前缀序列（GNU tar 常见写法），不能用 lstrip('./')——
    它会剥掉顶层隐藏条目的前导点（'.ssh' → 'ssh'），导致列表显示名
    与磁盘真实文件名不一致。
    """
    name = str(raw).replace('\\', '/')
    while name.startswith('./'):
        name = name[2:]
    return name


def _extract_tar(tar, outdir, progress, write, members=None):
    """遍历 tar 流并安全写出。返回处理的普通文件数（含硬链接条目）。"""
    count = 0
    dirs = []
    hardlinks = []  # (目标路径, 源成员路径, 条目名)，收尾阶段统一还原
    for m in tar:
        name = _normalize_member_name(m.name).rstrip('/')
        if not name or name == '.':
            continue  # tar 常见的 './' 目录项，无实际内容
        if not _member_match(name, members):
            continue
        target = _safe_target(outdir, name)
        if m.isdir():
            if write:
                os.makedirs(target, exist_ok=True)
                dirs.append((target, m.mtime))
        elif m.issym():
            if write:
                link = str(m.linkname).replace('\\', '/')
                dest = os.path.normpath(os.path.join(os.path.dirname(target), link))
                root = os.path.abspath(outdir)
                try:
                    inside = os.path.commonpath([root, os.path.abspath(dest)]) == root
                except ValueError:
                    inside = False  # Windows 跨盘符等情况按不安全链接跳过
                if inside:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    if os.path.lexists(target):
                        os.remove(target)
                    os.symlink(m.linkname, target)
        elif m.islnk():
            # 硬链接（tar 内指向另一成员）：v1.1.0.2 前落入静默跳过分支，
            # 条目无声丢失。现在以 os.link 还原（失败退化为复制内容），
            # 目标尚未解压（前向引用）的留到收尾重试，仍缺失则明确报错。
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
                parent = os.path.dirname(target)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                src = tar.extractfile(m)
                if src is None:
                    continue
                with src, open(target, 'wb') as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                # v1.1.0.2：权限掩码收紧为 0o777——不再原样恢复
                # setuid/setgid/sticky 位，避免解压即植入特权文件
                os.chmod(target, m.mode & 0o777)
                try:
                    os.utime(target, (m.mtime, m.mtime))
                except OSError:
                    pass
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


def extract_archive(path, outdir='.', progress=None, password=None,
                    members=None, mem_limit=DEFAULT_MEM_LIMIT):
    """解压归档到 outdir，自动修复可修复的损坏。返回解压出的文件数。

    path: .arhp / .zip / .7z（按扩展名自动识别）；支持多分卷归档
    （给出任一分卷或基名均可，会自动合并到临时目录后解压）；
    members: 可选，只解压这些条目（文件或目录子树）；
    mem_limit: 内存限制（字节，16M-1024M，默认 128M），.arhp 分块校验/
               修复按块流式进行，峰值内存不超此值。
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
    members = _norm_members(members)
    os.makedirs(outdir, exist_ok=True)
    pwd = _zip_pwd(password)
    count = 0
    _rep(progress, '解压中 (zip)...', 5)
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        for info in zf.infolist():
            name = str(info.filename).replace('\\', '/').lstrip('/')
            is_dir = name.endswith('/')
            if is_dir:
                name = name.rstrip('/')
            if not _member_match(name, members):
                continue
            target = _safe_target(outdir, name)
            if is_dir:
                os.makedirs(target, exist_ok=True)
                continue
            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)
            try:
                src = zf.open(info, pwd=pwd)
            except RuntimeError as e:
                raise ArchiveError('解压失败（%s）：%s'
                                   % (name, '密码错误或需要密码' if 'password' in str(e).lower() else e))
            try:
                with src, open(target, 'wb') as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
            except RuntimeError as e:
                raise ArchiveError('解压失败（%s）：%s'
                                   % (name, '密码错误或需要密码' if 'password' in str(e).lower() else e))
            except (zipfile.BadZipFile, zlib.error):
                raise ArchiveError('CRC/压缩数据校验失败: %s' % name)
            try:
                os.utime(target, (info.date_time and
                                  __import__('time').mktime(info.date_time + (0, 0, -1)),) * 2)
            except Exception:
                pass
            count += 1
            if count % 200 == 0:
                _rep(progress, '已解压 %d 个文件' % count,
                     5 + int(90 * count / max(len(infos), 1)))
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


def _extract_7z(path, outdir, progress=None, password=None, members=None):
    py7zr = _load_7z()
    os.makedirs(outdir, exist_ok=True)
    members = _norm_members(members)
    _rep(progress, '解压中 (7z)...', 10)
    count = 0
    try:
        with py7zr.SevenZipFile(path, 'r', password=password or None) as zf:
            _check_7z_password(zf, password)
            if members:
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


# ---------------------------------------------------------------- 信息 / 列目录

SUPPORTED_FORMATS = ('arhp', 'zip', '7z')
_FORMAT_EXT = {'.arhp': 'arhp', '.zip': 'zip', '.7z': '7z'}


def detect_format(path):
    """按扩展名识别归档格式，返回 'arhp' / 'zip' / '7z'。

    无法识别时抛出 ArchiveError。
    """
    ext = os.path.splitext(str(path))[1].lower()
    fmt = _FORMAT_EXT.get(ext)
    if not fmt:
        raise ArchiveError('无法识别的归档格式: %s（支持 .arhp / .zip / .7z）' % path)
    return fmt


def info_archive(path):
    """返回归档信息字典（不解压载荷）。支持 .arhp / .zip / .7z，
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
    return {
        'path': path,
        'size': size,
        'format': 'arhp',
        'version': hdr.get('version'),
        'header_protected': hdr.get('version', 0) >= 3,
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
    - compressed 为 None 表示该格式不记录单项压缩后大小；
    - mtime 为 float 时间戳（unix），未知为 None；
    - crc 为 32 位整数或 None；method 为算法名字符串或 None。
    需要密码的加密归档必须传入 password。
    支持多分卷归档（任一分卷或基名均可）。
    mem_limit: 内存限制（字节，16M-1024M，默认 128M），仅影响 .arhp
               分块校验/修复的峰值内存。
    说明：arhp 的 tar 载荷无中心目录，列目录仍需完整处理载荷流
    （加密时含解密）——这是当前格式的固有成本，info 命令不受影响。
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
    return _list_arhp(path, progress=progress, password=password,
                      mem_limit=mem_limit)


def _list_arhp(path, progress=None, password=None,
               mem_limit=DEFAULT_MEM_LIMIT):
    """列出 .arhp 内容：流式校验/修复分块 → 解密 → 流式读 tar 头信息。

    峰值内存不超过 mem_limit（v1.1.0.2 前会先把全部分块读进内存）。
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
                    # v1.1.0.2：硬链接（islnk）也列出（此前被静默跳过）
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
# 命令行入口   —— 原 cli.py
# ======================================================================

# 用法::
#     arhp create -o out.arhp|out.zip|out.7z [选项] 文件/目录...
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
        description='ARHP 压缩归档工具 — zstd(0-22级)/zip/7z + AES-256-GCM 加密 '
                    '+ Reed-Solomon 恢复数据 (GPL-3.0+)')
    parser.add_argument('--headless', action='store_true',
                        help='强制命令行模式（不带子命令时打印帮助而不是启动 GUI）')
    sub = parser.add_subparsers(dest='cmd')

    c = sub.add_parser('create', aliases=['c'], help='创建归档（.arhp/.zip/.7z）')
    c.add_argument('files', nargs='+', help='要打包的文件或目录')
    c.add_argument('-o', '--output', required=True, help='输出归档路径（扩展名决定格式）')
    c.add_argument('-f', '--format', choices=SUPPORTED_FORMATS, default=None,
                   help='归档格式（默认按输出扩展名判断）')
    c.add_argument('-l', '--level', type=int, default=9,
                   help='压缩级别（arhp: 0-22；zip/7z: 0-9；0 = 仅存储）')
    c.add_argument('-r', '--redundancy', type=int, default=3,
                   help='恢复数据百分比 0-50 (仅 .arhp；默认 3；0 = 不生成)')
    c.add_argument('-b', '--block-size', default='1M', help='分块大小, 如 256K/1M/4M (仅 .arhp)')
    c.add_argument('-V', '--volumes', default=None, metavar='SIZE',
                   help='分卷大小, 如 32M/650M/4480M；输出 name.ext.001/.002/... 分卷')
    c.add_argument('-m', '--memory', default=None, metavar='SIZE',
                   help='内存限制 16M-1024M（默认 128M），如 64M/512M；'
                        '分块校验/Reed-Solomon 按块流式进行，峰值内存不超此值')
    c.add_argument('-p', '--password', default=None,
                   help='加密密码（.arhp/.7z；也可用环境变量 ARHP_PASSWORD）')
    c.add_argument('--crypto', choices=_CRYPTO_ALGO_CHOICES, default='gcm',
                   help='.arhp 加密方案：gcm = AES-256-GCM + PBKDF2（默认，'
                        '兼容旧版）；argon2id = AES-256-GCM + Argon2id '
                        '内存硬派生（需 argon2-cffi）')
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


def _fmt_size(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return '%.1f %s' % (n, unit) if unit != 'B' else '%d B' % n
        n /= 1024


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
        crc = ('%08X' % e['crc']) if e.get('crc') is not None else '-'
        print('%-12s %12s %12s  %-19s  %s' % (
            attr, _fmt_size(e['size']), comp, mtime, e['name']))
        print('    算法: %-10s CRC: %s%s' % (e.get('method') or '-', crc,
                                            '  [加密]' if e.get('encrypted') else ''))
        total_u += e['size']
        total_c += e['compressed'] or 0
    print('-' * 72)
    print('共 %d 个条目，解压后 %s%s' % (
        len(entries), _fmt_size(total_u),
        '' if not total_c else '，压缩后 %s' % _fmt_size(total_c)))


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
                raise SystemExit('zip 格式不支持加密，请改用 .arhp 或 .7z 输出')
            if output_fmt != 'arhp' and args.crypto != 'gcm':
                raise SystemExit('--crypto 仅对 .arhp 格式有效，请改用 .arhp 输出')
            create_archive(args.files, args.output, fmt=output_fmt, level=args.level,
                           redundancy=args.redundancy,
                           block_size=_parse_size(args.block_size),
                           password=password, crypto=args.crypto,
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
            info = info_archive(args.archive)
            print('文件:        %s' % info['path'])
            print('归档格式:    %s' % info['format'])
            print('归档大小:    %s' % _fmt_size(info['size']))
            if info['format'] == 'arhp':
                print('载荷大小:    %s (压缩后%s)' % (
                    _fmt_size(info['payload_size']),
                    '' if info['compression'] == 'zstd' else '，未压缩'))
                if info['compression'] == 'zstd':
                    print('压缩:        zstd 级别 %s' % info['zstd_level'])
                else:
                    print('压缩:        仅存储')
                print('恢复数据:    方法 %s, %d 个校验块 (%.1f%%)' % (
                    info['method'], info['num_parity'],
                    100.0 * info['num_parity'] / max(info['num_blocks'], 1)))
                print('分块:        %d 个数据块 × %s' % (
                    info['num_blocks'], _fmt_size(info['block_size'])))
                print('格式版本:    v%s%s' % (info.get('version'),
                      '（归档头含 RS 保护）' if info.get('header_protected') else ''))
            else:
                print('包含:        %d 个文件, %d 个目录' % (info.get('num_files', 0),
                                                          info.get('num_dirs', 0)))
                print('解压后大小:  %s' % _fmt_size(info.get('unpacked_size')))
            if info['encrypted']:
                print('加密:        是 (%s)' % (info.get('crypto_kdf') or 'AES-256-GCM'))
            else:
                print('加密:        否')
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
