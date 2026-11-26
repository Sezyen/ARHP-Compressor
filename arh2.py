#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MienArch ARH2 独立归档工具（ARH2 格式）。

只创建和处理 .arh2 归档，统一使用 ARH2 （Cauchy-MDS RS + 中心化目录）。
内置 PySide6 图形界面，不依赖外部模块。

依赖：PySide6、pyzstd（或 zstandard）、cryptography；使用 Argon2id 时另需
argon2-cffi。程序图标从本脚本（或打包后 exe）所在目录读取 arh2.png。

Copyright (C) MienArch 2026. GPL-3.0-or-later.
"""

import base64
import getpass
import itertools
import json
import math
import os
import re
import stat
import shutil
import struct
import sys
import tarfile
import tempfile
import traceback
import zlib

__version__ = '1.0.0.2'
__license__ = 'GPL-3.0-or-later'
__all__ = ['ArchiveError', 'create_archive', 'extract_archive', 'test_archive',
           'open_archive', 'info_archive', 'list_archive', 'detect_format',
           'find_volumes', 'clear_app_temp_cache']

# ======================================================================
# ARH2 临时目录
# ======================================================================

def app_temp_dir():
    """本程序所有临时文件的统一存放目录。

    Windows: %LOCALAPPDATA%\\MienArch\\ARH2
    其他系统: ~/.cache/MienArch/ARH2
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
    d = os.path.join(parent, 'ARH2')
    # 同时检查应用名父目录和最终目录；否则攻击者可将 MienArch 本身
    # 预置为符号链接，绕过只检查 ARH2 最后一层的保护。
    for candidate in (parent, d):
        if os.path.lexists(candidate):
            if os.path.islink(candidate) or not os.path.isdir(candidate):
                raise ArchiveError(
                    '程序临时目录路径被符号链接或非目录占用，已拒绝使用: %s'
                    % candidate)
        else:
            os.mkdir(candidate)
        if os.path.islink(candidate):
            raise ArchiveError('程序临时目录路径出现符号链接，已拒绝使用: %s'
                               % candidate)
    return d


# 本程序在临时目录中创建条目的固定前缀；缓存清理只认这些前缀，
# 绝不整目录清空（用户可能把别的文件放进同一目录）。
_TEMP_PREFIXES = ('.arh2_', '.arh2_join_', '.arh2_payload_', '.arh2_restore_',
                  '.arh2_list_', 'arh2_view_')


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

    def coeff_cauchy(self, parity_idx, data_idx, n_data):
        """Cauchy-MDS 系数，保证任意可用分片组合均可恢复。"""
        row = n_data + parity_idx
        if not 0 <= data_idx < n_data or row >= 255 or parity_idx < 0:
            raise ReedSolomonError('Cauchy 校验矩阵索引越界')
        return self.inv(self.exp[data_idx] ^ self.exp[row])

    # ---- 编码 ----
    def encode(self, data_blocks, k):
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
                c = self.coeff_cauchy(j, i, n_data)
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

        # Cauchy-MDS 矩阵的任意 m 行、m 列子矩阵均可逆。
        m = len(missing)
        chosen = tuple(rows[:m])
        matrix = [[self.coeff_cauchy(j, i, n_data) for i in missing]
                  for j, _ in chosen]
        self._gauss([r[:] for r in matrix], [bytearray(1) for _ in range(m)])

        # 方程：sum_{i in missing} coeff(j,i) * D_i = P_j - sum_{i 已知} coeff(j,i) * D_i
        A = [[self.coeff_cauchy(j, i, n_data) for i in missing]
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
                c = self.coeff_cauchy(j, i, n_data)
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
# 归档加密 (AES-256-GCM + PBKDF2-HMAC-SHA256 / Argon2id)   —— 原 crypto.py
# ======================================================================

# 加密算法固定为分块 AES-256-GCM（4 MiB 一块，每块独立认证加密）；
# 密钥派生可选两种（--crypto，v1.1.0.0+）：
#   gcm      —— PBKDF2-HMAC-SHA256（60 万次迭代）；
#   argon2id —— Argon2id 内存硬派生（默认 3 轮 × 128 MiB × 4 线程），
#               显著抬高 GPU/ASIC 离线破解成本；需要 argon2-cffi；
# v1.0.2.3 起 nonce = 随机 8 字节前缀 + 4 字节大端块序号（总长 12 字节
# 不变）；更早版本为 4 字节前缀 + 8 字节序号，读取时两者都接受；
# 密文再进入分块/CRC/Reed-Solomon 流程：CRC+RS 负责纠错恢复，
# GCM 负责认证——RS 恢复出的块经 CRC 验证后与原始密文逐字节一致，
# 因此加密归档的比特级损坏同样可以被自动修复（先纠错、后认证）；
# 加密只作用于载荷；归档头本身自 v1.1.0.0 起同样纳入 Reed-Solomon
# 保护，避免归档头成为纠错盲区。

KDF_ITERATIONS = 600_000
CHUNK_SIZE = 4 * 1024 * 1024  # 每块明文大小，密文每块多 16 字节认证标签
_SALT_LEN = 16
_NONCE_LEN = 12  # AES-GCM 标准 nonce 长度
_NONCE_PREFIX_LEN = 8  # v1.0.2.3+ 写入：8 字节随机前缀 + 4 字节块序号
_VALID_NONCE_PREFIX_LENS = (_NONCE_PREFIX_LEN,)

# Argon2id 默认派生参数（可被头中 kdf_params 覆盖，读取时校验范围）
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 128 * 1024  # 128 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
# 读取侧安全上限：防止恶意头诱导超大内存/时间消耗
MAX_ARGON2_TIME_COST = 6
MAX_ARGON2_MEMORY_KIB = 256 * 1024  # 256 MiB；限制恶意归档的资源消耗
MAX_ARGON2_PARALLELISM = 8

# 可选加密方案（ARH2 专用）：值为写入归档头 crypto.kdf 的标识
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
            iterations = _strict_json_int(info.get('iterations', KDF_ITERATIONS),
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
                 progress=None, total=None, crypto='gcm'):
    """加密 src_path → dst_path，返回可写入 JSON 头的 KDF 参数字典。

    crypto: 'gcm'（PBKDF2-HMAC-SHA256）或 'argon2id'（Argon2id 内存硬派生），
    两者载荷加密均为 AES-256-GCM，仅密钥派生方式不同。
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
    return info


def decrypt_file(src_path, dst_path, kdf_info, password,
                 progress=None, total=None):
    """解密 src_path → dst_path。密码错误或数据被篡改时抛 CryptoError。"""
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
    except Exception:
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
    """校验中心目录 AEAD 参数，校验中心目录加密参数。"""
    try:
        if not isinstance(info, dict) or info.get('algo', 'AES-256-GCM') != 'AES-256-GCM':
            raise ValueError
        salt = base64.b64decode(info['salt'], validate=True)
        nonce = base64.b64decode(info['nonce'], validate=True)
        if len(salt) != _SALT_LEN or len(nonce) != _NONCE_LEN:
            raise ValueError
        kdf = info.get('kdf', KDF_PBKDF2)
        if kdf == KDF_PBKDF2:
            iterations = _strict_json_int(info.get('iterations', KDF_ITERATIONS),
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
            iterations = KDF_ITERATIONS
        else:
            raise ValueError
        return salt, nonce, kdf, iterations, params
    except Exception:
        raise CryptoError('中心目录加密参数损坏或超出安全范围')


def _decrypt_blob(ct, info, password):
    """解密中心目录；"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce, kdf, iterations, params = _validate_blob_crypto_info(info)
    if isinstance(password, str):
        password = password.encode('utf-8')
    try:
        key = derive_key_auto(password, salt, kdf=kdf,
                              iterations=iterations, kdf_params=params)
        return AESGCM(key).decrypt(nonce, ct, None)
    except CryptoError:
        raise
    except Exception:
        raise CryptoError('中心目录解密失败：密码错误或数据被篡改')


# ======================================================================
# ARH2 归档格式
# ======================================================================

# 文件布局：魔数 + JSON 头 + 数据块 + RS 校验块 + 受保护的头部 +
# 受保护的中心化目录 + 自描述尾注。头部和目录均使用 Cauchy-MDS RS。

MAGIC = b'ARH2\x00\x01'
TRAILER_MAGIC = b'ARH2\x00\x02'  # 尾注定位标识
MAX_SHARDS = 255  # GF(256) 码字长度上限
MAX_HEADER = 64 * 1024 * 1024  # 头长度上限，防止恶意头
MAX_BLOCK_SIZE = 256 * 1024 * 1024  # 单次分块读写的安全上限
MAX_CRYPTO_CHUNK_SIZE = 256 * 1024 * 1024
MAX_KDF_ITERATIONS = 2_000_000

# 头保护参数：头 JSON 按固定 64 KiB 等长分块（头通常远小于 1 MiB，
# 分块数 HB 很小）；头校验块数量取 HB 的 20%（下限 2、上限 16），
# 足以承受多块同时损坏；HB + HP 上限同样受 MAX_SHARDS 约束。
HEADER_BLOCK_SIZE = 64 * 1024
MAX_HEADER_PARITY = 16
MAX_TRAILER = 1024 * 1024  # 尾注长度上限（含 10 字节固定前缀）

# 头自校验字段：除该字段外整个头规范化 JSON 的 CRC32。
_HEADER_CRC_FIELD = 'header_crc'

_WIN_ABS = re.compile(r'^[a-zA-Z]:[\\/]')


def _crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def _canonical_header_json(hdr):
    """头自校验用的规范化 JSON 字节：排除 header_crc 字段自身，
    键排序与分隔符固定，保证同一份头内容生成同样的字节。"""
    h = {k: v for k, v in hdr.items() if k != _HEADER_CRC_FIELD}
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
    """避免输出归档把自身也打包进去。"""
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

_VOL_RE = re.compile(r'^(.*)\.(\d{3})$')


def split_volumes(archive_path, volume_size, progress=None):
    """把归档拆分为 name.ext.001 / .002 / ...，不覆盖任何既有分卷。

    只有全部分卷写入成功后才删除原归档；失败时清理本次生成的分卷，
    保留原始单文件归档，避免覆盖旧分卷或留下看似完整的残缺集合。
    """
    volume_size = int(volume_size)
    if volume_size < 1:
        raise ArchiveError('分卷大小必须是正整数')
    total = os.path.getsize(archive_path)
    if total <= volume_size:
        return 0
    count = -(-total // volume_size)
    if count > 999:
        raise ArchiveError('分卷数量超过 999，请增大分卷大小')
    volumes = ['%s.%03d' % (archive_path, i) for i in range(1, count + 1)]
    parent = os.path.dirname(os.path.abspath(archive_path)) or os.curdir
    prefix = os.path.basename(archive_path) + '.'
    existing_parts = [entry.path for entry in os.scandir(parent)
                      if entry.name.startswith(prefix)
                      and len(entry.name[len(prefix):]) == 3
                      and entry.name[len(prefix):].isdigit()]
    if existing_parts:
        raise ArchiveError('检测到已有同名前缀分卷，拒绝覆盖或混合旧分卷: %s'
                           % ', '.join(existing_parts[:5]))
    created = []
    done = 0
    try:
        with open(archive_path, 'rb') as fin:
            for idx, vol in enumerate(volumes, 1):
                chunk = fin.read(volume_size)
                if not chunk:
                    raise ArchiveError('分卷源文件读取提前结束')
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
    """定位并校验连续分卷；发现序号缺口时拒绝静默忽略后续分卷。"""
    base = str(path)
    m = _VOL_RE.match(base)
    if m:
        base = m.group(1)
    elif os.path.isfile(base):
        return None
    parent = os.path.dirname(os.path.abspath(base)) or os.curdir
    prefix = os.path.basename(base) + '.'
    numbers = []
    for entry in os.scandir(parent):
        if not entry.is_file(follow_symlinks=False) or not entry.name.startswith(prefix):
            continue
        suffix = entry.name[len(prefix):]
        if len(suffix) == 3 and suffix.isdigit():
            numbers.append(int(suffix))
    numbers.sort()
    if not numbers:
        return None
    if numbers[0] != 1 or numbers != list(range(1, numbers[-1] + 1)):
        raise ArchiveError('分卷序号不连续或缺少 .001 起始分卷: %s' % base)
    return ['%s.%03d' % (base, i) for i in numbers]


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
        fd, self._tmp = tempfile.mkstemp(prefix='.arh2_join_', suffix=ext,
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

def _protect_blob(blob, what='数据'):
    """对一块 JSON 字节做 Reed-Solomon 保护（归档头/中心化目录通用）。

    返回 (blocks, parity, layout)：
    - blocks: HB 个等长（HEADER_BLOCK_SIZE）数据块，末块零填充；
    - parity: HP 个校验块（同一 RS 编码，与载荷分片相互独立）；
    - layout: 写入尾注的自描述布局（crc/len/bs/hb/hp/crcs/pcrc，
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
    parity = [bytes(p) for p in rs.encode(blocks, hp)] if hp else []
    return blocks, parity, {
        'crc': orig_crc,   # 原始字节的 CRC32，读取时先比对
        'len': orig_len,
        'bs': hb_size,
        'hb': hb,
        'hp': hp,
        'codec': 'cauchy-v1',
        'crcs': [_crc(b) for b in blocks],
        'pcrc': [_crc(p) for p in parity],
    }


def _create_arh2(paths, out_path, level=9, redundancy=3, block_size=1 << 20,
                 password=None, crypto='gcm', cd_encrypt=False, progress=None):
    """创建 .arh2 归档（Cauchy-MDS RS + 中心化目录，目录可选加密）。"""
    return _build_arh2(paths, out_path, level, redundancy, block_size,
                       password, crypto, progress, cd_encrypt=cd_encrypt)


def _build_arh2(paths, out_path, level=9, redundancy=3, block_size=1 << 20,
                password=None, crypto='gcm', progress=None, cd_encrypt=False):
    """创建 .arh2 归档，统一使用 Cauchy-MDS 纠删码和中心化目录。"""
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    redundancy = min(max(int(redundancy), 0), 50)
    block_size = max(int(block_size), 4096)
    level = int(level)
    if not 0 <= level <= 22:
        raise ArchiveError('压缩级别必须是 0-22 的整数')
    # 中间产物统一放在程序临时目录（%LOCALAPPDATA%\MienArch\ARH2），
    # 而不是输出目录，避免污染用户选择的位置。
    tmpdir = tempfile.mkdtemp(prefix='.arh2_', dir=app_temp_dir())
    try:
        compression = 'store' if level == 0 else 'zstd'
        _rep(progress, '打包%s中...' % ('' if level == 0 else '并 Zstd 压缩'), 3)
        comp = os.path.join(tmpdir, 'payload.bin')
        members = []  # .arh2 中心化目录的条目元数据（_add_paths 收集）
        try:
            with open(comp, 'wb') as raw:
                if compression == 'zstd':
                    with open_writer(raw, level) as zw, \
                         tarfile.open(fileobj=zw, mode='w|') as tar:
                        _add_paths(tar, paths,
                                   collect=members)
                else:
                    with tarfile.open(fileobj=raw, mode='w|') as tar:
                        _add_paths(tar, paths,
                                   collect=members)
        except ImportError as e:
            raise ArchiveError(str(e))

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

        rs_codec = 'cauchy-v1'
        hdr = {
            'version': 1,
            'rs_codec': rs_codec,
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
        rs = ReedSolomon()
        parity = [bytearray(bs) for _ in range(k)]
        blocks_tmp = os.path.join(tmpdir, 'blocks.bin')
        written = 0
        with open(comp, 'rb') as fin, open(blocks_tmp, 'wb') as fout:
            for i in range(n):
                data = fin.read(bs)
                real = len(data)
                padded = data if real == bs else data + b'\x00' * (bs - real)
                hdr['block_crc'].append(_crc(data))
                hdr['block_len'].append(real)
                fout.write(data)
                for j in range(k):
                    c = rs.coeff_cauchy(j, i, n)
                    parity[j] = bytearray(xor_bytes(parity[j], padded.translate(rs.table(c))))
                written += real
                _rep(progress, '处理分块 %d/%d' % (i + 1, n),
                     25 + int(60 * written / max(payload_size, 1)))
            if written != payload_size or fin.read(1):
                raise ArchiveError('载荷在分块期间发生变化，已中止创建归档')
        for j in range(k):
            hdr['parity_crc'].append(_crc(bytes(parity[j])))

        # 头自校验：在所有头字段就绪后计算 CRC32
        hdr[_HEADER_CRC_FIELD] = _crc(_canonical_header_json(hdr))

        _rep(progress, '写入归档...', 84)
        out_parent = os.path.dirname(os.path.abspath(out_path)) or os.curdir
        fd_out, out_tmp = tempfile.mkstemp(prefix='.arh2_build_', dir=out_parent)
        os.close(fd_out)
        try:
            # mkstemp 默认 0600；新归档恢复常见文件权限，已有普通文件则保留其权限。
            try:
                old_mode = os.lstat(out_path).st_mode
                output_mode = stat.S_IMODE(old_mode) if stat.S_ISREG(old_mode) else 0o644
            except OSError:
                output_mode = 0o644
            os.chmod(out_tmp, output_mode)
            with open(out_tmp, 'wb') as out, open(blocks_tmp, 'rb') as fin:
                out.write(MAGIC)
                hj = json.dumps(hdr, separators=(',', ':')).encode('utf-8')
                out.write(struct.pack('>Q', len(hj)))
                out.write(hj)
                shutil.copyfileobj(fin, out, 1 << 20)
                for j in range(k):
                    out.write(bytes(parity[j]))
                # 归档头 RS 保护——头分块 + 头校验块 + 自描述尾注
                _rep(progress, '生成归档头恢复数据...', 91)
                hblocks, hparity, hinfo = _protect_blob(hj, '归档头')
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
                cblocks, cparity, cinfo = _protect_blob(cj, '中心化目录')
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
                out.write(TRAILER_MAGIC)                   # 最末尾：从尾向前自定位
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

        _rep(progress, '完成', 100)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _crypto_encrypt(src, dst, password, progress, crypto='gcm'):
    total = os.path.getsize(src)
    return encrypt_file(src, dst, password,
                        progress=lambda d, t: _rep(progress, '加密中...',
                                                   15 + 8 * d // max(t, 1)),
                        total=total, crypto=crypto)

def _header_int(value, name, minimum, maximum=None):
    """读取严格 JSON 整数；拒绝布尔值、浮点数、字符串与越界值。"""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ArchiveError('归档头字段 %s 必须为整数' % name)
    if value < minimum or (maximum is not None and value > maximum):
        raise ArchiveError('归档头字段 %s 越界: %s' % (name, value))
    return value


def _validate_header(hdr):
    """在访问分块表前做结构校验，避免损坏头导致二次异常或超大 read()。"""
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
    if rs_codec != 'cauchy-v1':
        raise ArchiveError('归档头中 Reed-Solomon 编码标识无效')

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
    if encrypted:
        crypto_info = hdr.get('crypto')
        if not isinstance(crypto_info, dict):
            raise ArchiveError('加密归档缺少加密参数')
        _validate_payload_crypto_info(crypto_info, payload_size=payload_size)

    # 头自校验字段必须存在且有效。
    if hdr.get(_HEADER_CRC_FIELD) is None:
        raise ArchiveError('归档头缺少 header_crc')
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
    hdr['rs_codec'] = rs_codec


def _read_trailer(f, file_size):
    """读取尾注并校验 CRC。返回 (trailer_dict, trailer_total_len)。"""
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


def _protected_blob_span(layout, what='数据'):
    """严格校验尾注保护布局并返回保护区总字节数。"""
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
            or codec != 'cauchy-v1'
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
    codec = layout.get('codec')

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
        rec = ReedSolomon().recover(blocks, par, missing)
        for i, b in rec.items():
            if _crc(bytes(b)) != crcs[i]:
                raise ArchiveError('%s恢复数据未通过 CRC 校验，无法安全读取' % what)
            blocks[i] = b
        blob = b''.join(blocks)[:hlen]
    if _crc(blob) != hcrc:
        raise ArchiveError('%s恢复结果校验失败，无法安全读取' % what)
    return blob


def _open_archive_impl(path):
    """读取并校验 ARH2 归档头，返回 header 字典。

    短读时抛出清晰的 ArchiveError；头部损坏时使用 Cauchy-MDS 分片恢复。
    """
    with open(path, 'rb') as f:
        if f.read(6) != MAGIC:
            raise ArchiveError('不是 ARH2 归档: %s' % path)
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
        trailer_start = file_size - trailer_len
        protected_layout = None
        header_region_end = None
        cd_span = 0
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
        if cd_codec != hdr_codec or cd_codec != 'cauchy-v1':
            raise ArchiveError('头部与中心目录 RS 编码标识不一致')
        cd_span = _protected_blob_span(cd, '中心化目录')
        header_region_end = trailer_start - cd_span
        _protected_blob_span(hl, '归档头')
        if header_region_end < 14:
            raise ArchiveError('ARH2 头部保护区位置异常')
        if _crc(hj) != hl['crc']:
            hj = _recover_blob(f, header_region_end, hl, '归档头')
        protected_layout = hl
        try:
            hdr = json.loads(hj.decode('utf-8'))
        except Exception:
            raise ArchiveError('归档头损坏（JSON 解析失败）')
        _validate_header(hdr)
        if hdr.get('version') != 1 or hdr.get('rs_codec') != 'cauchy-v1':
            raise ArchiveError('不支持的 ARH2 格式或 Reed-Solomon 编码')
        payload_end = data_offset + hdr['payload_size'] + \
            hdr['num_parity'] * hdr['block_size']
        if payload_end > file_size:
            raise ArchiveError('归档数据区或校验区被截断')
        header_span = _protected_blob_span(protected_layout, '归档头')
        expected_header_start = header_region_end - header_span
        if expected_header_start != payload_end:
            raise ArchiveError('归档数据/头保护/中心目录区域边界不连续')
        hdr['data_offset'] = data_offset
        # 暂存尾注（.arh2 列目录快路径用）；须在 _validate_header 之后
        # 再挂到 hdr 上，避免参与 header_crc 的规范化 JSON 计算
        hdr['_trailer'] = trailer
        hdr['_trailer_len'] = trailer_len
        return hdr


def _load_blocks(path, hdr):
    """读出全部分块并校验 CRC。返回 (data_blocks, parity_blocks, missing)。"""
    n, k = hdr['num_blocks'], hdr['num_parity']
    data, missing = [], []
    with open(path, 'rb') as f:
        f.seek(hdr['data_offset'])
        for i in range(n):
            blk = f.read(hdr['block_len'][i])
            if len(blk) != hdr['block_len'][i] or _crc(blk) != hdr['block_crc'][i]:
                data.append(None)
                missing.append(i)
            else:
                data.append(blk)
        par = []
        for j in range(k):
            pb = f.read(hdr['block_size'])
            if len(pb) != hdr['block_size'] or _crc(pb) != hdr['parity_crc'][j]:
                par.append(None)
            else:
                par.append(pb)
    return data, par, missing


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
    fd, tmp_path = tempfile.mkstemp(prefix='.arh2_extract_', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as dst:
            shutil.copyfileobj(source, dst, 1 << 20)
            dst.flush()
            os.fsync(dst.fileno())
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


def _assemble_payload(data, hdr, tmpdir, password, progress):
    """把恢复出的分块拼成载荷文件（密文或明文流），返回文件路径。

    密文会在写入后解密为 <payload>.dec 并返回解密结果路径。
    """
    fd, payload = tempfile.mkstemp(prefix='.arh2_payload_', dir=app_temp_dir())
    with os.fdopen(fd, 'wb') as f:
        for i, b in enumerate(data):
            if b is None:
                raise ArchiveError('内部错误: 块 %d 未恢复' % i)
            # RS 恢复出的块补零到了 block_size，只写原始长度
            f.write(b[:hdr['block_len'][i]])
    if not hdr.get('encrypted'):
        return payload
    if not password:
        os.unlink(payload)
        raise ArchiveError('该归档已加密，需要提供密码（-p/--password）')
    _rep(progress, 'AES-256-GCM 解密校验中...', 55)
    dec = payload + '.dec'
    total = hdr.get('payload_size', 0)
    try:
        decrypt_file(payload, dec, hdr.get('crypto') or {}, password,
                     progress=lambda d, t: _rep(progress, 'AES-256-GCM 解密中...',
                                                55 + 5 * d // max(t, 1)),
                     total=total)
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


def _restore(data, hdr, outdir, progress, write, password=None, members=None):
    """把载荷（解密后）解包。write=False 时只做测试。

    members: 只处理给定名称（文件或目录子树）的条目；None 表示全部。
    """
    members = _norm_members(members)
    if write:
        os.makedirs(outdir, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix='.arh2_restore_', dir=app_temp_dir())
    payload_path = None
    try:
        payload_path = _assemble_payload(data, hdr, tmpdir, password, progress)
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
                count = _extract_tar(tar, outdir, progress, write, members)
            return count
    finally:
        # 载荷临时文件（mkstemp 产生，位于 app_temp_dir）用完即删，避免缓存堆积
        if payload_path:
            try:
                os.unlink(payload_path)
            except OSError:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)


class _NullCtx:
    """把任意读对象包成上下文管理器（仅存储模式用）。"""

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        return self.f

    def __exit__(self, *exc):
        return False


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


def _extract_tar(tar, outdir, progress, write, members=None):
    """遍历 tar 流并安全写出。返回处理的普通文件数。"""
    count = 0
    dirs = []
    seen_names = {}
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
        elif m.isreg():
            if write:
                parent = os.path.dirname(target)
                if parent:
                    os.makedirs(parent, exist_ok=True)
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
    # 目录 mtime 最后设置（子文件写入会刷新目录时间）
    if write:
        for d, mt in reversed(dirs):
            try:
                os.utime(d, (mt, mt))
            except OSError:
                pass
    return count


def _repair(path, hdr, progress):
    """尽可能修复归档，返回 (data, par, missing)。"""
    data, par, missing = _load_blocks(path, hdr)
    if missing and hdr.get('method') == 'rs':
        ok = sum(1 for p in par if p is not None)
        if len(missing) > ok:
            raise ArchiveError('损坏 %d 块，超出恢复上限 %d 块，归档无法修复'
                               % (len(missing), ok))
        _rep(progress, 'Reed-Solomon 修复 %d 个块...' % len(missing), 30)
        rec = ReedSolomon().recover(data, par, missing)
        for i, b in rec.items():
            real_len = hdr['block_len'][i]
            if len(b) < real_len or _crc(bytes(b[:real_len])) != hdr['block_crc'][i]:
                raise ArchiveError('恢复数据未通过 CRC 校验，归档无法安全修复')
            data[i] = b
        missing = []
    return data, par, missing


def extract_archive(path, outdir='.', progress=None, password=None,
                    members=None):
    """解压归档到 outdir，自动修复可修复的损坏。

    path: .arh2；支持多分卷归档（给出任一分卷或基名均可，
    会自动合并到临时目录后解压）；
    members: 可选，只解压这些条目（文件或目录子树）。
    """
    with _ArchiveInput(path, progress) as real_path:
        return _extract_archive(real_path, outdir, progress=progress,
                                password=password, members=members)


def _extract_archive(path, outdir='.', progress=None, password=None,
                     members=None):
    """extract_archive 的实现（path 已是真实单文件路径）。"""
    detect_format(path)
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    data, _par, missing = _repair(path, hdr, progress)
    if missing:
        raise ArchiveError('%d 个数据块损坏且无法恢复' % len(missing))
    count = _restore(data, hdr, outdir, progress, write=True,
                     password=password, members=members)
    _rep(progress, '完成，共 %d 个文件' % count, 100)


def test_archive(path, progress=None, password=None):
    """测试归档完整性（含修复能力与加密认证），不写出文件。

    支持多分卷归档（任一分卷或基名均可）。
    """
    with _ArchiveInput(path, progress) as real_path:
        return _test_archive(real_path, progress=progress, password=password)


def _test_archive(path, progress=None, password=None):
    """test_archive 的实现（path 已是真实单文件路径）。"""
    detect_format(path)
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    data, _par, missing = _repair(path, hdr, progress)
    if missing:
        raise ArchiveError('%d 个数据块损坏且无法恢复' % len(missing))
    count = _restore(data, hdr, '.', progress, write=False, password=password)
    _rep(progress, '归档完好，共 %d 个文件' % count, 100)


# ---- ARH2 中心目录快速列举 / tar 流回退 ----

def _list_arh2(path, progress=None, password=None):
    """.arh2 列目录：优先读中心化目录（O(目录大小），无需解压载荷）；
    尾注无目录布局（旧布局/异常归档）时回退流式扫描，保证任何可读
    归档都能列出内容。"""
    hdr = open_archive(path)
    trailer = hdr.get('_trailer')
    if isinstance(trailer, dict) and isinstance(trailer.get('cd'), dict):
        try:
            entries = _read_central_directory(path, trailer, hdr, password)
        except (ArchiveError, ValueError, TypeError, KeyError) as exc:
            # 未加密中心目录只是缓存副本；损坏时回退 tar 权威流。
            # 加密目录绝不回退，以免绕过“列目录需密码”的隐私预期。
            if trailer['cd'].get('encrypted') is True:
                raise
            _rep(progress, '中心目录不可用，回退流式扫描: %s' % exc, 10)
            return _list_arh2_stream(path, progress=progress, password=password)
        _rep(progress, '共 %d 个条目（中心化目录）' % len(entries), 100)
        return entries
    return _list_arh2_stream(path, progress=progress, password=password)


def _read_central_directory(path, trailer, hdr, password):
    """读取 .arh2 中心化目录：RS 保护（自动修复损坏块）+ 可选解密。

    返回 7-Zip 风格的条目字典列表（与 _list_arh2_stream 慢路径字段一致）。
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


def _list_arh2_stream(path, progress=None, password=None):
    """ARH2 中心目录不可用时，恢复载荷并流式扫描 tar 头信息。"""
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    data, _par, missing = _repair(path, hdr, progress)
    if missing:
        raise ArchiveError('%d 个数据块损坏且无法恢复' % len(missing))
    method = 'zstd 级别 %s' % hdr['zstd_level'] \
        if hdr.get('compression', 'zstd') == 'zstd' else 'store'
    encrypted = bool(hdr.get('encrypted'))
    entries = []
    tmpdir = tempfile.mkdtemp(prefix='.arh2_list_', dir=app_temp_dir())
    payload_path = None
    try:
        _rep(progress, '列出归档内容...', 40)
        payload_path = _assemble_payload(data, hdr, tmpdir, password, progress)
        with open(payload_path, 'rb') as pf:
            # 总量取实际载荷文件大小（加密归档 payload_size 为密文大小）
            counter = _CountingReader(pf, os.path.getsize(payload_path),
                                      lambda p: _rep(progress, '列出归档内容...',
                                                     40 + p * 55 // 100))
            if hdr.get('compression', 'zstd') == 'store':
                src_ctx = _NullCtx(counter)
            else:
                src_ctx = open_reader(counter)
            with src_ctx as zr, tarfile.open(fileobj=zr, mode='r|') as tar:
                seen_names = {}
                for m in tar:
                    if not (m.isdir() or m.isreg() or m.issym()):
                        continue
                    name = _normalize_member_name(m.name)
                    if not name or name == '.':
                        continue
                    _safe_target('.', name, check_existing=False)
                    is_dir = m.isdir()
                    if not _register_member_name(name, is_dir, seen_names, 'tar 归档'):
                        continue
                    entries.append({
                        'name': name.rstrip('/') if m.isdir() else name,
                        'size': 0 if m.isdir() else m.size,
                        'compressed': None,  # tar 流不记录单项压缩后大小
                        'mtime': float(m.mtime) if m.mtime else None,
                        'is_dir': is_dir,
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
        shutil.rmtree(tmpdir, ignore_errors=True)
    _rep(progress, '共 %d 个条目' % len(entries), 100)
    return entries



# ======================================================================
# ARH2-only public API
# ======================================================================

SUPPORTED_FORMATS = ('arh2',)


def detect_format(path):
    """仅识别 .arh2；分卷由 _ArchiveInput 先合并后再检查扩展名。"""
    if os.path.splitext(str(path))[1].lower() != '.arh2':
        raise ArchiveError('仅支持 .arh2 归档文件: %s' % path)
    return 'arh2'


def open_archive(path):
    """读取并校验 ARH2 归档。"""
    detect_format(path)
    hdr = _open_archive_impl(path)
    trailer = hdr.get('_trailer')
    if (not isinstance(trailer, dict) or trailer.get('fmt') != 'arh2'
            or not isinstance(trailer.get('cd'), dict)
            or not isinstance(trailer.get('hdr'), dict)):
        raise ArchiveError('该文件不是受支持的 ARH2（缺少中心化目录布局）')
    if hdr.get('version') != 1 or hdr.get('rs_codec') != 'cauchy-v1':
        raise ArchiveError('仅支持 ARH2')
    return hdr


def create_archive(paths, out_path, level=9, redundancy=3,
                   block_size=1 << 20, password=None, volume_size=None,
                   progress=None, crypto='gcm', cd_encrypt=False):
    """创建 ARH2 归档；可选载荷/中心目录加密及分卷。"""
    detect_format(out_path)
    if volume_size is not None:
        if isinstance(volume_size, bool):
            raise ArchiveError('分卷大小必须为正整数')
        try:
            volume_size = int(volume_size)
        except (TypeError, ValueError, OverflowError):
            raise ArchiveError('分卷大小必须为正整数')
        if volume_size < 1:
            raise ArchiveError('分卷大小必须为正整数')
    if cd_encrypt and not password:
        raise ArchiveError('加密中心目录需要先启用加密并提供密码')
    result = _create_arh2(
        paths, out_path, level=level, redundancy=redundancy,
        block_size=block_size, password=password, crypto=crypto,
        cd_encrypt=cd_encrypt, progress=progress)
    if volume_size:
        split_volumes(out_path, volume_size, progress=progress)
    return result


def info_archive(path):
    """读取 ARH2 元信息，不解压载荷；支持多分卷。"""
    with _ArchiveInput(path) as real_path:
        hdr = open_archive(real_path)
        trailer = hdr['_trailer']
        cd = trailer['cd']
        crypto_info = hdr.get('crypto') if isinstance(hdr.get('crypto'), dict) else {}
        kdf_label = {
            KDF_PBKDF2: 'AES-256-GCM (PBKDF2)',
            KDF_ARGON2ID: 'AES-256-GCM (Argon2id)',
        }.get(crypto_info.get('kdf', KDF_PBKDF2), 'AES-256-GCM')
        return {
            'path': path,
            'size': os.path.getsize(real_path),
            'format': 'arh2',
            'version': 5,
            'format_version': hdr.get('version'),
            'rs_codec': hdr['rs_codec'],
            'header_protected': True,
            'central_directory': True,
            'cd_encrypted': bool(cd.get('encrypted')),
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


def list_archive(path, progress=None, password=None):
    """列出 ARH2 成员；优先读取受 RS 保护的中心目录。"""
    with _ArchiveInput(path, progress) as real_path:
        detect_format(real_path)
        return _list_arh2(real_path, progress=progress, password=password)



# ======================================================================
# PySide6 GUI
# ======================================================================

try:
    from PySide6.QtCore import Qt, QThread, QTimer, Signal
    from PySide6.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog,
        QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QMainWindow,
        QMessageBox, QProgressBar, QPushButton, QSlider, QTabWidget, QTextEdit,
        QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
    )
    from PySide6.QtGui import QIcon
    _GUI_AVAILABLE = True
except ImportError:
    _GUI_AVAILABLE = False

_APP_ID = 'MienArch.ARH2.ArchiveTool.1.0.0.2'
BLOCK_SIZES = ['64K', '128K', '256K', '512K', '1M', '2M', '4M', '8M',
               '16M', '32M', '64M', '128M']
VOLUME_PRESETS = ['不分卷', '32M', '128M', '512M', '1024M', '650M (CD)',
                  '4092M (FAT)', '4480M (DVD)', '8128M (DVD DL)', '23040M (BD)']


def application_dir():
    """脚本运行时取 .py 所在目录；PyInstaller 下取 exe 所在目录。"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _load_app_icon():
    if not _GUI_AVAILABLE:
        return None
    icon_path = os.path.join(application_dir(), 'arh2.png')
    if os.path.isfile(icon_path):
        icon = QIcon(icon_path)
        if not icon.isNull():
            return icon
    return None


def _apply_windows_taskbar_icon():
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(_APP_ID)
        except Exception:
            pass


def fmt_size(n):
    if n is None:
        return ''
    value = float(n)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB', 'PB'):
        if abs(value) < 1024.0 or unit == 'PB':
            return ('%.0f %s' if unit == 'B' else '%.2f %s') % (value, unit)
        value /= 1024.0


def fmt_time(ts):
    if not ts:
        return ''
    import datetime
    try:
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def default_archive_name():
    import datetime
    return 'Archive-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S') + '.arh2'


if _GUI_AVAILABLE:
    class Worker(QThread):
        progressed = Signal(str, int)
        succeeded = Signal(object)
        failed = Signal(str)

        def __init__(self, job, parent=None):
            super().__init__(parent)
            self._job = job

        def run(self):
            try:
                result = self._job(lambda msg, pct: self.progressed.emit(msg, pct))
            except Exception:
                self.failed.emit(traceback.format_exc())
            else:
                self.succeeded.emit(result)


    class CreateTab(QWidget):
        def __init__(self, window):
            super().__init__()
            self.window = window
            lay = QVBoxLayout(self)

            lay.addWidget(QLabel('文件列表（全部打包进一个 ARH2 归档）:'))
            self.list = QListWidget()
            self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
            lay.addWidget(self.list)

            row = QHBoxLayout()
            for text, slot in (('添加文件', self.add_files),
                               ('添加目录', self.add_dir),
                               ('移除选中', self.remove_selected)):
                button = QPushButton(text)
                button.clicked.connect(slot)
                row.addWidget(button)
            lay.addLayout(row)

            row = QHBoxLayout()
            row.addWidget(QLabel('输出:'))
            self.out = QLineEdit(default_archive_name())
            self.out.setPlaceholderText('Archive-年月日时分秒.arh2')
            row.addWidget(self.out)
            browse = QPushButton('浏览…')
            browse.clicked.connect(self.browse)
            row.addWidget(browse)
            lay.addLayout(row)

            row = QHBoxLayout()
            row.addWidget(QLabel('压缩等级:'))
            self.level = QSlider(Qt.Horizontal)
            self.level.setRange(0, 22)
            self.level.setValue(9)
            self.level.setTickPosition(QSlider.TicksBelow)
            self.level.setTickInterval(1)
            self.level.valueChanged.connect(self._on_level)
            row.addWidget(self.level)
            self.level_label = QLabel()
            row.addWidget(self.level_label)
            self._on_level(9)
            lay.addLayout(row)

            row = QHBoxLayout()
            row.addWidget(QLabel('恢复数据:'))
            self.red = QSlider(Qt.Horizontal)
            self.red.setRange(0, 50)
            self.red.setValue(3)
            self.red.setTickPosition(QSlider.TicksBelow)
            self.red.setTickInterval(5)
            self.red.valueChanged.connect(self._on_red)
            row.addWidget(self.red)
            self.red_label = QLabel()
            row.addWidget(self.red_label)
            self._on_red(3)
            lay.addLayout(row)

            row = QHBoxLayout()
            row.addWidget(QLabel('分块大小:'))
            self.block = QComboBox()
            self.block.addItems(BLOCK_SIZES)
            self.block.setCurrentText('1M')
            row.addWidget(self.block)
            self.encrypt = QCheckBox('加密')
            self.encrypt.toggled.connect(self._on_encrypt_toggled)
            row.addWidget(self.encrypt)
            self.crypto_algo = QComboBox()
            self.crypto_algo.addItems(['PBKDF2（经典）', 'Argon2id（内存硬 KDF）'])
            self.crypto_algo.setToolTip(
                '载荷和中心目录均使用 AES-256-GCM；此项选择密钥派生算法')
            row.addWidget(self.crypto_algo)
            self.cd_encrypt = QCheckBox('加密中心目录')
            self.cd_encrypt.setToolTip('勾选后，列目录也需要密码；默认不加密')
            self.cd_encrypt.setEnabled(False)
            row.addWidget(self.cd_encrypt)
            self.pwd = QLineEdit()
            self.pwd.setPlaceholderText('请输入密码')
            self.pwd.setEchoMode(QLineEdit.Password)
            self.pwd.setEnabled(False)
            row.addWidget(self.pwd)
            row.addStretch(1)
            lay.addLayout(row)

            row = QHBoxLayout()
            row.addWidget(QLabel('分卷大小:'))
            self.vol = QComboBox()
            self.vol.setEditable(True)
            self.vol.addItems(VOLUME_PRESETS)
            self.vol.setCurrentIndex(0)
            self.vol.setToolTip('可手填（如 200M、1G）或选择预设；不分卷则输出单文件')
            row.addWidget(self.vol)
            row.addStretch(1)
            lay.addLayout(row)

            self.hint = QLabel(
                '.arh2：zstd 0-22 级 + Reed-Solomon 恢复数据 + 受保护的中心化目录；'
                'ARH2：Cauchy-MDS 纠删码、受保护的中心化目录，支持 PBKDF2 / Argon2id。')
            self.hint.setStyleSheet('color: #666;')
            self.hint.setWordWrap(True)
            lay.addWidget(self.hint)

            row = QHBoxLayout()
            self.btn_pack = QPushButton('压缩')
            self.btn_pack.clicked.connect(self.pack)
            row.addStretch(1)
            row.addWidget(self.btn_pack)
            lay.addLayout(row)

        def _parse_size(self, text):
            value = str(text).strip().upper()
            mult = 1
            for suffix, factor in (('K', 1 << 10), ('M', 1 << 20), ('G', 1 << 30)):
                if value.endswith(suffix):
                    value = value[:-1].strip()
                    mult = factor
                    break
            number = float(value)
            if not math.isfinite(number) or number <= 0:
                raise ValueError('大小必须为正数')
            return int(number * mult)

        def _on_level(self, value):
            text = {0: '0 仅存储', 1: '1 最快', 19: '19 超高', 22: '22 最高'}.get(
                value, '%d' % value if value < 19 else '%d 超高' % value)
            self.level_label.setText(text)
            self.level_label.setToolTip('0 = 仅存储不压缩；数值越大压缩率越高、速度越慢')

        def _on_red(self, value):
            self.red_label.setText('%d%%' % value + ('（不生成）' if value == 0 else ''))

        def _on_encrypt_toggled(self, enabled):
            self.pwd.setEnabled(enabled)
            self.crypto_algo.setEnabled(enabled)
            self.cd_encrypt.setEnabled(enabled)
            if not enabled:
                self.pwd.clear()
                self.cd_encrypt.setChecked(False)

        def add_files(self):
            files, _ = QFileDialog.getOpenFileNames(self, '选择文件')
            if files:
                self.list.addItems(files)

        def add_dir(self):
            directory = QFileDialog.getExistingDirectory(self, '选择目录')
            if directory:
                self.list.addItem(directory)

        def remove_selected(self):
            for item in self.list.selectedItems():
                self.list.takeItem(self.list.row(item))

        def browse(self):
            path, _ = QFileDialog.getSaveFileName(
                self, '输出 ARH2 归档', default_archive_name(), 'ARH2 归档 (*.arh2)')
            if path:
                if not path.lower().endswith('.arh2'):
                    path = os.path.splitext(path)[0] + '.arh2'
                self.out.setText(path)

        def pack(self):
            paths = [self.list.item(i).text() for i in range(self.list.count())]
            if not paths:
                QMessageBox.warning(self, '提示', '请先添加文件或目录')
                return
            out = self.out.text().strip()
            if not out:
                QMessageBox.warning(self, '提示', '请设置输出路径')
                return
            if not out.lower().endswith('.arh2'):
                out = os.path.splitext(out)[0] + '.arh2'
                self.out.setText(out)

            password = self.pwd.text() if self.encrypt.isChecked() else None
            if self.encrypt.isChecked() and not password:
                QMessageBox.warning(self, '提示', '请输入加密密码')
                return
            cd_encrypt = self.cd_encrypt.isChecked()
            if cd_encrypt and not password:
                QMessageBox.warning(self, '提示', '加密中心目录需要先启用加密并输入密码')
                return

            volume_size = None
            volume_text = self.vol.currentText().strip()
            if volume_text and volume_text != '不分卷':
                token = volume_text.split()[0].split('（')[0].split('(')[0]
                try:
                    volume_size = self._parse_size(token)
                except (ValueError, OverflowError):
                    QMessageBox.warning(
                        self, '提示', '分卷大小无效，请填写如 32M、650M、1G 或选择预设。')
                    return

            crypto_algo = 'argon2id' if self.crypto_algo.currentIndex() == 1 else 'gcm'
            done_msg = '已创建: %s' % out
            if volume_size:
                done_msg += '（按 %s 分卷）' % volume_text

            self.window.start_job(
                lambda prog: create_archive(
                    paths, out, level=self.level.value(), redundancy=self.red.value(),
                    block_size=self._parse_size(self.block.currentText()),
                    password=password, crypto=crypto_algo, cd_encrypt=cd_encrypt,
                    volume_size=volume_size, progress=prog),
                done_msg=done_msg, buttons=(self.btn_pack,))

    class OpenTab(QWidget):
        COLS = ('名称', '大小', '压缩后大小', '修改时间', '属性', 'CRC', '算法')

        def __init__(self, window):
            super().__init__()
            self.window = window
            self.archive = None      # 当前归档路径
            self.password = None     # 已确认的密码
            self.entries = []        # list_archive 的结果
            self._nodes = {}         # 路径 → QTreeWidgetItem

            lay = QVBoxLayout(self)

            # ---- 工具行 ----
            row = QHBoxLayout()
            self.btn_open = QPushButton('打开压缩包…')
            self.btn_open.clicked.connect(self.open_archive)
            row.addWidget(self.btn_open)
            # 解压到 所选目录/
            self.btn_extract = QPushButton('解压到…')
            self.btn_extract.clicked.connect(lambda: self.extract(False))
            # 解压到 所选目录/压缩包名/
            self.btn_extract_sub = QPushButton('解压到…/压缩包名/')
            self.btn_extract_sub.setToolTip(
                '解压到所选目录下以压缩包名命名的子文件夹中')
            self.btn_extract_sub.clicked.connect(lambda: self.extract(True))
            self.btn_test = QPushButton('测试')
            self.btn_test.clicked.connect(self.test)
            self.btn_info = QPushButton('信息')
            self.btn_info.clicked.connect(self.info)
            for b in (self.btn_extract, self.btn_extract_sub, self.btn_test,
                      self.btn_info):
                b.setEnabled(False)
                row.addWidget(b)
            row.addStretch(1)
            lay.addLayout(row)

            # ---- 归档概要 ----
            self.summary = QLabel('尚未打开归档。仅支持 .arh2')
            lay.addWidget(self.summary)

            # ---- 内容树（名称/大小/压缩后/修改时间/属性/CRC/算法）----
            self.tree = QTreeWidget()
            self.tree.setHeaderLabels(self.COLS)
            self.tree.setColumnWidth(0, 380)
            self.tree.setAlternatingRowColors(True)
            self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
            self.tree.itemDoubleClicked.connect(self._on_double_click)
            lay.addWidget(self.tree)

            # ---- 状态行 ----
            self.status = QLabel('')
            lay.addWidget(self.status)

        # ---- 打开 / 列目录 ----
        def open_archive(self, path=None):
            if not path:
                p, _ = QFileDialog.getOpenFileName(
                    self, '打开压缩包', '',
                    'ARH2 归档 (*.arh2);;ARH2 分卷 (*.arh2.001 *.001)')
                if not p:
                    return
                path = p
            self.password = None
            self.archive = None
            self.entries = []
            self.tree.clear()
            self.summary.setText('正在读取归档…')
            self.status.setText('')
            self._do_list(path)

        def _do_list(self, path):
            def job(prog):
                return list_archive(path, progress=prog,
                                              password=self.password)
            self.window.start_job(
                job, done_msg='', buttons=self._action_buttons(),
                on_ok=lambda entries: self._on_listed(path, entries),
                on_fail=lambda tb: self._on_list_failed(path, tb))

        def _on_listed(self, path, entries):
            self.archive = path
            self.entries = entries
            vols = find_volumes(path)
            if vols:
                # 分卷归档：基名去掉末尾 ".NNN" 共 4 个字符
                base = vols[0][:-4]
                size = sum(os.path.getsize(v) for v in vols)
                path = '%s（%d 个分卷）' % (base, len(vols))
            else:
                size = os.path.getsize(path)
            n_files = sum(1 for e in entries if not e['is_dir'])
            unpacked = sum(e['size'] for e in entries if not e['is_dir'])
            self.summary.setText(
                '%s    格式: ARH2    归档大小: %s    包含: %d 个文件 / %d 个目录    '
                '解压后: %s' % (path, fmt_size(size), n_files,
                                len(entries) - n_files, fmt_size(unpacked)))
            self._fill_tree(entries)
            for b in self._action_buttons():
                b.setEnabled(True)
            self.status.setText('共 %d 个条目' % len(entries))
            self.window.append_log('已打开: %s（%d 个条目）' % (path, len(entries)))

        @staticmethod
        def _is_password_error(tb):
            # 只检查 traceback 最后一行；完整 traceback 的代码行可能含
            # password= 参数名，不能因此把普通异常误判成密码错误。
            last = tb.strip().splitlines()[-1] if tb.strip() else ''
            lower = last.lower()
            return ('需要提供密码' in last or '密码错误' in last
                    or 'password' in lower)

        def _retry_after_password(self, tb, retry, title):
            """目录未加密时，payload 仍可能加密；对列目录后操作也提示密码。"""
            if self._is_password_error(tb):
                pw, ok = QInputDialog.getText(
                    self, '输入密码', '密码错误或归档已加密，请输入密码:',
                    QLineEdit.Password)
                if ok and pw:
                    self.password = pw
                    # 等当前 QThread 完全结束后再启动重试任务。
                    worker = self.window.worker
                    if worker is not None and worker.isRunning():
                        worker.finished.connect(lambda: QTimer.singleShot(0, retry))
                    else:
                        QTimer.singleShot(0, retry)
                    return
            self.password = None
            last = tb.strip().splitlines()[-1] if tb.strip() else ''
            self.window.show_error(tb, '%s: %s' % (title, last))

        def _on_list_failed(self, path, tb):
            self._retry_after_password(tb, lambda: self._do_list(path), '打开失败')

        # ---- 内容树填充 ----
        def _fill_tree(self, entries):
            self.tree.clear()
            self._nodes = {}
            skipped = 0
            for e in sorted(entries, key=lambda x: (x['name'].count('/'), x['name'])):
                if not self._add_entry(e):
                    skipped += 1
            self.tree.expandAll()
            if skipped:
                self.window.append_log('提示: %d 个条目的路径包含 ".." 或绝对路径，已跳过显示' % skipped)

        def _add_entry(self, e):
            name = e['name']
            if not name or name.startswith('/') or '..' in name.split('/'):
                return False
            parts = [p for p in name.split('/') if p]
            if not parts:
                return False
            parent = None
            prefix = ''
            # 逐级确保父目录节点存在（归档里可能没记录目录项）
            for part in parts[:-1]:
                prefix = part if not prefix else prefix + '/' + part
                node = self._nodes.get(prefix)
                if node is None:
                    node = self._mk_node(parent, part, {'name': prefix, 'is_dir': True,
                                                        'size': 0, 'compressed': None,
                                                        'mtime': None, 'crc': None,
                                                        'method': None,
                                                        'encrypted': False})
                    self._nodes[prefix] = node
                parent = node
            self._mk_node(parent, parts[-1], e)
            return True

        def _mk_node(self, parent, text, e):
            node = QTreeWidgetItem([text,
                                    '' if e['is_dir'] else fmt_size(e['size']),
                                    '' if e['compressed'] is None else fmt_size(e['compressed']),
                                    fmt_time(e.get('mtime')),
                                    'D' if e['is_dir'] else '.',
                                    ('%08X' % e['crc']) if e.get('crc') is not None else '',
                                    e.get('method') or ''])
            node.setData(0, Qt.UserRole, e['name'])
            if e.get('encrypted'):
                node.setText(6, (node.text(6) + ' [加密]').strip())
            if parent is None:
                self.tree.addTopLevelItem(node)
            else:
                parent.addChild(node)
            return node

        def _on_double_click(self, item, col):
            e_name = item.data(0, Qt.UserRole)
            entry = next((e for e in self.entries if e['name'] == e_name), None)
            if entry and not entry['is_dir']:
                # 双击文件：提取到程序临时目录并用系统默认程序打开
                import tempfile
                outdir = tempfile.mkdtemp(prefix='arh2_view_',
                                          dir=app_temp_dir())
                def job(prog):
                    extract_archive(self.archive, outdir, progress=prog,
                                              password=self.password,
                                              members=[entry['name']])
                def start_preview():
                    self.window.start_job(
                        job, done_msg='已提取: %s' % entry['name'],
                        buttons=self._action_buttons(),
                        on_ok=lambda _r: self._view_file(outdir, entry['name']),
                        on_fail=lambda tb: self._retry_after_password(
                            tb, start_preview, '预览失败'))
                start_preview()

        def _view_file(self, outdir, name):
            target = os.path.join(outdir, *name.split('/'))
            if sys.platform == 'win32':
                os.startfile(target)  # noqa
            elif sys.platform == 'darwin':
                import subprocess
                subprocess.Popen(['open', target])
            else:
                import subprocess
                subprocess.Popen(['xdg-open', target])

        # ---- 选中条目 ----
        def _selected_members(self):
            """返回选中的顶层条目名；未选中时返回 None（表示全部）。"""
            items = self.tree.selectedItems()
            if not items:
                return None
            return [it.data(0, Qt.UserRole) for it in items]

        # ---- 操作 ----
        def _archive_base_name(self):
            """压缩包基名（不含扩展名；分卷先去掉末尾 .NNN），
            用作"解压到…/压缩包名/"的子目录名。"""
            base = os.path.basename(str(self.archive))
            if len(base) > 4 and base[-4] == '.' and base[-3:].isdigit():
                base = base[:-4]
            base = os.path.splitext(base)[0]
            return base or 'archive'

        def extract(self, sub_dir=False):
            if not self.archive:
                return
            members = self._selected_members()
            outdir = QFileDialog.getExistingDirectory(self, '选择解压目录')
            if not outdir:
                return
            target = os.path.join(outdir, self._archive_base_name()) \
                if sub_dir else outdir
            label = '选中条目' if members else '全部内容'
            def start_extract():
                self.window.start_job(
                    lambda prog: extract_archive(
                        self.archive, target, progress=prog,
                        password=self.password, members=members),
                    done_msg='已解压%s到: %s' % (label, target),
                    buttons=self._action_buttons(),
                    on_ok=lambda _r: self._cleanup_temp_cache(),
                    on_fail=lambda tb: self._retry_after_password(
                        tb, start_extract, '解压失败'))
            start_extract()

        def _cleanup_temp_cache(self):
            """解压结束后自动清除程序临时目录中的缓存。"""
            try:
                clear_app_temp_cache()
                self.window.append_log('已清除临时缓存 ✔')
            except Exception as e:
                self.window.append_log('清除临时缓存失败: %s' % e)

        def test(self):
            if not self.archive:
                return
            def start_test():
                self.window.start_job(
                    lambda prog: test_archive(self.archive, progress=prog,
                                                        password=self.password),
                    done_msg='归档完好 ✔', buttons=self._action_buttons(),
                    on_fail=lambda tb: self._retry_after_password(
                        tb, start_test, '测试失败'))
            start_test()

        def info(self):
            if not self.archive:
                return
            try:
                info = info_archive(self.archive)
            except Exception as exc:
                return QMessageBox.critical(self, '错误', str(exc))
            codec_label = 'Cauchy-MDS'
            text = (
                '文件:     %s\n格式:     ARH2 v%s\n归档大小: %s\n载荷大小: %s%s\n'
                '压缩:     %s\n载荷加密: %s\n中心目录: %s\n头保护:   Reed-Solomon\n'
                '纠删码:   %s\n恢复数据: %d 个校验块（%.1f%%）\n分块:     %d 个数据块 × %s' % (
                    self.archive, info['version'], fmt_size(info['size']),
                    fmt_size(info['payload_size']),
                    '' if info['compression'] == 'zstd' else '（未压缩）',
                    ('zstd 级别 %s' % info['zstd_level']) if info['compression'] == 'zstd' else '仅存储',
                    info.get('crypto_kdf') or ('是 (AES-256-GCM)' if info['encrypted'] else '否'),
                    '已加密' if info['cd_encrypted'] else '未加密', codec_label,
                    info['num_parity'],
                    100.0 * info['num_parity'] / max(info['num_blocks'], 1),
                    info['num_blocks'], fmt_size(info['block_size'])))
            QMessageBox.information(self, 'ARH2 归档信息', text)

        def _action_buttons(self):
            return (self.btn_open, self.btn_extract, self.btn_extract_sub,
                    self.btn_test, self.btn_info)



    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle('MienArch ARH2 Compressor %s' % __version__)
            self.resize(900, 680)
            self.worker = None
            icon = _load_app_icon()
            if icon is not None:
                self.setWindowIcon(icon)

            central = QWidget()
            layout = QVBoxLayout(central)
            self.setCentralWidget(central)
            self.tabs = QTabWidget()
            self.open_tab = OpenTab(self)
            self.create_tab = CreateTab(self)
            self.tabs.addTab(self.create_tab, '添加压缩包')
            self.tabs.addTab(self.open_tab, '打开压缩包')
            layout.addWidget(self.tabs)

            self.bar = QProgressBar()
            layout.addWidget(self.bar)
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            self.log.setMaximumHeight(120)
            layout.addWidget(self.log)

            copyright_label = QLabel('Copyright MienArch 2026. ')
            copyright_label.setStyleSheet('color: #666;')
            copyright_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            layout.addWidget(copyright_label)

        def start_job(self, job, done_msg='完成', buttons=(), on_ok=None, on_fail=None):
            if self.worker is not None and self.worker.isRunning():
                QMessageBox.information(self, '任务进行中', '请等待当前任务完成后再执行新操作。')
                return
            self.bar.setValue(0)
            self.worker = Worker(job, self)
            self.worker.progressed.connect(self._on_progress)
            self.worker.succeeded.connect(
                lambda result: self._on_ok(done_msg, buttons, on_ok, result))
            self.worker.failed.connect(
                lambda tb: self._on_fail(tb, buttons, on_fail))
            self.worker.finished.connect(lambda: self._set_buttons(buttons, True))
            self._set_buttons(buttons, False)
            self.worker.start()

        def _set_buttons(self, buttons, enabled):
            for button in buttons:
                button.setEnabled(enabled)

        def _on_ok(self, done_msg, buttons, on_ok, result):
            if done_msg:
                self.append_log(done_msg + ' ✔')
            if on_ok:
                on_ok(result)

        def _on_fail(self, tb, buttons, on_fail):
            if on_fail:
                on_fail(tb)
            else:
                self.show_error(tb)

        def show_error(self, tb, title='错误'):
            self.append_log(tb)
            QMessageBox.critical(
                self, title, tb.strip().splitlines()[-1] if tb.strip() else '未知错误')

        def _on_progress(self, msg, pct):
            self.bar.setValue(pct)
            self.append_log('%3d%%  %s' % (pct, msg))

        def append_log(self, msg):
            self.log.append(msg)


    def run_gui():
        app = QApplication(sys.argv)
        app.setApplicationName('ARH2')
        app.setOrganizationName('MienArch')
        _apply_windows_taskbar_icon()
        icon = _load_app_icon()
        if icon is not None:
            app.setWindowIcon(icon)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())

else:
    def run_gui():
        raise ImportError('未安装 PySide6，无法启动图形界面：pip install PySide6')


if __name__ == '__main__':
    run_gui()
