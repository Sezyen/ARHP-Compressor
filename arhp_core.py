"""ARHP Core — 压缩归档核心库（v1.0.2.2）。

Copyright (C) MienArch 2026.
面包图书馆 2026. 版权所有
本项目基于 GPL-3.0-or-later 许可证发布，详见 LICENSE.txt。


"""

__version__ = '1.0.2.2'
__license__ = 'GPL-3.0-or-later'

import argparse
import base64
import getpass
import json
import os
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import zlib



def app_dir():
    """程序所在目录：打包成 exe 后是 exe 所在目录，否则是源文件所在目录。"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def find_resource(name):
    
    candidates = [os.path.join(app_dir(), name)]
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidates.append(os.path.join(meipass, name))
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None



def app_temp_dir():
    
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA') or \
            os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
    else:
        base = os.environ.get('XDG_CACHE_HOME') or \
            os.path.join(os.path.expanduser('~'), '.cache')
    d = os.path.join(base, 'MienArch', 'ARHP')
    os.makedirs(d, exist_ok=True)
    return d


def clear_app_temp_cache():
   
    d = app_temp_dir()
    try:
        names = os.listdir(d)
    except OSError:
        return
    for name in names:
        p = os.path.join(d, name)
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass



__all__ = ['ArchiveError', 'create_archive', 'extract_archive', 'test_archive',
           'open_archive', 'info_archive', 'list_archive',
           'detect_format', 'SUPPORTED_FORMATS', 'clear_app_temp_cache']


class ReedSolomonError(Exception):
    pass


def xor_bytes(a, b):
    
    if len(a) != len(b):
        raise ReedSolomonError('异或长度不一致: %d != %d' % (len(a), len(b)))
    return (int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little')).to_bytes(len(a), 'little')


class ReedSolomon:
    

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

    def mul(self, a, b):
        if a == 0 or b == 0:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def inv(self, a):
        if a == 0:
            raise ReedSolomonError('GF 除零')
        return self.exp[255 - self.log[a]]

    def table(self, c):
        
        t = self._tables.get(c)
        if t is None:
            t = bytes(self.mul(c, b) for b in range(256))
            self._tables[c] = t
        return t

    def coeff(self, parity_idx, data_idx):
        return self.exp[((parity_idx + 1) * data_idx) % 255]

    def encode(self, data_blocks, k):
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

    def recover(self, data_blocks, parity_blocks, missing):
        
        missing = list(missing)
        if not missing:
            return {}
        rows = [(j, p) for j, p in enumerate(parity_blocks) if p is not None]
        if len(missing) > len(rows):
            raise ReedSolomonError(
                '损坏 %d 块，超出可恢复上限 %d 块' % (len(missing), len(rows)))
        rows = rows[:len(missing)]
        size = len(rows[0][1])
        A = [[self.coeff(j, i) for i in missing] for j, _ in rows]
        B = []
        for j, p in rows:
            rhs = bytearray(p)
            for i, blk in enumerate(data_blocks):
                if blk is None:
                    continue
                if len(blk) != size:
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



MIN_LEVEL = -7
MAX_LEVEL = 22
DEFAULT_LEVEL = 9
STORE_LEVEL = 0


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




KDF_ITERATIONS = 600_000
CHUNK_SIZE = 4 * 1024 * 1024
_SALT_LEN = 16
_NONCE_PREFIX_LEN = 4
_NONCE_LEN = 12


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


def _nonce(prefix, counter):
    return prefix + struct.pack('>Q', counter)


def encrypt_file(src_path, dst_path, password, chunk_size=CHUNK_SIZE,
                 progress=None, total=None):
    """加密 src_path → dst_path，返回可写入 JSON 头的 KDF 参数字典。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(_SALT_LEN)
    prefix = os.urandom(_NONCE_PREFIX_LEN)
    aes = AESGCM(derive_key(password, salt))
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
    return {
        'algo': 'AES-256-GCM',
        'kdf': 'PBKDF2-HMAC-SHA256',
        'salt': base64.b64encode(salt).decode('ascii'),
        'iterations': KDF_ITERATIONS,
        'nonce_prefix': base64.b64encode(prefix).decode('ascii'),
        'chunk_size': chunk_size,
        'num_chunks': counter,
    }


def decrypt_file(src_path, dst_path, kdf_info, password,
                 progress=None, total=None):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        salt = base64.b64decode(kdf_info['salt'])
        prefix = base64.b64decode(kdf_info['nonce_prefix'])
        chunk_size = int(kdf_info.get('chunk_size', CHUNK_SIZE))
        iterations = int(kdf_info.get('iterations', KDF_ITERATIONS))
        if (len(salt) != _SALT_LEN or len(prefix) != _NONCE_PREFIX_LEN
                or not 1 <= chunk_size <= MAX_CRYPTO_CHUNK_SIZE
                or not 1 <= iterations <= MAX_KDF_ITERATIONS):
            raise ValueError
    except Exception:
        raise CryptoError('归档头中加密参数损坏')
    try:
        key = derive_key(password, salt, iterations)
    except Exception:
        raise CryptoError('归档头中加密参数损坏')
    aes = AESGCM(key)
    src_size = os.path.getsize(src_path)
    n_chunks = -(-src_size // (chunk_size + 16)) if src_size else 0
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




MAGIC = b'ARHP\x00\x01'
MAX_SHARDS = 255
MAX_HEADER = 64 * 1024 * 1024
MAX_BLOCK_SIZE = 256 * 1024 * 1024
MAX_CRYPTO_CHUNK_SIZE = 256 * 1024 * 1024
MAX_KDF_ITERATIONS = 10_000_000

_WIN_ABS = re.compile(r'^[a-zA-Z]:[\\/]')


def _crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


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
        return False


def _check_paths(paths):
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise ArchiveError('以下输入路径不存在: %s' % ', '.join(missing))
    paths = [os.path.normpath(p) for p in paths]
    keys = [_path_key(p) for p in paths]
    if len(set(keys)) != len(keys):
        raise ArchiveError('输入路径有重复')
    for i, p in enumerate(paths):
        if not os.path.isdir(p):
            continue
        for j, q in enumerate(paths):
            if i != j and _path_contains(p, q):
                raise ArchiveError('输入路径存在包含关系: %r 已包含 %r' % (p, q))
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



_VOL_RE = re.compile(r'^(.*)\.(\d{3})$')


def split_volumes(archive_path, volume_size, progress=None):
    """把已生成的单个归档拆分为 name.ext.001 / .002 / ... 分卷。

    volume_size 为整数字节数；归档不超过该大小时不拆分并返回 0，
    否则删除原文件、保留分卷并返回分卷数。
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
    with open(archive_path, 'rb') as fin:
        while True:
            chunk = fin.read(volume_size)
            if not chunk:
                break
            idx += 1
            vol = '%s.%03d' % (archive_path, idx)
            with open(vol, 'wb') as f:
                f.write(chunk)
            done += len(chunk)
            _rep(progress, '写入分卷 %d/%d（%s）' % (idx, count, vol),
                 int(95 * done / total))
    os.unlink(archive_path)
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
        return None
    if not os.path.isfile(base + '.001'):
        return None
    vols = []
    i = 1
    while os.path.isfile('%s.%03d' % (base, i)):
        vols.append('%s.%03d' % (base, i))
        i += 1
    return vols


class _ArchiveInput:
   
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



def create_archive(paths, out_path, fmt=None, level=9, redundancy=3,
                   block_size=1 << 20, password=None,
                   volume_size=None, progress=None):
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
                              password=password,
                              progress=progress)
    else:
        raise ArchiveError('不支持的归档格式: %s（支持 arhp/zip/7z）' % fmt)
    if volume_size:
        split_volumes(out_path, volume_size, progress=progress)
    return result


def _create_arhp(paths, out_path, level=9, redundancy=3, block_size=1 << 20,
                 password=None, progress=None):
    """创建 .arhp 归档。"""
    if not paths:
        raise ArchiveError('没有输入文件')
    paths = _check_paths(paths)
    _check_output_location(paths, out_path)
    redundancy = min(max(int(redundancy), 0), 50)
    block_size = max(int(block_size), 4096)
    level = int(level)
    if not 0 <= level <= 22:
        raise ArchiveError('压缩级别必须是 0-22 的整数')
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
        if encrypted:
            _rep(progress, 'AES-256-GCM 加密中...', 15)
            enc = os.path.join(tmpdir, 'payload.enc')
            kdf_info = _crypto_encrypt(comp, enc, password, progress)
            os.replace(enc, comp)
        else:
            kdf_info = None

        payload_size = os.path.getsize(comp)
        method = 'rs'
        n, k, bs = _layout(payload_size, redundancy, block_size)

        hdr = {
            'version': 2,
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
                    c = rs.coeff(j, i)
                    if c:
                        parity[j] = bytearray(xor_bytes(parity[j], padded.translate(rs.table(c))))
                written += real
                _rep(progress, '处理分块 %d/%d' % (i + 1, n),
                     25 + int(60 * written / max(payload_size, 1)))
        for j in range(k):
            hdr['parity_crc'].append(_crc(bytes(parity[j])))

        _rep(progress, '写入归档...', 88)
        with open(out_path, 'wb') as out, open(blocks_tmp, 'rb') as fin:
            out.write(MAGIC)
            hj = json.dumps(hdr, separators=(',', ':')).encode('utf-8')
            out.write(struct.pack('>Q', len(hj)))
            out.write(hj)
            shutil.copyfileobj(fin, out, 1 << 20)
            for j in range(k):
                out.write(bytes(parity[j]))

        _rep(progress, '完成', 100)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _crypto_encrypt(src, dst, password, progress):
    total = os.path.getsize(src)
    return encrypt_file(src, dst, password,
                        progress=lambda d, t: _rep(progress, 'AES-256-GCM 加密中...',
                                                   15 + 8 * d // max(t, 1)),
                        total=total)



def _create_zip(paths, out_path, level=9, password=None, progress=None):
  
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
                zf.writestr(arc.replace(os.sep, '/') + '/', b'')
    _rep(progress, '完成，共 %d 个文件' % count, 100)



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
    if hdr.get('encrypted') and not isinstance(hdr.get('crypto'), dict):
        raise ArchiveError('加密归档缺少加密参数')

    hdr['block_size'] = block_size
    hdr['num_blocks'] = num_blocks
    hdr['num_parity'] = num_parity
    hdr['payload_size'] = payload_size
    hdr['block_len'] = parsed_len
    hdr['block_crc'] = parsed_crc
    hdr['parity_crc'] = parsed_parity


def open_archive(path):
  
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
        try:
            hdr = json.loads(hj.decode('utf-8'))
        except Exception:
            raise ArchiveError('归档头损坏（JSON 解析失败）')
        _validate_header(hdr)
        data_offset = f.tell()
        f.seek(0, os.SEEK_END)
        if hdr['payload_size'] > f.tell() - data_offset:
            raise ArchiveError('归档数据区被截断')
        hdr['data_offset'] = data_offset
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
        if pct != self._last_pct:
            self._last_pct = pct
            self.cb(pct)
        return b


def _assemble_payload(data, hdr, tmpdir, password, progress):
  
    fd, payload = tempfile.mkstemp(prefix='.arhp_payload_', dir=app_temp_dir())
    with os.fdopen(fd, 'wb') as f:
        for i, b in enumerate(data):
            if b is None:
                raise ArchiveError('内部错误: 块 %d 未恢复' % i)
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
    if members is None:
        return True
    if name in members:
        return True
    return any(name.startswith(d + '/') for d in members)


def _restore(data, hdr, outdir, progress, write, password=None, members=None):
   
    members = _norm_members(members)
    if write:
        os.makedirs(outdir, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix='.arhp_restore_', dir=app_temp_dir())
    payload_path = None
    try:
        payload_path = _assemble_payload(data, hdr, tmpdir, password, progress)
        with open(payload_path, 'rb') as pf:
            counter = _CountingReader(pf, hdr['payload_size'],
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
        if payload_path:
            try:
                os.unlink(payload_path)
            except OSError:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)


class _NullCtx:

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        return self.f

    def __exit__(self, *exc):
        return False


def _extract_tar(tar, outdir, progress, write, members=None):
    count = 0
    dirs = []
    for m in tar:
        name = str(m.name).replace('\\', '/').lstrip('./').rstrip('/')
        if not _member_match(name, members):
            continue
        target = _safe_target(outdir, m.name)
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
                    inside = False
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
                with src, open(target, 'wb') as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                os.chmod(target, m.mode & 0o7777)
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
        for d, mt in reversed(dirs):
            try:
                os.utime(d, (mt, mt))
            except OSError:
                pass
    return count


def _repair(path, hdr, progress):
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
  
    with _ArchiveInput(path, progress) as real_path:
        return _extract_archive(real_path, outdir, progress=progress,
                                password=password, members=members)


def _extract_archive(path, outdir='.', progress=None, password=None,
                     members=None):
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
    data, _par, missing = _repair(path, hdr, progress)
    if missing:
        raise ArchiveError('%d 个数据块损坏且无法恢复' % len(missing))
    count = _restore(data, hdr, outdir, progress, write=True,
                     password=password, members=members)
    _rep(progress, '完成，共 %d 个文件' % count, 100)


def test_archive(path, progress=None, password=None):
  
    with _ArchiveInput(path, progress) as real_path:
        return _test_archive(real_path, progress=progress, password=password)


def _test_archive(path, progress=None, password=None):
    """test_archive 的实现（path 已是真实单文件路径）。"""
    fmt = detect_format(path)
    if fmt == 'zip':
        return _test_zip(path, progress=progress, password=password)
    if fmt == '7z':
        return _test_7z(path, progress=progress, password=password)
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    data, _par, missing = _repair(path, hdr, progress)
    if missing:
        raise ArchiveError('%d 个数据块损坏且无法恢复' % len(missing))
    count = _restore(data, hdr, '.', progress, write=False, password=password)
    _rep(progress, '归档完好，共 %d 个文件' % count, 100)



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
            except zipfile.BadZipFile:
                raise ArchiveError('CRC 校验失败: %s' % info.filename)
            count += 1
            _rep(progress, '已测试 %d 个文件' % count, int(95 * count / total))
    _rep(progress, '归档完好，共 %d 个文件' % count, 100)



def _check_7z_password(zf, password):
    try:
        if zf.needs_password() and not password:
            raise ArchiveError('该 7z 归档已加密，需要提供密码（-p/--password）')
    except AttributeError:
        pass


def _is_7z_bad_header_error(exc):
    try:
        import py7zr
        cls = getattr(py7zr, 'Bad7zFile', None)
        if cls is None:
            cls = getattr(getattr(py7zr, 'exceptions', py7zr), 'Bad7zFile', None)
        return isinstance(cls, type) and isinstance(exc, cls)
    except Exception:
        return False


def _is_7z_password_or_header_error(exc, password):
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
    try:
        with py7zr.SevenZipFile(path, 'r', password=password or None) as zf:
            _check_7z_password(zf, password)
            if members:
                zf.extract(path=outdir, targets=sorted(members), recursive=True)
            else:
                zf.extractall(path=outdir)
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
    _rep(progress, '完成', 100)


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
    return {
        'path': path,
        'size': size,
        'format': 'arhp',
        'version': hdr.get('version'),
        'method': hdr.get('method'),
        'compression': hdr.get('compression', 'zstd'),
        'zstd_level': hdr.get('zstd_level'),
        'encrypted': hdr.get('encrypted', False),
        'block_size': hdr.get('block_size'),
        'num_blocks': hdr.get('num_blocks'),
        'num_parity': hdr.get('num_parity'),
        'payload_size': hdr.get('payload_size'),
    }


def list_archive(path, progress=None, password=None):
   
    with _ArchiveInput(path, progress) as real_path:
        return _list_archive(real_path, progress=progress, password=password)


def _list_archive(path, progress=None, password=None):
    """list_archive 的实现（path 已是真实单文件路径）。"""
    fmt = detect_format(path)
    if fmt == 'zip':
        return _list_zip(path)
    if fmt == '7z':
        return _list_7z(path, password=password)
    return _list_arhp(path, progress=progress, password=password)


def _list_arhp(path, progress=None, password=None):
    """列出 .arhp 内容：恢复分块 → 组装载荷 → 流式读 tar 头信息。"""
    hdr = open_archive(path)
    _rep(progress, '读取归档...', 5)
    data, _par, missing = _repair(path, hdr, progress)
    if missing:
        raise ArchiveError('%d 个数据块损坏且无法恢复' % len(missing))
    method = 'zstd 级别 %s' % hdr['zstd_level'] \
        if hdr.get('compression', 'zstd') == 'zstd' else 'store'
    encrypted = bool(hdr.get('encrypted'))
    entries = []
    tmpdir = tempfile.mkdtemp(prefix='.arhp_list_', dir=app_temp_dir())
    payload_path = None
    try:
        _rep(progress, '列出归档内容...', 40)
        payload_path = _assemble_payload(data, hdr, tmpdir, password, progress)
        with open(payload_path, 'rb') as pf:
            counter = _CountingReader(pf, hdr['payload_size'],
                                      lambda p: _rep(progress, '列出归档内容...',
                                                     40 + p * 55 // 100))
            if hdr.get('compression', 'zstd') == 'store':
                src_ctx = _NullCtx(counter)
            else:
                src_ctx = open_reader(counter)
            with src_ctx as zr, tarfile.open(fileobj=zr, mode='r|') as tar:
                for m in tar:
                    if not (m.isdir() or m.isreg() or m.issym()):
                        continue
                    name = str(m.name).replace('\\', '/').lstrip('./')
                    entries.append({
                        'name': name.rstrip('/') if m.isdir() else name,
                        'size': 0 if m.isdir() else m.size,
                        'compressed': None,
                        'mtime': float(m.mtime) if m.mtime else None,
                        'is_dir': m.isdir(),
                        'crc': None,
                        'method': method,
                        'encrypted': encrypted,
                    })
    finally:
        if payload_path:
            try:
                os.unlink(payload_path)
            except OSError:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)
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





def _parse_size(s):
    s = str(s).strip().upper()
    mult = 1
    for suf, m in (('K', 1 << 10), ('M', 1 << 20), ('G', 1 << 30)):
        if s.endswith(suf):
            mult = m
            s = s[:-1]
            break
    return int(float(s) * mult)


def _progress(msg, pct):
    out = sys.stdout
    if out is None:
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
    c.add_argument('-p', '--password', default=None,
                   help='加密密码（.arhp/.7z；也可用环境变量 ARHP_PASSWORD）')
    c.add_argument('--encrypt', action='store_true', help='交互输入加密密码')

    x = sub.add_parser('extract', aliases=['x'], help='解压归档')
    x.add_argument('archive')
    x.add_argument('-o', '--output', default='.', help='输出目录')
    x.add_argument('-p', '--password', default=None, help='解密密码')
    x.add_argument('--only', nargs='+', default=None, metavar='NAME',
                   help='只解压指定条目（文件或目录子树）')

    t = sub.add_parser('test', aliases=['t'], help='测试归档完整性')
    t.add_argument('archive')
    t.add_argument('-p', '--password', default=None, help='解密密码')

    i = sub.add_parser('info', aliases=['i'], help='查看归档信息')
    i.add_argument('archive')

    l = sub.add_parser('list', aliases=['l', 'ls'], help='列出归档内容（预览）')
    l.add_argument('archive')
    l.add_argument('-p', '--password', default=None, help='解密密码')

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
            create_archive(args.files, args.output, fmt=output_fmt, level=args.level,
                           redundancy=args.redundancy,
                           block_size=_parse_size(args.block_size),
                           password=password,
                           volume_size=_parse_size(args.volumes) if args.volumes else None,
                           progress=_progress)
            print('\n已创建: %s' % args.output)
            vols = find_volumes(args.output)
            if vols:
                print('已拆分为 %d 个分卷: %s.001 ... .%03d'
                      % (len(vols), args.output, len(vols)))
        elif cmd in ('extract', 'x'):
            extract_archive(args.archive, args.output, progress=_progress,
                            password=_get_password(args), members=args.only)
            print('\n已解压到: %s' % args.output)
        elif cmd in ('test', 't'):
            test_archive(args.archive, progress=_progress,
                         password=_get_password(args))
            print()
        elif cmd in ('list', 'l', 'ls'):
            entries = list_archive(args.archive, progress=_progress,
                                   password=_get_password(args))
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
            else:
                print('包含:        %d 个文件, %d 个目录' % (info.get('num_files', 0),
                                                          info.get('num_dirs', 0)))
                print('解压后大小:  %s' % _fmt_size(info.get('unpacked_size')))
            print('加密:        %s' % ('是' if info['encrypted'] else '否'))
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
