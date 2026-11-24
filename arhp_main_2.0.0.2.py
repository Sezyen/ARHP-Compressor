#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARHP 2.0.0.2 主程序入口 + 图形界面。

Copyright (C) MienArch | 2026
面包图书馆 2026. 版权所有
本项目基于 GPL-3.0-or-later 许可证发布，详见 LICENSE.txt。

Python版本要求 3.8+
脚本依赖需求：pyzstd cryptography PySide6 argon2-cffi py7zr
依赖安装命令： pip install pyzstd cryptography PySide6 argon2-cffi py7zr

- 双击运行（无参数）       → 启动图形界面
- 命令行带参数             → 无头模式执行对应命令（create/extract/test/list/info）
- 命令行无参数 + --headless → 打印帮助（纯服务器/脚本场景）

v2.0.0.2 改动（bugfix + 安全加固，全部在 arhp_core）：
- 修复 zip 解压超过 200 个文件必崩的 NameError（进度统计引用了不存在的
  变量 infos）；
- zip 解压改用与 tar 一致的原子写入：中断不留半文件、不直接截断旧目标；
- zip / 7z 创建统一原子写入：崩溃不留损坏归档、不提前截断旧文件；
- 7z 解压新增成员名预检（../、绝对路径、盘符、重名、文件/目录冲突），
  不再把路径安全完全交给第三方库；
- zip 创建保留符号链接（与 arh2/arhp 策略一致），不再静默跟随链接；
- 内存上限说明措辞修正（工作集受控，进程总内存另含对象/元数据开销）；
- 任务栏图标分组标识（AppUserModelID）更新为 2.0.0.2。

v2.0.0.1 改动（bugfix）：
- “添加压缩包”页压缩前若目标文件已存在，先弹确认框再覆盖（此前与右键
  菜单 /add 对话框行为不一致：右键路径有确认，GUI 主界面会静默原子
  替换已有归档）；
- 右键菜单 /add 对话框切换到 zip 格式后自动清空已填密码（残留密码会
  触发“zip 不支持加密”误报错）；
- 核心库修复 zip 解压不拒绝重复成员名的问题（与 tar 路径对齐）；
- 任务栏图标分组标识（AppUserModelID）更新为 2.0.0.1。

v2.0.0.0 改动（arh2 合并版）：
- 基于 arh2 1.0.0.2 的高优化核心重写：分块校验/Reed-Solomon 编解码全面
  流式化，峰值内存由“内存限制”设置控制（16M-1024M 档位，默认 128M；
  CLI 对应 -m/--memory）；
- 一个程序支持四种归档格式：.arh2（Cauchy-MDS RS + 受保护中心目录，
  列目录快路径）、.arhp（Vandermonde RS，v3 头保护 + 加密头 HMAC）、
  .zip（deflate，兼容所有压缩软件）、.7z（LZMA2，可选 AES-256 加密）；
- 与旧版完全双向兼容：旧 arhp 1.1.0.2 / arh2 1.0.0.2 创建的归档可直接
  打开；本版创建的 .arhp 仍可由 arhp 1.1.0.2 读取（Vandermonde + 扁平
  尾注 + HMAC），创建的 .arh2 仍可由 arh2 1.0.0.2 读取（Cauchy-MDS，
  无 header_mac）；
- 新建归档默认格式由 .arhp 改为 .arh2（更新、更快、中心目录受保护）；
- 右键菜单插件升级为 arhp_plugin.py：级联菜单同时服务 .arh2 / .arhp /
  .zip / .7z，文件关联注册 MienArch.ARH2 与 MienArch.ARHP 两个 ProgID，
  并自动清理旧版 arh2 插件的菜单键；
- 加密归档头 HMAC-SHA256 防篡改认证（.arhp；载荷逐块 GCM 认证）；
  注意 CRC32+RS 恢复数据仅防随机损坏、不防恶意篡改；
- zip 格式不支持写入加密（标准库限制），传入密码会明确报错并建议改用
  .arh2/.arhp/.7z；
- 任务栏图标分组标识（AppUserModelID）更新为 2.0.0.0。

自动加载同目录下的 arhp_core.py 核心库，无需安装；
同目录下的 arhp_plugin.py 存在时启用右键菜单集成（缺失不影响其他功能）；
图形界面会读取同目录的 ARHP.png（或 arhp.png）作为窗口与任务栏图标
（打包为 onedir exe 时把 ARHP.png 放在 exe 旁即可）。

等价用法：
    python arhp_main_2.0.0.2.py gui          # 强制启动图形界面
    pythonw arhp_main_2.0.0.2.py             # Windows 双击/无控制台启动 GUI
"""

import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import arhp_core
except ImportError as e:
    sys.stderr.write('无法加载 arhp_core 核心库: %s\n' % e)
    sys.stderr.write('请确认 arhp_core.py 与本程序在同一目录下。\n')
    sys.exit(1)

# 右键菜单插件（可选）：同目录的 arhp_plugin.py，缺失时全部功能不受影响。
try:
    import arhp_plugin
except ImportError:
    arhp_plugin = None

# =======================================================================
# 图形界面 (PySide6)   —— 由 arhp_main 1.1.0.2 / arh2 主界面合并而来
# =======================================================================

try:
    from PySide6.QtCore import Qt, QThread, Signal
    from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox,
                                   QComboBox, QFileDialog, QHBoxLayout,
                                   QInputDialog, QLabel, QLineEdit, QListWidget,
                                   QMainWindow, QMessageBox, QProgressBar,
                                   QPushButton, QSlider, QTabWidget, QTextEdit,
                                   QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                                   QWidget)
    from PySide6.QtGui import QIcon
except ImportError:
    _GUI_AVAILABLE = False
else:
    _GUI_AVAILABLE = True

ICON_NAMES = ('ARHP.png', 'arhp.png')  # 优先大写，兼容旧文件名
_APP_ID = 'ARHP.ArchiveTool.2.0.0.2'  # Windows 任务栏图标分组标识

# .arh2/.arhp 的 Reed-Solomon 纠删码分块大小（不是字典大小），64K–128M 各档
BLOCK_SIZES = ['64K', '128K', '256K', '512K', '1M', '2M', '4M', '8M',
               '16M', '32M', '64M', '128M']
# 格式顺序即下拉框顺序：arh2 为新建默认（最新格式，中心目录受保护）
FORMAT_ORDER = ('arh2', 'arhp', 'zip', '7z')
FORMAT_EXTS = {'arh2': '.arh2', 'arhp': '.arhp', 'zip': '.zip', '7z': '.7z'}

# 分卷大小预设（可手填任意值）
VOLUME_PRESETS = ['不分卷', '32M', '128M', '512M', '1024M', '650M (CD)',
                  '4092M (FAT)', '4480M (DVD)', '8128M (DVD DL)', '23040M (BD)']

# 内存限制档位（压缩/解压归档的峰值内存上限）
MEM_LIMIT_PRESETS = ['16M', '32M', '64M', '128M', '256M', '512M', '1024M']


def default_archive_name(ext='.arh2'):
    """默认输出文件名：Archive-年月日时分秒。"""
    import datetime
    return 'Archive-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S') + ext


def _load_app_icon():
    """加载脚本/exe 所在目录（或 PyInstaller 资源目录）下的 ARHP.png 作为
    窗口左上角与任务栏图标，找不到时尝试兼容名 arhp.png，再找不到返回 None。"""
    if not _GUI_AVAILABLE:
        return None
    for name in ICON_NAMES:
        path = arhp_core.find_resource(name)
        if path:
            icon = QIcon(path)
            if not icon.isNull():
                return icon
    return None


def _apply_windows_taskbar_icon():
    """Windows 下为进程设置显式 AppUserModelID。

    不设置时任务栏会把窗口归到 python/pythonw 组，图标显示为解释器图标；
    设置后任务栏/任务视图按应用 ID 分组，显示窗口自身图标。
    打包为 onedir exe 时 exe 旁放置 ARHP.png 即可作为任务栏图标。
    """
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(_APP_ID)
    except Exception:
        pass


def _exe_path():
    """插件注册右键菜单所需的带引号启动命令前缀。"""
    return '"%s"' % os.path.abspath(sys.argv[0])


if _GUI_AVAILABLE:

    def fmt_size(n):
        return arhp_core._fmt_size(n)

    def fmt_time(ts):
        if not ts:
            return ''
        import datetime
        try:
            return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return ''

    class Worker(QThread):
        progressed = Signal(str, int)
        succeeded = Signal(object)
        failed = Signal(str)

        def __init__(self, job, parent=None):
            super().__init__(parent)
            self._job = job

        def run(self):
            try:
                result = self._job(lambda m, p: self.progressed.emit(m, p))
            except Exception:
                self.failed.emit(traceback.format_exc())
            else:
                self.succeeded.emit(result)

    # ------------------------------------------------------------------
    # 标签页一：添加压缩包
    # ------------------------------------------------------------------

    class CreateTab(QWidget):
        def __init__(self, window):
            super().__init__()
            self.window = window

            lay = QVBoxLayout(self)

            lay.addWidget(QLabel('文件列表（全部打包进一个归档）:'))
            self.list = QListWidget()
            self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
            lay.addWidget(self.list)

            row = QHBoxLayout()
            for text, slot in (('添加文件', self.add_files), ('添加目录', self.add_dir),
                               ('移除选中', self.remove_selected)):
                b = QPushButton(text)
                b.clicked.connect(slot)
                row.addWidget(b)
            lay.addLayout(row)

            # ---- 输出路径 + 归档格式 ----
            row = QHBoxLayout()
            row.addWidget(QLabel('输出:'))
            self.out = QLineEdit(default_archive_name('.arh2'))
            self.out.setPlaceholderText('Archive-年月日时分秒')
            row.addWidget(self.out)
            b = QPushButton('浏览…')
            b.clicked.connect(self.browse)
            row.addWidget(b)
            lay.addLayout(row)

            row = QHBoxLayout()
            row.addWidget(QLabel('归档格式:'))
            self.fmt = QComboBox()
            # 括号内标注该格式实际使用的压缩方法；arh2 为默认（最新格式）
            self.fmt.addItems([
                'arh2（zstd + Cauchy-MDS RS + 中心目录）[推荐]',
                'arhp（zstd + Vandermonde RS）',
                'zip（deflate）', '7z（LZMA2）'])
            self.fmt.currentIndexChanged.connect(self._on_fmt)
            row.addWidget(self.fmt)
            row.addStretch(1)
            lay.addLayout(row)

            # ---- 压缩级别滑块 ----
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

            # ---- 恢复数据（仅 arh2/arhp 可用滑块；zip/7z 显示"不可用"文本框）----
            row = QHBoxLayout()
            row.addWidget(QLabel('恢复数据:'))
            self.red = QSlider(Qt.Horizontal)
            self.red.setRange(0, 50)
            self.red.setValue(3)  # 默认对齐 RAR5 恢复记录的 3%
            self.red.setTickPosition(QSlider.TicksBelow)
            self.red.setTickInterval(5)
            self.red.valueChanged.connect(self._on_red)
            row.addWidget(self.red)
            self.red_label = QLabel()
            row.addWidget(self.red_label)
            self._on_red(3)
            # zip / 7z 不支持恢复数据：不显示滑块，显示禁用文本框
            self.red_na = QLineEdit('恢复数据不可用')
            self.red_na.setEnabled(False)
            row.addWidget(self.red_na)
            lay.addLayout(row)

            # ---- 分块大小（仅 arh2/arhp）+ 加密（arh2/arhp/7z）----
            row = QHBoxLayout()
            row.addWidget(QLabel('分块大小:'))
            self.block = QComboBox()
            self.block.addItems(BLOCK_SIZES)
            self.block.setCurrentText('1M')
            row.addWidget(self.block)
            self.encrypt = QCheckBox('加密')
            self.encrypt.toggled.connect(self._on_encrypt_toggled)
            row.addWidget(self.encrypt)
            # 加密算法（密钥派生方式）：仅 .arh2/.arhp 可选，载荷均为 AES-256-GCM
            self.crypto_algo = QComboBox()
            self.crypto_algo.addItems(['PBKDF2（经典）', 'Argon2id（更强）'])
            self.crypto_algo.setToolTip('.arh2/.arhp 加密密钥派生方式：PBKDF2 为'
                                        '经典方案；Argon2id 为更强大的加密方案')
            row.addWidget(self.crypto_algo)
            # 中心目录加密：仅 .arh2 可用（列目录也需要密码）
            self.cd_encrypt = QCheckBox('加密目录')
            self.cd_encrypt.setToolTip('仅 .arh2：加密中心化目录，列目录预览也需要密码')
            row.addWidget(self.cd_encrypt)
            self.pwd = QLineEdit()
            self.pwd.setPlaceholderText('请输入密码')
            self.pwd.setEchoMode(QLineEdit.Password)
            self.pwd.setEnabled(False)
            row.addWidget(self.pwd)
            row.addStretch(1)
            lay.addLayout(row)

            # ---- 分卷大小（全部格式支持；可手填或选择预设）----
            row = QHBoxLayout()
            row.addWidget(QLabel('分卷大小:'))
            self.vol = QComboBox()
            self.vol.setEditable(True)
            self.vol.addItems(VOLUME_PRESETS)
            self.vol.setCurrentIndex(0)
            self.vol.setToolTip('可手填（如 200M、1G）或选择预设；'
                                '选择"不分卷"输出单个文件')
            row.addWidget(self.vol)
            row.addStretch(1)
            lay.addLayout(row)

            self.hint = QLabel()
            self.hint.setStyleSheet('color: #666;')
            lay.addWidget(self.hint)

            row = QHBoxLayout()
            self.btn_pack = QPushButton('压缩')
            self.btn_pack.clicked.connect(self.pack)
            row.addStretch(1)
            row.addWidget(self.btn_pack)
            lay.addLayout(row)

            self._on_fmt(0)

        # ---- 控件回调 ----
        def _fmt_key(self):
            return FORMAT_ORDER[self.fmt.currentIndex()]

        def _on_fmt(self, idx):
            key = self._fmt_key()
            is_rs = key in ('arh2', 'arhp')   # 带 Reed-Solomon 恢复数据的格式
            is_zip = key == 'zip'
            # 恢复数据：仅 arh2/arhp 显示滑块；zip/7z 换成禁用文本框
            self.red.setVisible(is_rs)
            self.red_label.setVisible(is_rs)
            self.red_na.setVisible(not is_rs)
            # 分块大小是 .arh2/.arhp 纠删码专用参数
            self.block.setEnabled(is_rs)
            # 加密算法（PBKDF2/Argon2id）仅 .arh2/.arhp 可选
            self.crypto_algo.setVisible(is_rs)
            # 中心目录加密仅 .arh2 可选
            self.cd_encrypt.setVisible(key == 'arh2')
            if key != 'arh2' and self.cd_encrypt.isChecked():
                self.cd_encrypt.setChecked(False)
            self.encrypt.setEnabled(not is_zip)
            if is_zip and self.encrypt.isChecked():
                self.encrypt.setChecked(False)
            self.pwd.setEnabled(self.encrypt.isChecked() and not is_zip)
            if is_rs:
                self.level.setRange(0, 22)
                if key == 'arh2':
                    self.hint.setText(
                        '.arh2：zstd 0-22 级 + Cauchy-MDS 恢复数据 + 受保护中心'
                        '目录（列目录快），可选 AES-256-GCM 加密')
                else:
                    self.hint.setText(
                        '.arhp：zstd 0-22 级 + Vandermonde 恢复数据 + 归档头 RS '
                        '保护（v3），加密归档含头 HMAC 认证；兼容 arhp 1.1.0.2')
            elif is_zip:
                self.level.setRange(0, 9)
                self.hint.setText('.zip：标准 deflate 压缩，兼容所有压缩软件'
                                  '（不支持加密/恢复数据）')
            else:
                self.level.setRange(0, 9)
                self.hint.setText('.7z：LZMA2 压缩（0 级为 Copy 仅存储），可选 AES-256 加密')
            if self.level.value() > self.level.maximum():
                self.level.setValue(self.level.maximum())
            self._on_level(self.level.value())
            # 同步输出扩展名
            out = self.out.text().strip()
            if out:
                base, _ = os.path.splitext(out)
                self.out.setText(base + FORMAT_EXTS[key])
            self._on_encrypt_toggled(self.encrypt.isChecked())

        def _on_level(self, v):
            if self._fmt_key() in ('arh2', 'arhp'):
                text = {0: '0 仅存储', 1: '1 最快', 19: '19 超高', 22: '22 最高'}.get(
                    v, '%d' % v if v < 19 else '%d 超高' % v)
            else:
                text = {0: '0 仅存储', 1: '1 最快', 9: '9 最高'}.get(v, str(v))
            self.level_label.setText(text)
            self.level_label.setToolTip('0 = 仅存储不压缩；数值越大压缩率越高、速度越慢')

        def _on_red(self, v):
            self.red_label.setText('%d%%' % v + ('（不生成）' if v == 0 else ''))

        def _on_encrypt_toggled(self, on):
            self.pwd.setEnabled(on and self._fmt_key() != 'zip')
            if not on:
                self.pwd.clear()

        # ---- 列表管理 ----
        def add_files(self):
            files, _ = QFileDialog.getOpenFileNames(self, '选择文件')
            self.list.addItems(files)

        def add_dir(self):
            d = QFileDialog.getExistingDirectory(self, '选择目录')
            if d:
                self.list.addItem(d)

        def remove_selected(self):
            for it in self.list.selectedItems():
                self.list.takeItem(self.list.row(it))

        def browse(self):
            key = self._fmt_key()
            filters = {
                'arh2': 'ARH2 归档 (*.arh2)',
                'arhp': 'ARHP 归档 (*.arhp)',
                'zip': 'Zip 归档 (*.zip)',
                '7z': '7-Zip 归档 (*.7z)',
            }
            p, _ = QFileDialog.getSaveFileName(self, '输出归档',
                                               default_archive_name(FORMAT_EXTS[key]),
                                               filters[key])
            if p:
                if not p.lower().endswith(FORMAT_EXTS[key]):
                    p += FORMAT_EXTS[key]
                self.out.setText(p)

        # ---- 压缩 ----
        def pack(self):
            files = [self.list.item(i).text() for i in range(self.list.count())]
            if not files:
                return QMessageBox.warning(self, '提示', '请先添加文件或目录')
            out = self.out.text().strip()
            if not out:
                return QMessageBox.warning(self, '提示', '请设置输出路径')
            key = self._fmt_key()
            if not out.lower().endswith(FORMAT_EXTS[key]):
                out += FORMAT_EXTS[key]
                self.out.setText(out)
            # 目标已存在时必须确认——底层 create_archive 会直接原子替换，
            # 不确认就可能在用户手滑输错名字时静默覆盖旧归档
            if os.path.exists(out):
                answer = QMessageBox.question(
                    self, '文件已存在',
                    '目标文件已存在，是否覆盖？\n%s' % out,
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if answer != QMessageBox.Yes:
                    return
            password = None
            if self.encrypt.isChecked():
                password = self.pwd.text()
                if not password:
                    return QMessageBox.warning(self, '提示', '请输入加密密码')

            def _parse_size(s):
                s = s.upper()
                mult = 1
                for suf, m in (('K', 1 << 10), ('M', 1 << 20), ('G', 1 << 30)):
                    if s.endswith(suf):
                        mult = m
                        s = s[:-1]
                        break
                return int(float(s) * mult)

            # ---- 分卷大小：可手填或预设，"不分卷"/空 = 单文件 ----
            volume_size = None
            vol_text = self.vol.currentText().strip()
            if vol_text and vol_text != '不分卷':
                vol_num = vol_text.split()[0].split('（')[0].split('(')[0]
                try:
                    volume_size = _parse_size(vol_num)
                except ValueError:
                    return QMessageBox.warning(
                        self, '提示', '分卷大小无效: %s\n请填写如 32M、650M、1G 或选择预设。'
                        % vol_text)
                if volume_size < 1:
                    return QMessageBox.warning(self, '提示', '分卷大小必须为正数')

            done_msg = '已创建: %s' % out
            if volume_size:
                done_msg = '已创建: %s（按 %s 分卷）' % (out, self.vol.currentText().strip())

            crypto_algo = 'argon2id' \
                if (key in ('arh2', 'arhp') and self.crypto_algo.currentIndex() == 1) \
                else 'gcm'
            cd_encrypt = bool(self.cd_encrypt.isChecked()) and key == 'arh2'

            self.window.start_job(
                lambda prog: arhp_core.create_archive(
                    files, out, fmt=key, level=self.level.value(),
                    redundancy=self.red.value(),
                    block_size=_parse_size(self.block.currentText()),
                    password=password, crypto=crypto_algo,
                    cd_encrypt=cd_encrypt,
                    volume_size=volume_size,
                    mem_limit=self.window.memory_limit(),
                    progress=prog),
                done_msg=done_msg, buttons=(self.btn_pack,))

    # ------------------------------------------------------------------
    # 标签页二：打开压缩包（7-Zip Manager 风格内容预览）
    # ------------------------------------------------------------------

    class OpenTab(QWidget):
        COLS = ('名称', '大小', '压缩后大小', '修改时间', '属性', 'CRC', '算法')
        MAX_PW_TRIES = 3  # 加密归档密码错误时的最大重试次数

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
            self.summary = QLabel('尚未打开归档。支持 .arh2 / .arhp / .zip / .7z')
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
                    '所有支持的归档 (*.arh2 *.arhp *.zip *.7z *.001);;'
                    'ARH2 归档 (*.arh2);;ARHP 归档 (*.arhp);;'
                    'Zip 归档 (*.zip);;7-Zip 归档 (*.7z);;分卷 (*.001)')
                if not p:
                    return
                path = p
            self.password = None
            self._tries = 0
            self._do_list(path)

        def _do_list(self, path):
            def job(prog):
                return arhp_core.list_archive(path, progress=prog,
                                              password=self.password,
                                              mem_limit=self.window.memory_limit())
            self.window.start_job(
                job, done_msg='', buttons=self._action_buttons(),
                on_ok=lambda entries: self._on_listed(path, entries),
                on_fail=lambda tb: self._on_list_failed(path, tb))

        def _retry_after_password(self, path, tb):
            """加密归档密码错误（CryptoError 或密码相关报错）时询问密码重试，
            最多 MAX_PW_TRIES 次；其他错误直接上报。返回 True 表示已重试。"""
            crypto_error = getattr(arhp_core, 'CryptoError', None)
            is_crypto = (isinstance(crypto_error, type)
                         and isinstance(tb, crypto_error))
            need_pw = is_crypto or ('密码' in tb or 'password' in tb.lower()
                                    or '加密' in tb)
            if not need_pw or getattr(self, '_tries', 0) >= self.MAX_PW_TRIES:
                return False
            self._tries += 1
            pw, ok = QInputDialog.getText(
                self, '输入密码', '该归档已加密，请输入密码:', QLineEdit.Password)
            if ok:
                self.password = pw or None
                self._do_list(path)
                return True
            return False

        def _on_listed(self, path, entries):
            self.archive = path
            self.entries = entries
            vols = arhp_core.find_volumes(path)
            if vols:
                # 分卷归档：基名去掉末尾 ".NNN"（正则兼容 1000 卷以上的四位卷名）
                m = arhp_core._VOL_RE.match(vols[0])
                base = m.group(1) if m else vols[0]
                fmt = arhp_core.detect_format(base)
                size = sum(os.path.getsize(v) for v in vols)
                path = '%s（%d 个分卷）' % (base, len(vols))
            else:
                fmt = arhp_core.detect_format(path)
                size = os.path.getsize(path)
            n_files = sum(1 for e in entries if not e['is_dir'])
            unpacked = sum(e['size'] for e in entries if not e['is_dir'])
            self.summary.setText(
                '%s    格式: %s    归档大小: %s    包含: %d 个文件 / %d 个目录    '
                '解压后: %s' % (path, fmt, fmt_size(size), n_files,
                                len(entries) - n_files, fmt_size(unpacked)))
            self._fill_tree(entries)
            for b in self._action_buttons():
                b.setEnabled(True)
            self.status.setText('共 %d 个条目' % len(entries))
            self.window.append_log('已打开: %s（%d 个条目）' % (path, len(entries)))

        def _on_list_failed(self, path, tb):
            last = tb.strip().splitlines()[-1] if tb.strip() else ''
            if self._retry_after_password(path, tb):
                return
            self.window.show_error(tb, '打开失败: %s' % last)

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
                self.window.append_log(
                    '提示: %d 个条目的路径包含 ".." 或绝对路径，已跳过显示' % skipped)

        def _add_entry(self, e):
            name = e['name']
            if not name or name.startswith('/') or '..' in name.split('/'):
                return False
            parts = [p for p in name.split('/') if p]
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
                outdir = tempfile.mkdtemp(prefix='arhp_view_',
                                          dir=arhp_core.app_temp_dir())
                def job(prog):
                    arhp_core.extract_archive(self.archive, outdir, progress=prog,
                                              password=self.password,
                                              members=[entry['name']],
                                              mem_limit=self.window.memory_limit())
                self.window.start_job(
                    job, done_msg='已提取: %s' % entry['name'],
                    buttons=self._action_buttons(),
                    on_ok=lambda _r: self._view_file(outdir, entry['name']))

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
            """压缩包基名（不含扩展名；分卷先去掉末尾 .NNN/.1000 卷号，
            用正则兼容四位卷名），用作"解压到…/压缩包名/"的子目录名。"""
            base = os.path.basename(str(self.archive))
            m = arhp_core._VOL_RE.match(base)
            if m:
                base = m.group(1)
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
            self.window.start_job(
                lambda prog: arhp_core.extract_archive(
                    self.archive, target, progress=prog,
                    password=self.password, members=members,
                    mem_limit=self.window.memory_limit()),
                done_msg='已解压%s到: %s' % (label, target),
                buttons=self._action_buttons(),
                on_ok=lambda _r: self._cleanup_temp_cache())

        def _cleanup_temp_cache(self):
            """解压结束后自动清除程序临时目录中的缓存。"""
            try:
                arhp_core.clear_app_temp_cache()
                self.window.append_log('已清除临时缓存 ✔')
            except Exception as e:
                self.window.append_log('清除临时缓存失败: %s' % e)

        def test(self):
            if not self.archive:
                return
            self.window.start_job(
                lambda prog: arhp_core.test_archive(
                    self.archive, progress=prog, password=self.password,
                    mem_limit=self.window.memory_limit()),
                done_msg='归档完好 ✔', buttons=self._action_buttons())

        def info(self):
            if not self.archive:
                return
            try:
                i = arhp_core.info_archive(self.archive)
            except Exception as e:
                return QMessageBox.critical(self, '错误', str(e))
            if i['format'] == 'arh2':
                codec = {'cauchy-v1': 'Cauchy-MDS', 'vandermonde-v1': 'Vandermonde'}.get(
                    i.get('rs_codec'), i.get('rs_codec') or '-')
                text = (
                    '文件:     %s\n格式:     ARH2 v%s（中心化目录 + 头 RS 保护）\n'
                    '归档大小: %s\n载荷大小: %s%s\n压缩:     %s\n'
                    '纠删码:   %s\n加密:     %s\n中心目录: %s\n'
                    '恢复数据: %s, %d 个校验块 (%.1f%%)\n分块:     %d 个数据块 × %s' % (
                        i['path'], i.get('version') or '?',
                        fmt_size(i['size']), fmt_size(i['payload_size']),
                        '' if i['compression'] == 'zstd' else '（未压缩）',
                        ('zstd 级别 %s' % i['zstd_level']) if i['compression'] == 'zstd' else '仅存储',
                        codec,
                        i.get('crypto_kdf') or ('是 (AES-256-GCM)' if i['encrypted'] else '否'),
                        '已加密（列目录需密码）' if i.get('cd_encrypted') else '未加密',
                        i['method'], i['num_parity'],
                        100.0 * i['num_parity'] / max(i['num_blocks'], 1),
                        i['num_blocks'], fmt_size(i['block_size'])))
            elif i['format'] == 'arhp':
                header_prot = ('Reed-Solomon（归档头已纳入保护）'
                               if i.get('header_protected')
                               else '仅载荷（旧格式归档头无冗余）')
                if i.get('header_mac'):
                    header_prot += ' + HMAC-SHA256 防篡改'
                codec = {'cauchy-v1': 'Cauchy-MDS', 'vandermonde-v1': 'Vandermonde'}.get(
                    i.get('rs_codec'), i.get('rs_codec') or '-')
                text = (
                    '文件:     %s\n格式:     ARHP v%s%s\n归档大小: %s\n载荷大小: %s%s\n压缩:     %s\n'
                    '纠删码:   %s\n加密:     %s\n头保护:   %s\n恢复数据: %s, %d 个校验块 (%.1f%%)\n分块:     %d 个数据块 × %s' % (
                        i['path'], i.get('version') or '?',
                        '（旧格式）' if not i.get('header_protected') else '',
                        fmt_size(i['size']), fmt_size(i['payload_size']),
                        '' if i['compression'] == 'zstd' else '（未压缩）',
                        ('zstd 级别 %s' % i['zstd_level']) if i['compression'] == 'zstd' else '仅存储',
                        codec,
                        i.get('crypto_kdf') or ('是 (AES-256-GCM)' if i['encrypted'] else '否'),
                        header_prot,
                        i['method'], i['num_parity'],
                        100.0 * i['num_parity'] / max(i['num_blocks'], 1),
                        i['num_blocks'], fmt_size(i['block_size'])))
            else:
                text = (
                    '文件:       %s\n格式:       %s\n归档大小:   %s\n'
                    '文件/目录:  %d / %d\n解压后大小: %s\n加密:       %s' % (
                        i['path'], i['format'].upper(), fmt_size(i['size']),
                        i.get('num_files', 0), i.get('num_dirs', 0),
                        fmt_size(i.get('unpacked_size')),
                        '是' if i['encrypted'] else '否'))
            QMessageBox.information(self, '归档信息', text)

        def _action_buttons(self):
            return (self.btn_extract, self.btn_extract_sub, self.btn_test,
                    self.btn_info)

    # ------------------------------------------------------------------
    # 主窗口
    # ------------------------------------------------------------------

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle('MienArch ARHP Compressor %s '
                                % arhp_core.__version__)
            self.resize(920, 700)
            self.worker = None

            icon = _load_app_icon()
            if icon is not None:
                self.setWindowIcon(icon)

            central = QWidget()
            lay = QVBoxLayout(central)
            self.setCentralWidget(central)

            # ---- 全局设置行：内存限制 + 右键菜单安装（v2.0.0.0 引入）----
            row = QHBoxLayout()
            row.addWidget(QLabel('内存限制:'))
            self.mem_limit = QComboBox()
            self.mem_limit.addItems(MEM_LIMIT_PRESETS)
            self.mem_limit.setCurrentText('128M')
            self.mem_limit.setToolTip(
                '压缩/解压归档时流式处理工作集的上限（16MB–1024MB，默认 128MB）。\n'
                '分块校验与 Reed-Solomon 恢复数据按块流式处理，工作集不超过此限制；\n'
                '实际进程内存另含 Python 对象、缓冲区与目录元数据开销。')
            row.addWidget(self.mem_limit)
            row.addStretch(1)
            # 右键菜单安装/移除（仅安装了插件的 Windows 环境可用）
            self.btn_install_shell = QPushButton('安装右键菜单')
            self.btn_install_shell.setToolTip('在资源管理器右键菜单注册 ARHP 级联菜单'
                                              '（.arh2/.arhp/.zip/.7z）与文件关联')
            self.btn_install_shell.clicked.connect(self._install_shell)
            self.btn_remove_shell = QPushButton('移除右键菜单')
            self.btn_remove_shell.clicked.connect(self._remove_shell)
            shell_ok = arhp_plugin is not None and sys.platform == 'win32'
            self.btn_install_shell.setEnabled(shell_ok)
            self.btn_remove_shell.setEnabled(shell_ok)
            if arhp_plugin is None:
                tip = '未找到同目录的 arhp_plugin.py，右键菜单集成不可用'
                self.btn_install_shell.setToolTip(tip)
            elif sys.platform != 'win32':
                tip = '右键菜单仅支持 Windows'
                self.btn_install_shell.setToolTip(tip)
                self.btn_remove_shell.setToolTip(tip)
            row.addWidget(self.btn_install_shell)
            row.addWidget(self.btn_remove_shell)
            lay.addLayout(row)

            # 顶部两个标签页：添加压缩包 / 打开压缩包
            self.tabs = QTabWidget()
            self.open_tab = OpenTab(self)
            self.create_tab = CreateTab(self)
            self.tabs.addTab(self.create_tab, '添加压缩包')
            self.tabs.addTab(self.open_tab, '打开压缩包')
            lay.addWidget(self.tabs)

            self.bar = QProgressBar()
            lay.addWidget(self.bar)
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            self.log.setMaximumHeight(120)
            lay.addWidget(self.log)

            # ---- 底栏：版权标识 ----
            copyright_label = QLabel('Copyright MienArch 2026. ')
            copyright_label.setStyleSheet('color: #666;')
            copyright_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            lay.addWidget(copyright_label)

        # ---- 右键菜单安装 / 移除 ----
        def _install_shell(self):
            if arhp_plugin is None:
                return
            ok, msg = arhp_plugin.install(_exe_path())
            (QMessageBox.information if ok else QMessageBox.critical)(
                self, '右键菜单', msg)
            self.append_log(('右键菜单已安装 ✔' if ok else '右键菜单安装失败'))

        def _remove_shell(self):
            if arhp_plugin is None:
                return
            ok, msg = arhp_plugin.uninstall()
            (QMessageBox.information if ok else QMessageBox.critical)(
                self, '右键菜单', msg)
            self.append_log(('右键菜单已移除 ✔' if ok else '右键菜单移除失败'))

        # ---- 任务框架（供两个标签页共用）----
        def memory_limit(self):
            """当前内存限制（字节）；对应 core 的 mem_limit 参数。"""
            return arhp_core._parse_size(self.mem_limit.currentText())

        def start_job(self, job, done_msg='完成', buttons=(), on_ok=None,
                      on_fail=None):
            if self.worker is not None and self.worker.isRunning():
                QMessageBox.information(self, '任务进行中',
                                        '请等待当前任务完成后再执行新操作。')
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
            for b in buttons:
                b.setEnabled(enabled)

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
            QMessageBox.critical(self, title,
                                 tb.strip().splitlines()[-1] if tb.strip() else '未知错误')

        def _on_progress(self, msg, pct):
            self.bar.setValue(pct)
            self.append_log('%3d%%  %s' % (pct, msg))

        def append_log(self, msg):
            self.log.append(msg)

    def run_gui(open_path=None):
        app = QApplication(sys.argv)
        app.setApplicationName('ARHP')
        # 任务栏图标（Windows 依赖 AppUserModelID 分组，见函数注释）
        _apply_windows_taskbar_icon()
        icon = _load_app_icon()
        if icon is not None:
            app.setWindowIcon(icon)
        w = MainWindow()
        w.show()
        if open_path:
            # 右键菜单/双击文件关联启动：进入主界面的打开页并加载该归档
            from PySide6.QtCore import QTimer
            w.tabs.setCurrentWidget(w.open_tab)
            QTimer.singleShot(0, lambda: w.open_tab.open_archive(open_path))
        sys.exit(app.exec())

else:  # 无 PySide6：run_gui 不可用，main() 会回退到打印帮助

    def run_gui(open_path=None):
        raise ImportError('未安装 PySide6，无法启动图形界面: pip install PySide6')


def _plugin_api():
    """右键菜单插件 dispatch() 需要的宿主 API。"""
    return {
        'open_archive_gui': lambda path: run_gui(open_path=path),
        'create_archive': arhp_core.create_archive,
        'extract_archive': arhp_core.extract_archive,
        'info_archive': arhp_core.info_archive,
        'CryptoError': getattr(arhp_core, 'CryptoError', None),
        'exe_path': _exe_path(),
    }


if __name__ == '__main__':
    # 1) 命令行先交给右键菜单插件 dispatch（/add、/open、双击关联文件等）
    if arhp_plugin is not None:
        try:
            if arhp_plugin.dispatch(sys.argv, _plugin_api()):
                sys.exit(0)
        except SystemExit:
            raise
        except Exception:
            # 插件异常绝不静默：记录后以非零码退出（插件已认领该命令，
            # 绝不能把文件路径当普通参数再喂给命令行解析器）
            traceback.print_exc()
            sys.exit(1)
    # 2) 常规入口：default_gui=True，无参数时自动进入 GUI（双击场景）
    arhp_core.main(sys.argv[1:] or None, default_gui=True,
                   run_gui=lambda: run_gui())
