#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""arhp_plugin.py — MienArch ARHP 2.0.0.2 Windows 右键菜单集成插件（随主程序打包进 exe）。

v2.0.0.2：随核心库 2.0.0.2 更新版本标识（本轮修复均在 arhp_core：
zip 解压 NameError、zip/7z 原子写入、7z 解压成员预检、zip 符号链接保留）。

v2.0.0.1：修复 /add 对话框切换到 zip 格式后已填密码未清空、导致
create_archive 以“zip 不支持加密”误报错的问题。

构建 exe 时由 PyInstaller 把本模块与 arhp_main/arhp_core 一并打包（作为普通
模块导入，不需要 --add-data，exe 旁边不再需要独立的 arhp_plugin.py）；源码运
行时也可作为独立文件与 arhp_main_2.0.0.2.py 放在同一目录。

  - 主程序 GUI 会出现“安装右键菜单 / 移除右键菜单”按钮；
  - 主程序启动时先把命令行交给本插件的 dispatch() 处理，
    因此右键菜单可以直接调起“添加压缩包 / 打开 / 解压”等操作。
    缺少本模块时主程序的所有功能完全不受影响。

注册的右键菜单结构（写入 HKCU\\Software\\Classes，免管理员权限）：

  “ARHP”注册为一级级联菜单（cascading menu），具体操作是其二级菜单：

  任意文件、文件夹        → ARHP → 添加到 ARHP 压缩包
  文件夹空白处右键        → ARHP → 将当前文件夹添加到 ARHP 压缩包
  .arh2/.arhp/.zip/.7z    → ARHP → 打开压缩包
                            ARHP → 解压文件到当前位置
                            ARHP → 解压到同名文件夹

安装时同时注册 .arh2 与 .arhp 两个文件关联（ProgID MienArch.ARH2 /
MienArch.ARHP）：资源管理器直接双击会以【裸路径参数】调起主程序
（arhp.exe "C:\\x.arh2"），dispatch() 把裸参数按“打开压缩包”处理，
直接进入主界面的打开页并加载该归档。关联只在用户尚未为该扩展名指定
其他打开方式（或已指向本 ProgID）时写入，绝不覆盖用户手动选择过的
其他程序。

级联菜单的注册表实现（重要，勿改回旧写法）：

  一级根键上写 MUIVerb（显示名）、Icon，并把 SubCommands 写成【空串】；
  二级动词放在根键的 shell\\<verb> 子键下（静态动词结构：默认值=菜单文字，
  command 子键=命令行）。

  为什么 SubCommands 必须为空：Explorer 只把 SubCommands 里的每个 token
  拿到 Explorer Command Store（HKCU\\Software\\Microsoft\\Windows\\
  CurrentVersion\\Explorer\\CommandStore\\shell）里解析。在 token 里写了
  'add;open;...' 却从不注册 Command Store，会导致每个 token 都解析失败、
  级联菜单展开为空白。空串 + shell 子键是纯注册表级联的标准写法，
  Windows 7–11 经典菜单均支持，且不需要 Command Store 的全局谓词命名空间。

  二级菜单的显示顺序按【键名】排序而非写入顺序，所以归档根下的动词
  键名带 a_/b_/c_ 前缀，保证“打开 → 解压到当前位置 → 解压到同名文件夹”。

Windows 11 说明：注册表级联菜单属于经典右键菜单，Windows 11 默认折叠在
“显示更多选项”(Shift+F10) 中；如需固定到一级菜单，需要 MSIX 稀疏包 +
IExplorerCommand COM 组件，超出本插件范围。

从 arh2_plugin.py 升级时的清理：旧版 arh2 插件的平铺菜单键
（MienArch.ARH2.AddTo 等）与级联根键（\\shell\\arh2）在安装/卸载时
顺带删除，避免新旧两套菜单并存。

Copyright (C) MienArch 2026. GPL-3.0-or-later.
"""

import os
import re
import sys

__all__ = ['install', 'uninstall', 'is_registered', 'dispatch']

# ---------------------------------------------------------------- 注册表结构

# 一级级联菜单（cascading menu）注册表根键。显示名通过 MUIVerb 写在
# 根键上；根键下有 shell 子键承载二级动词时，Explorer 才会把它渲染成
# 级联菜单而不是直接执行命令。键名用 arhp（而非旧插件的 arh2），避免与
# 旧版 arh2 插件的安装并存冲突。
_MENU_ROOTS = (
    r'Software\Classes\*\shell\arhp',
    r'Software\Classes\Directory\shell\arhp',
    r'Software\Classes\Directory\Background\shell\arhp',
    r'Software\Classes\SystemFileAssociations\.arh2\shell\arhp',
    r'Software\Classes\SystemFileAssociations\.arhp\shell\arhp',
    r'Software\Classes\SystemFileAssociations\.zip\shell\arhp',
    r'Software\Classes\SystemFileAssociations\.7z\shell\arhp',
)

_ARCHIVE_ROOTS = (
    r'Software\Classes\SystemFileAssociations\.arh2\shell\arhp',
    r'Software\Classes\SystemFileAssociations\.arhp\shell\arhp',
    r'Software\Classes\SystemFileAssociations\.zip\shell\arhp',
    r'Software\Classes\SystemFileAssociations\.7z\shell\arhp',
)

# 级联菜单下的二级菜单项：(所属根键, 动词键名, 菜单文字, 命令行参数模板)。
# 只增删自己创建的键，绝不触碰其他项。
# 注意：二级菜单按【键名】排序显示，归档根的键名用 a_/b_/c_ 前缀固定
# 顺序为 打开 → 解压到当前位置 → 解压到同名文件夹；改顺序只改键名前缀。
_VERBS = (
    (r'Software\Classes\*\shell\arhp', 'add',
     '添加到 ARHP 压缩包(&A)', '/add "%1"'),
    (r'Software\Classes\Directory\shell\arhp', 'add',
     '添加到 ARHP 压缩包(&A)', '/add "%1"'),
    (r'Software\Classes\Directory\Background\shell\arhp', 'add',
     '将当前文件夹添加到 ARHP 压缩包(&A)', '/add "%V"'),
)
_VERBS += tuple(
    (root, 'a_open', '打开压缩包(&O)', '/open "%1"') for root in _ARCHIVE_ROOTS
) + tuple(
    (root, 'b_extract_here', '解压文件到当前位置(&X)', '/extract-here "%1"')
    for root in _ARCHIVE_ROOTS
) + tuple(
    (root, 'c_extract_to', '解压到同名文件夹(&E)', '/extract-to "%1"')
    for root in _ARCHIVE_ROOTS
)

# 旧版菜单键（v1.x 平铺菜单与 arh2 插件级联菜单），安装/卸载时顺带
# 清理，避免升级后新旧两套菜单并存。
_LEGACY_KEYS = (
    # arh2 插件 v1.0.0.2 及更早的平铺菜单键
    r'Software\Classes\*\shell\MienArch.ARH2.AddTo',
    r'Software\Classes\Directory\shell\MienArch.ARH2.AddTo',
    r'Software\Classes\Directory\Background\shell\MienArch.ARH2.AddTo',
    r'Software\Classes\SystemFileAssociations\.arh2\shell\MienArch.ARH2.Open',
    r'Software\Classes\SystemFileAssociations\.arh2\shell\MienArch.ARH2.ExtractHere',
    r'Software\Classes\SystemFileAssociations\.arh2\shell\MienArch.ARH2.ExtractTo',
    # arh2 插件 v1.x 的级联菜单根键（本插件改用 arhp 键名，旧的整树删除）
    r'Software\Classes\*\shell\arh2',
    r'Software\Classes\Directory\shell\arh2',
    r'Software\Classes\Directory\Background\shell\arh2',
    r'Software\Classes\SystemFileAssociations\.arh2\shell\arh2',
)

_MENU_LABEL = 'ARHP(&R)'

_COMMANDS = frozenset(('/install-shell', '/uninstall-shell', '/add', '/open',
                       '/extract-here', '/extract-to', '/extract-ask'))

# 双击启动程序所需的文件关联：扩展名键指向本 ProgID，ProgID 的
# open 动词调起主程序。只在没有既有关联、或关联已指向本 ProgID 时
# 写入，绝不覆盖用户手动选择过的其他打开方式。
# (.zip 不注册关联：它是通用格式，用户多半已有自己的打开方式)
_FILE_ASSOC = (
    ('MienArch.ARH2', r'Software\Classes\MienArch.ARH2',
     r'Software\Classes\.arh2', 'ARH2 压缩包'),
    ('MienArch.ARHP', r'Software\Classes\MienArch.ARHP',
     r'Software\Classes\.arhp', 'ARHP 压缩包'),
)


def _winreg():
    if sys.platform != 'win32':
        return None
    try:
        import winreg
        return winreg
    except ImportError:
        return None


def _icon_source(launcher):
    """从启动命令里取可执行文件路径作为菜单图标来源。"""
    m = re.match(r'^"([^"]+)"', launcher.strip())
    return m.group(1) if m else launcher.strip()


def _delete_tree(winreg, key_path):
    """递归删除 HKCU 下的键树；不存在或删不掉（非空/无权限）时忽略。"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path,
                            0, winreg.KEY_ALL_ACCESS) as k:
            subs = []
            index = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, index))
                    index += 1
                except OSError:
                    break
        for sub in subs:
            _delete_tree(winreg, key_path + '\\' + sub)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        return True
    except OSError:
        return False


def _clear_children(winreg, key_path):
    """删除 key_path 下的全部子键。

    只用于本插件自有的级联根键（\\shell 之下），保证重复安装/版本升级后
    不会残留旧版动词子键（例如旧名 open/extract-here 与新名并存导致
    菜单里出现重复项）。键本身及其默认值、值项不受影响。
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path,
                            0, winreg.KEY_ALL_ACCESS) as k:
            subs = []
            index = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, index))
                    index += 1
                except OSError:
                    break
    except OSError:
        return
    for sub in subs:
        _delete_tree(winreg, key_path + '\\' + sub)


def _key_exists(winreg, key_path):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path):
            return True
    except OSError:
        return False


def is_registered():
    """是否已安装右键菜单（任一级菜单键存在即视为已安装）。

    旧版平铺/级联菜单键存在时也视为已安装，提示用户重新安装以迁移到
    新版级联菜单结构。
    """
    winreg = _winreg()
    if winreg is None:
        return False
    return (any(_key_exists(winreg, key) for key in _MENU_ROOTS)
            or any(_key_exists(winreg, key) for key in _LEGACY_KEYS))


def install(launcher):
    """注册右键菜单。

    launcher: 宿主程序给出的带引号启动命令前缀（如 '"C:\\app\\arhp.exe"'）。
    返回 (ok, message)。
    """
    winreg = _winreg()
    if winreg is None:
        return False, '右键菜单仅支持 Windows。'
    if not launcher:
        return False, '无法确定程序路径，无法注册右键菜单。'
    icon = _icon_source(launcher)
    try:
        # 先清理旧版菜单，避免新旧两套菜单并存。
        for legacy in _LEGACY_KEYS:
            _delete_tree(winreg, legacy)
        # 一级级联菜单根键：MUIVerb 提供显示名，Icon 提供菜单图标。
        # SubCommands 必须为【空串】：非空 token 只在 Explorer Command
        # Store 里解析，本插件不注册 Command Store，非空会导致级联菜单
        # 展开为空白。空串 + shell 子键是纯注册表级联的标准写法，二级
        # 动词由根键下的 shell 子键承载。
        for root in _MENU_ROOTS:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root) as k:
                winreg.SetValueEx(k, 'MUIVerb', 0, winreg.REG_SZ, _MENU_LABEL)
                winreg.SetValueEx(k, 'Icon', 0, winreg.REG_SZ, icon)
                winreg.SetValueEx(k, 'SubCommands', 0, winreg.REG_SZ, '')
            # 清空 shell 子键下可能存在的旧版动词（键名升级/顺序调整
            # 后避免与新版动词并存），再写入当前动词。
            shell_path = root + '\\shell'
            _clear_children(winreg, shell_path)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, shell_path):
                pass  # 确保 shell 子键存在，承载二级动词
        for root, verb, label, args in _VERBS:
            key_path = root + '\\shell\\' + verb
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
                winreg.SetValueEx(k, '', 0, winreg.REG_SZ, label)
                winreg.SetValueEx(k, 'Icon', 0, winreg.REG_SZ, icon)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  key_path + '\\command') as k:
                winreg.SetValueEx(k, '', 0, winreg.REG_SZ,
                                  '%s %s' % (launcher, args))
        # 文件关联：让资源管理器“双击 .arh2 / .arhp”能调起本程序（裸路径
        # 参数由 dispatch 按“打开压缩包”处理）。只在没有既有关联、或关联
        # 已指向本 ProgID 时写入，不覆盖用户选过的其他打开方式。
        for progid, progid_key, ext_key, type_name in _FILE_ASSOC:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ext_key) as k:
                    current, _t = winreg.QueryValueEx(k, '')
            except OSError:
                current = None
            if current not in (None, '', progid):
                continue  # 用户已指定其他打开方式，绝不覆盖
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, progid_key) as k:
                winreg.SetValueEx(k, '', 0, winreg.REG_SZ, type_name)
                winreg.SetValueEx(k, 'FriendlyTypeName', 0, winreg.REG_SZ,
                                  type_name)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  progid_key + r'\DefaultIcon') as k:
                winreg.SetValueEx(k, '', 0, winreg.REG_SZ, icon)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  progid_key + r'\shell\open\command') as k:
                winreg.SetValueEx(k, '', 0, winreg.REG_SZ,
                                  '%s /open "%%1"' % launcher)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, ext_key) as k:
                winreg.SetValueEx(k, '', 0, winreg.REG_SZ, progid)
        return True, ('右键菜单已安装。\n'
                      '· 文件/文件夹右键 →“ARHP”→“添加到 ARHP 压缩包”\n'
                      '· .arh2/.arhp/.zip/.7z 右键 →“ARHP”→“打开 / 解压到当前位置 / '
                      '解压到同名文件夹”\n'
                      '· 直接双击 .arh2 / .arhp 文件即可在主界面中打开该归档\n'
                      'Windows 11 中位于“显示更多选项”(Shift+F10)。')
    except OSError as exc:
        return False, '注册右键菜单失败（权限不足？）: %s' % exc


def uninstall():
    """移除本插件创建的全部右键菜单键。返回 (ok, message)。"""
    winreg = _winreg()
    if winreg is None:
        return False, '右键菜单仅支持 Windows。'
    removed, failed = 0, []
    # 二级动词键与一级菜单根键（递归删除整棵树）。
    targets = [root + '\\shell\\' + verb
               for root, verb, _label, _args in _VERBS]
    targets += list(_MENU_ROOTS) + list(_LEGACY_KEYS)
    for key_path in targets:
        if _delete_tree(winreg, key_path):
            removed += 1
    # 文件关联：只清理指向本插件 ProgID 的部分；用户后来改绑的其他
    # 程序一律不动。扩展名键上可能残留其他值项（如 OpenWithList），
    # 删除失败（非空/共享）时静默忽略。
    for progid, progid_key, ext_key, _name in _FILE_ASSOC:
        if _delete_tree(winreg, progid_key):
            removed += 1
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ext_key) as k:
                current, _t = winreg.QueryValueEx(k, '')
        except OSError:
            current = None
        if current == progid:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ext_key,
                                    0, winreg.KEY_ALL_ACCESS) as k:
                    winreg.DeleteValue(k, '')
            except OSError:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, ext_key)
            except OSError:
                pass
    # 仍存在的键如实上报，绝不假报成功。
    for key_path in list(_MENU_ROOTS) + list(_LEGACY_KEYS):
        if _key_exists(winreg, key_path):
            failed.append(key_path)
    # 尝试清理可能因此变空的父键；非空、共享或无权限时忽略失败。
    # 归档扩展名下的 shell 只承载本插件的级联键，同样属于自留空壳，
    # 一并清理；Directory\shell、*\shell 等系统共享键绝不触碰。
    for ext in ('.arh2', '.arhp', '.zip', '.7z'):
        for parent in (r'Software\Classes\SystemFileAssociations\%s\shell'
                       % ext,
                       r'Software\Classes\SystemFileAssociations\%s' % ext):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
            except OSError:
                pass
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                         r'Software\Classes\SystemFileAssociations')
    except OSError:
        pass
    if failed:
        return False, ('已移除 %d 项右键菜单，但以下 %d 项删除失败（权限不足？）: %s'
                       % (removed, len(failed), '; '.join(failed)))
    return True, '已移除 %d 项右键菜单。' % removed

# ======================================================================
# 命令行分发：主程序启动时调用 dispatch()，返回 True 表示已处理。
# ======================================================================


def dispatch(argv, api):
    """处理右键菜单/命令行指令；返回 True 表示主程序无需再进入 GUI 主流程。"""
    if len(argv) < 2:
        return False
    cmd = argv[1].strip().lower()
    if cmd not in _COMMANDS:
        # 资源管理器双击归档（或把文件拖到 exe 上）：文件关联把压缩包
        # 路径作为【裸参数】传进来（arhp.exe "C:\x.arh2"），argv[1] 不是
        # 指令而是文件路径。存在的真实路径一律按“打开压缩包”处理，
        # 直接进入主界面的打开页并加载该归档。
        candidate = argv[1].strip()
        # 无需再判断是否以 '/' 开头：Windows 绝对路径是盘符开头，
        # 不存在的“伪指令”会被 os.path.exists 自然过滤。
        if candidate and os.path.exists(candidate):
            api['open_archive_gui'](candidate)
            return True
        return False  # 普通双击启动，交还给主程序
    args = [a for a in argv[2:] if a]
    if cmd == '/install-shell':
        ok, msg = install(api.get('exe_path', ''))
        _notify('ARHP 右键菜单', msg, error=not ok)
    elif cmd == '/uninstall-shell':
        ok, msg = uninstall()
        _notify('ARHP 右键菜单', msg, error=not ok)
    elif cmd == '/add':
        _cmd_add(api, args)
    elif cmd == '/open':
        if not args:
            _notify('ARHP', '未指定要打开的归档。', error=True)
        else:
            api['open_archive_gui'](args[0])
    elif cmd == '/extract-here':
        _cmd_extract(api, args, 'here')
    elif cmd == '/extract-to':
        _cmd_extract(api, args, 'to')
    elif cmd == '/extract-ask':
        _cmd_extract(api, args, 'ask')
    return True


_APP = None


def _ensure_app():
    """返回全局唯一的 QApplication。

    实例必须保存在模块级变量中：PySide 里 QApplication 由 Python 包装
    对象持有，临时引用归零会连带销毁底层 C++ 实例，之后再创建任何
    QWidget 都会崩溃。右键菜单属冷启动路径（宿主 GUI 不在运行），
    这里几乎一定会新建 QApplication，因此绝不能丢弃引用。
    """
    global _APP
    if _APP is None:
        from PySide6.QtWidgets import QApplication
        existing = QApplication.instance()
        _APP = existing if existing is not None else QApplication(sys.argv)
        _APP.setApplicationName('ARHP')
    return _APP


def _notify(title, msg, error=False):
    try:
        _ensure_app()
        from PySide6.QtWidgets import QMessageBox
        box = QMessageBox.critical if error else QMessageBox.information
        box(None, title, msg)
    except Exception:
        # 完全无法弹窗时退化为控制台输出
        stream = sys.stderr if error else sys.stdout
        print('%s: %s' % (title, msg), file=stream)


class _Cancelled(Exception):
    pass


# /add 对话框可选的归档格式（下拉框顺序 = 推荐顺序，.arh2 为默认）
_ADD_FORMATS = (
    ('arh2', '.arh2', 'ARH2 归档 (*.arh2)'),
    ('arhp', '.arhp', 'ARHP 归档 (*.arhp)'),
    ('zip', '.zip', 'Zip 归档 (*.zip)'),
    ('7z', '.7z', '7-Zip 归档 (*.7z)'),
)


def _cmd_add(api, paths):
    """“添加到 ARHP 压缩包”：弹小对话框收集输出名/格式/密码/级别后创建。

    注意：注册表 verb 只会传入选中的第一个对象（%1），多选文件时
    Explorer 会逐项调用但每次都只有单路径。要真正支持多选需改用
    DropTarget COM 方式，当前设计为单对象打包。
    """
    import datetime
    if not paths:
        _notify('ARHP', '没有可打包的文件。', error=True)
        return
    _ensure_app()
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (QApplication, QComboBox, QDialog,
                                   QDialogButtonBox, QFileDialog,
                                   QHBoxLayout, QLabel, QLineEdit,
                                   QProgressDialog, QPushButton, QCheckBox,
                                   QMessageBox, QSlider, QVBoxLayout)

    first = os.path.abspath(paths[0])
    base_dir = os.path.dirname(first)
    default_out = os.path.join(
        base_dir,
        'Archive-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S') + '.arh2')

    dlg = QDialog()
    dlg.setWindowTitle('添加到 ARHP 压缩包（%d 个对象）' % len(paths))
    lay = QVBoxLayout(dlg)

    row = QHBoxLayout()
    row.addWidget(QLabel('输出文件:'))
    out_edit = QLineEdit(default_out)
    row.addWidget(out_edit)
    browse = QPushButton('浏览…')
    row.addWidget(browse)
    lay.addLayout(row)

    row = QHBoxLayout()
    row.addWidget(QLabel('格式:'))
    fmt_box = QComboBox()
    fmt_box.addItems([label for _k, _e, label in _ADD_FORMATS])
    row.addWidget(fmt_box)
    row.addStretch(1)
    lay.addLayout(row)

    row = QHBoxLayout()
    row.addWidget(QLabel('密码:'))
    pwd_edit = QLineEdit()
    pwd_edit.setEchoMode(QLineEdit.Password)
    pwd_edit.setPlaceholderText('留空 = 不加密')
    row.addWidget(pwd_edit)
    cd_encrypt = QCheckBox('加密目录')
    cd_encrypt.setToolTip('仅 .arh2：加密中心化目录，列目录也需要密码')
    cd_encrypt.setVisible(True)
    row.addWidget(cd_encrypt)
    row.addWidget(QLabel('压缩等级:'))
    level_slider = QSlider(Qt.Horizontal)
    level_slider.setRange(0, 22)
    level_slider.setValue(9)
    level_label = QLabel('9')
    level_slider.valueChanged.connect(lambda v: level_label.setText(str(v)))
    row.addWidget(level_slider)
    row.addWidget(level_label)
    lay.addLayout(row)

    buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    buttons.button(QDialogButtonBox.Ok).setText('压缩')
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    lay.addWidget(buttons)

    def _fmt_info(index=None):
        return _ADD_FORMATS[fmt_box.currentIndex() if index is None else index]

    def _sync_fmt(index):
        key, ext, _label = _fmt_info(index)
        out = out_edit.text().strip()
        if out:
            base, _e = os.path.splitext(out)
            out_edit.setText(base + ext)
        # zip 不支持加密：禁用密码输入并清空已填密码——否则切换到 zip 后
        # 残留的密码会被传给 create_archive，直接以“zip 不支持加密”报错
        is_zip = key == 'zip'
        pwd_edit.setEnabled(not is_zip)
        if is_zip:
            pwd_edit.clear()
        cd_encrypt.setVisible(key == 'arh2')
        level_slider.setMaximum(22 if key in ('arh2', 'arhp') else 9)
        if level_slider.value() > level_slider.maximum():
            level_slider.setValue(level_slider.maximum())

    def browse_out():
        _key, ext, label = _fmt_info()
        path, _f = QFileDialog.getSaveFileName(dlg, '输出归档',
                                               out_edit.text(), label)
        if path:
            if not path.lower().endswith(ext):
                path += ext
            out_edit.setText(path)

    fmt_box.currentIndexChanged.connect(_sync_fmt)
    browse.clicked.connect(browse_out)
    _sync_fmt(fmt_box.currentIndex())

    if dlg.exec() != QDialog.Accepted:
        return
    key, ext, _label = _fmt_info()
    out = out_edit.text().strip()
    if not out:
        _notify('ARHP', '输出文件名为空，已取消。', error=True)
        return
    if not out.lower().endswith(ext):
        out += ext
    # 目标已存在时必须确认——底层 create_archive 会直接原子替换，
    # 不确认就可能在用户手滑输错名字时静默覆盖旧归档。
    if os.path.exists(out):
        answer = QMessageBox.question(
            None, '文件已存在',
            '目标文件已存在，是否覆盖？\n%s' % out,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            _notify('ARHP', '已取消（不覆盖已存在的文件）。')
            return
    password = pwd_edit.text() or None
    cd_enc = bool(cd_encrypt.isChecked()) and key == 'arh2'

    progress = QProgressDialog('正在创建归档…', '取消', 0, 100, None)
    progress.setWindowTitle('ARHP')
    progress.setWindowModality(Qt.WindowModal)
    progress.setMinimumDuration(0)

    def prog(msg, pct):
        progress.setValue(pct)
        progress.setLabelText(msg)
        QApplication.processEvents()
        if progress.wasCanceled():
            raise _Cancelled()

    # finally 中统一关闭进度对话框，取消/异常路径不再依赖 GC 关窗。
    try:
        api['create_archive'](paths, out, fmt=key,
                              level=level_slider.value(),
                              password=password, cd_encrypt=cd_enc,
                              progress=prog)
    except _Cancelled:
        _notify('ARHP', '已取消。')
        return
    except Exception as exc:
        _notify('ARHP', '创建归档失败: %s' % exc, error=True)
        return
    finally:
        progress.close()
    _notify('ARHP', '已创建归档:\n%s' % out)


def _archive_base_name(path):
    """压缩包基名：去掉分卷 .NNN 后缀和扩展名，用作“同名文件夹”。"""
    base = os.path.basename(str(path))
    base = re.sub(r'\.\d{3,}$', '', base)
    base = os.path.splitext(base)[0]
    return base or 'archive'


def _is_crypto_error(exc, api):
    """密码/认证类错误判定：只认宿主传入的 CryptoError 异常类型。"""
    crypto_error = api.get('CryptoError')
    return (isinstance(crypto_error, type)
            and issubclass(crypto_error, BaseException)
            and isinstance(exc, crypto_error))


def _archive_is_encrypted(path, api):
    """尽力判断归档是否加密：True/False，无法判断时返回 None。

    通过宿主 api 提供的 info_archive 读取归档头；读取失败（文件损坏、
    不支持的格式等）返回 None，把报错交给后续的解压流程，避免在这里
    误杀合法归档。
    """
    info = api.get('info_archive')
    if info is None:
        return None
    try:
        return bool(info(path).get('encrypted'))
    except Exception:
        return None


def _cmd_extract(api, args, mode):
    """解压命令。

    here: 解压到归档所在目录；to: 解压到归档所在目录下的同名文件夹；
    ask: 先询问目标目录，再在其下创建同名文件夹。
    加密归档会在解压前先弹出密码输入框；密码错误（CryptoError）最多
    重试 3 次。
    """
    if not args:
        _notify('ARHP', '未指定要解压的归档。', error=True)
        return
    archive = args[0]
    _ensure_app()
    from PySide6.QtWidgets import (QFileDialog, QInputDialog, QLineEdit,
                                   QMessageBox)

    folder = os.path.dirname(os.path.abspath(archive))
    if mode == 'here':
        target = folder
    elif mode == 'to':
        target = os.path.join(folder, _archive_base_name(archive))
    else:
        chosen = QFileDialog.getExistingDirectory(
            None, '选择解压位置（将在其中创建“%s”文件夹）'
            % _archive_base_name(archive), folder)
        if not chosen:
            return
        target = os.path.join(chosen, _archive_base_name(archive))

    def ask_password():
        pw, ok = QInputDialog.getText(
            None, '输入密码', '该归档已加密，请输入密码:',
            QLineEdit.Password)
        return (pw, ok) if ok else (None, False)

    # 加密归档先主动询问密码：宿主对“未提供密码”抛的是 ArchiveError
    # 而非 CryptoError，仅靠异常重试永远不会弹框。
    password = None
    if _archive_is_encrypted(archive, api):
        password, ok = ask_password()
        if not ok or not password:
            return
    tries = 0
    while True:
        try:
            api['extract_archive'](archive, target, password=password)
            break
        except Exception as exc:
            # 只按宿主传入的 CryptoError 异常类型判定，避免用错误文案猜测。
            if _is_crypto_error(exc, api) and tries < 3:
                tries += 1
                password, ok = ask_password()
                if ok and password:
                    continue
                return
            QMessageBox.critical(None, '解压失败', str(exc))
            return
    QMessageBox.information(None, 'ARHP', '已解压到:\n%s' % target)
