# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

root = Path(SPEC).resolve().parent

a = Analysis(
    [str(root / "src" / "tun_bridge" / "__main__.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[
        (str(root / "mihomo-tun.ps1"), "."),
        (str(root / "cleanup-tun.ps1"), "."),
        (str(root / "tun-watchdog.ps1"), "."),
        (str(root / "runtime"), "runtime"),
        (str(root / "THIRD_PARTY_NOTICES.md"), "."),
        (str(root / "LICENSE"), "."),
    ],
    hiddenimports=["tun_gui.app", "tun_controller.mihomo_supervisor"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="V2RayN-TUN-Bridge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name="V2RayN-TUN-Bridge",
)
