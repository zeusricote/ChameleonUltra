# -*- mode: python ; coding: utf-8 -*-

import os
import platform
import glob

block_cipher = None
is_windows = platform.system() == 'Windows'

# Debug info
print("\n=== PyInstaller Build Debug ===")
print(f"Current working directory: {os.getcwd()}")
print(f"Script directory: {os.path.dirname(os.path.abspath(__file__))}")
print("\nLooking for binary files in script/bin/:")
bin_files = glob.glob(os.path.join('script', 'bin', '*'))
for f in bin_files:
    print(f"- {f} (exists: {os.path.exists(f)})")
print("\n")

a = Analysis(
    ['script/chameleon_cli_main.py'],
    pathex=[],
    # Include all files in script/bin/
    # The build will fail if the required binaries are not present
    binaries=[
        ("script/bin/*", "bin/"),
        # Include .exe files on Windows from the Release directory
        *([
            ("script/bin/Release/*.exe", "bin/"),
            ("script/bin/Release/*.dll", "bin/")  # Include any DLLs if they exist
        ] if is_windows else [
            ("script/bin/*", "bin/")
        ]),
    ],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='chameleon_cli_main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
