# -*- mode: python ; coding: utf-8 -*-

import os
import platform
import glob

block_cipher = None
is_windows = platform.system() == 'Windows'

# Debug info
print("\n=== PyInstaller Build Debug ===")
print(f"Current working directory: {os.getcwd()}")
print("\nLooking for binary files:")

# Check Windows paths
if is_windows:
    win_path = os.path.join('script', 'bin', 'Release')
    print(f"Checking Windows path: {win_path}")
    if os.path.exists(win_path):
        print("Found Windows Release directory. Contents:")
        for f in glob.glob(os.path.join(win_path, '*')):
            print(f"- {f} (exists: {os.path.exists(f)})")
    else:
        print(f"Warning: {win_path} does not exist")

# Check standard paths
std_path = os.path.join('script', 'bin')
print(f"\nChecking standard path: {std_path}")
if os.path.exists(std_path):
    print("Found standard bin directory. Contents:")
    for f in glob.glob(os.path.join(std_path, '*')):
        print(f"- {f} (exists: {os.path.exists(f)})")
else:
    print(f"Warning: {std_path} does not exist")

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
