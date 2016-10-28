# we shouldnt need to declare hiddenimports
# https://github.com/pyinstaller/pyinstaller/issues/2185
a = Analysis(['test_util/launch.py'],
             hiddenimports=['html.parser'],
             datas=[('gen/ip-detect/*.sh', 'gen/ip-detect/')])
pyz = PYZ(a.pure, a.zipped_data, cipher=None)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='dcos-launch',
    debug=False,
    strip=False,
    upx=True,
    console=True)
