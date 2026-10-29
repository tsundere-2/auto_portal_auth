"""删除 Windows 保留名 nul 的文件：手动拼 \\?\ 前缀，改名后再删。"""
import ctypes
import os

base = os.path.dirname(os.path.abspath(__file__))          # ...\.box-agent-scratch
root = os.path.dirname(base)                                # D:\auto_portal_auth
nul = root + "\\nul"
deleteme = root + "\\nul.deleteme"
long_nul = "\\\\?\\" + nul
long_del = "\\\\?\\" + deleteme

print("root:", root)
print("exists(plain):", os.path.exists(nul))

ok = False
try:
    os.rename(long_nul, long_del)          # 先脱离保留名
    print("renamed ->", deleteme)
    ok = True
except OSError as exc:
    print("rename failed:", exc)

if ok:
    try:
        os.remove(long_del)
        print("removed:", deleteme)
    except OSError as exc:
        print("remove failed:", exc)

print("nul exists :", os.path.exists(nul))
print("tmp exists :", os.path.exists(deleteme))
