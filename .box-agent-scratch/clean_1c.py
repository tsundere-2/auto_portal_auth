"""清理误建目录 D:auto_portal_auth.box-agent-scratch（名字里带冒号）。

os.path.join/relpath 都会把 "D:" 当成盘符，因此这里改用 Win32 API
直接按文件名操作：先 os.scandir 找到真实目录项，再走 \\?\ 长路径删除。
"""
import ctypes
import os

root = os.getcwd()
target_name = "D:auto_portal_auth.box-agent-scratch"

found = [e for e in os.scandir(root) if e.name == target_name]
if not found:
    print("[SKIP] 未找到目录项:", target_name)
    raise SystemExit(0)

entry = found[0]
print("目录项:", entry.name, "is_dir:", entry.is_dir())
if not entry.is_dir():
    print("[SKIP] 不是目录")
    raise SystemExit(0)

children = list(os.scandir(entry.path))
if children:
    print("[SKIP] 非空，保留:", [c.name for c in children])
    raise SystemExit(0)

# \\?\ 前缀绕过冒号被当作盘符解析的问题
long_path = "\\\\?\\" + os.path.join(root, target_name)
rc = ctypes.windll.kernel32.RemoveDirectoryW(long_path)
print("RemoveDirectoryW ->", rc, "(非0=成功)")
if not rc:
    print("GetLastError:", ctypes.windll.kernel32.GetLastError())

still = [e.name for e in os.scandir(root) if e.name == target_name]
print("仍存在:", bool(still))
