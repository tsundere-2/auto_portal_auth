"""清理误建目录 D:auto_portal_auth.box-agent-scratch。

注意：目录名里带 "D:"，os.path.join 会把它当成绝对盘符，所以这里用
POSIX 风格的 "./" 前缀锁定为当前工作区内的真实目录。
"""
import os

path = os.path.join(os.getcwd(), "D:auto_portal_auth.box-agent-scratch")
path = "./" + os.path.relpath(path)

print("目标路径:", path)
if not os.path.isdir(path):
    print("[SKIP] 不存在")
    raise SystemExit(0)

entries = os.listdir(path)
if entries:
    print("[SKIP] 非空，保留:", entries)
    raise SystemExit(0)

os.rmdir(path)
print("[OK] 已删除空目录")
print("仍存在:", os.path.isdir(path))
