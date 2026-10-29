"""清理第 ① 项：我上一轮误建的目录（均为空目录）。

只删空的、确认不含任何文件的目录；任何非空目录一律跳过并报告。
"""
import os

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
targets = [
    os.path.join(root, ".box-agent-scratch", "9d568bbb7b784009b06037a07a1e80f0"),
    os.path.join(root, "D:auto_portal_auth.box-agent-scratch"),
]

for path in targets:
    name = os.path.basename(path)
    if not os.path.isdir(path):
        print(f"[SKIP] 不存在: {name}")
        continue
    entries = os.listdir(path)
    if entries:
        print(f"[SKIP] 非空，保留: {name} -> {entries}")
        continue
    try:
        os.rmdir(path)
        print(f"[OK]   已删除空目录: {name}")
    except OSError as exc:
        print(f"[FAIL] {name}: {exc}")
