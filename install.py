#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install.py —— AutoPortalAuth 交互式安装脚本

为什么要有这个文件？
--------------------
原本把安装逻辑全写在 install.bat 里，会踩到 cmd.exe 的两个大坑：
  1. cmd.exe 读取 .bat 需要 CRLF 换行；纯 LF 的批处理会被错误解析。
  2. 批处理里执行 `chcp 65001` 后，cmd 继续按"字节偏移"读取脚本时会吃掉
     下一行的第一个字符（`python` 变成 `ython`），于是每一步都报
     "'ython' 不是内部或外部命令"。
所以现在 install.bat 只保留一个"纯 ASCII + CRLF"的极简启动器，
所有逻辑（含中文提示）都放在 Python 里 —— Python 处理 UTF-8 没有任何问题。

用法
----
    python install.py                       # 交互式安装
    python install.py --autostart no        # 只装依赖、不装自启
    python install.py --autostart yes --method registry --start-now
    python install.py --skip-deps --no-pause
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
MAIN = BASE / "auto_portal_auth.py"
IS_WINDOWS = platform.system() == "Windows"

# pip 镜像源：先官方，失败再试国内镜像
PIP_MIRRORS = [
    None,
    "https://pypi.tuna.tsinghua.edu.cn/simple",
    "https://mirrors.aliyun.com/pypi/simple",
]

LINE = "=" * 60


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def setup_console() -> None:
    """让控制台正确显示中文。

    把控制台代码页切到 UTF-8，并把标准流重新配置为 UTF-8 输出。
    即使某一步失败也不会中断安装（最多是中文显示成乱码）。
    """
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONUNBUFFERED"] = "1"   # 让子进程输出及时冒泡，避免与控制台打印交错错乱
    return env


def run(cmd: list, check: bool = False, capture: bool = False) -> subprocess.CompletedProcess:
    """在项目目录下执行子命令；统一使用 UTF-8 输出。"""
    # 先把自己的输出刷出去，保证"标题 -> 子进程输出"的先后顺序稳定
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    return subprocess.run(
        cmd, cwd=str(BASE), env=child_env(),
        check=check,
        capture_output=capture,
        text=True, encoding="utf-8", errors="replace",
    )


def py_main(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    """调用主程序：python -X utf8 auto_portal_auth.py ..."""
    return run([sys.executable, "-X", "utf8", str(MAIN), *args], capture=capture)


def ask(prompt: str, default: str = "y") -> bool:
    """是/否询问；非交互环境（EOF）时返回默认值。"""
    suffix = "[Y/n]" if default == "y" else "[y/N]"
    try:
        answer = input(f"      {prompt} {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default == "y"
    if not answer:
        return default == "y"
    return answer in ("y", "yes", "是", "1")


def pause_at_end(enabled: bool) -> None:
    if not enabled:
        return
    try:
        input("\n按回车键退出...")
    except (EOFError, KeyboardInterrupt):
        pass


def step(n: int, total: int, text: str) -> None:
    print(f"\n[{n}/{total}] {text}")


# ---------------------------------------------------------------------------
# 安装步骤
# ---------------------------------------------------------------------------
def check_python() -> bool:
    version = platform.python_version()
    ok = sys.version_info >= (3, 8)
    mark = "OK" if ok else "版本过低"
    print(f"      Python {version}  ({sys.executable})  [{mark}]")
    if not ok:
        print("      [!] 需要 Python 3.8 或更高版本，请先升级。")
        print("          下载地址: https://www.python.org/downloads/")
    return ok


def install_deps(skip: bool = False) -> bool:
    if skip:
        print("      已跳过依赖安装（--skip-deps）")
        return True

    req = BASE / "requirements.txt"
    if not req.exists():
        print(f"      [!] 找不到 {req.name}，改为直接安装 requests PyYAML psutil")
        base_cmd = [sys.executable, "-m", "pip", "install", "requests", "PyYAML", "psutil"]
    else:
        base_cmd = [sys.executable, "-m", "pip", "install", "-r", str(req)]

    # 先确认 pip 可用
    if run([sys.executable, "-m", "pip", "--version"], capture=True).returncode != 0:
        print("      未检测到 pip，尝试使用 ensurepip 安装 ...")
        run([sys.executable, "-m", "ensurepip", "--upgrade"], capture=True)

    for index, mirror in enumerate(PIP_MIRRORS):
        cmd = list(base_cmd)
        if mirror:
            cmd += ["-i", mirror]
            print(f"      使用镜像源重试: {mirror}")
        proc = run(cmd)
        if proc.returncode == 0:
            break
    else:
        print("\n      [X] 依赖安装失败。请手动执行：")
        print(f"          {sys.executable} -m pip install requests PyYAML psutil")
        return False

    # 复核依赖是否真的可导入
    probe = run([sys.executable, "-c", "import requests, yaml, psutil; print('ok')"],
                capture=True)
    if "ok" not in (probe.stdout or ""):
        print("      [!] 依赖复核失败，输出如下：")
        print((probe.stdout or "") + (probe.stderr or ""))
        return False
    print("      依赖已就绪: requests / PyYAML / psutil")
    return True


def ensure_config() -> bool:
    cfg = BASE / "config.yaml"
    if cfg.exists():
        print(f"      config.yaml 已存在，保留原有配置（{cfg}）")
        return True
    print("      未找到 config.yaml，正在生成默认配置 ...")
    # selftest 会触发 Config.load()，从而自动写出默认 config.yaml
    proc = py_main("selftest", capture=True)
    if cfg.exists():
        print(f"      已生成 {cfg}")
        return True
    print("      [!] 生成配置失败：")
    print((proc.stdout or "") + (proc.stderr or ""))
    return False


def run_selftest() -> bool:
    proc = py_main("selftest")
    return proc.returncode == 0


def probe_network() -> int:
    proc = py_main("once", "--no-trigger")
    code = proc.returncode
    meaning = {0: "网络正常", 1: "状态未知", 2: "需要认证（Portal）", 3: "链路未连接"}.get(code, "未知")
    print(f"      退出码 {code} => {meaning}")
    return code


def do_autostart(method: str, start_now: bool) -> bool:
    args = ["install", "--method", method]
    if start_now:
        args.append("--start-now")
    proc = py_main(*args)
    return proc.returncode == 0


def ask_autostart_method() -> str:
    if not IS_WINDOWS:
        return "auto"
    print("         1 = 注册表 (推荐，无需管理员权限)")
    print("         2 = 启动文件夹 (生成 .vbs，隐藏窗口)")
    print("         3 = 计划任务 (可与系统唤醒事件联动，可能需管理员权限)")
    try:
        choice = input("      请选择 [1] ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        choice = "1"
        print()
    return {"2": "startup", "3": "task"}.get(choice, "registry")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    setup_console()

    parser = argparse.ArgumentParser(description="AutoPortalAuth 安装脚本")
    parser.add_argument("--autostart", choices=["ask", "yes", "no"], default="ask",
                        help="是否安装开机自启（默认交互询问）")
    parser.add_argument("--method", default="auto",
                        choices=["auto", "registry", "startup", "task", "systemd", "launchd"],
                        help="自启方式")
    parser.add_argument("--start-now", action="store_true", help="安装后立即在后台启动")
    parser.add_argument("--no-start", action="store_true", help="安装自启后不要立即启动（也不询问）")
    parser.add_argument("--skip-deps", action="store_true", help="跳过依赖安装")
    parser.add_argument("--no-pause", action="store_true", help="结束时不等待按键")
    parser.add_argument("--no-probe", action="store_true", help="跳过网络探测试运行")
    args = parser.parse_args(argv)

    print(f"\n{LINE}\n  AutoPortalAuth 安装程序\n{LINE}\n")
    print(f"  项目目录: {BASE}")
    print(f"  运行平台: {platform.system()} {platform.release()}")

    if not MAIN.exists():
        print(f"\n[X] 找不到主程序 {MAIN}，请确认 install.py 与 auto_portal_auth.py 在同一目录。")
        pause_at_end(not args.no_pause)
        return 1

    total = 5
    failed = False

    step(1, total, "检查 Python 环境")
    if not check_python():
        pause_at_end(not args.no_pause)
        return 1

    step(2, total, "安装依赖 (requests / PyYAML / psutil)")
    if not install_deps(args.skip_deps):
        failed = True

    step(3, total, "准备配置文件")
    if not ensure_config():
        failed = True

    step(4, total, "自检 (Portal 指纹识别)")
    if not run_selftest():
        print("      [!] 自检存在失败项，请查看上面的输出")
        failed = True

    if not args.no_probe:
        print("\n      试运行一次网络检测 ...")
        probe_network()

    step(5, total, "开机自启")
    want_autostart = args.autostart == "yes"
    if args.autostart == "ask":
        want_autostart = ask("是否安装开机自启？", default="y")
    if want_autostart:
        method = args.method
        if method == "auto" and IS_WINDOWS and args.autostart == "ask":
            method = ask_autostart_method()
        if args.start_now:
            start_now = True
        elif args.no_start:
            start_now = False
        else:
            start_now = ask("安装后立即在后台启动？", default="y")
        if do_autostart(method, start_now):
            print("      开机自启安装完成")
        else:
            print("      [!] 自启安装失败，稍后可手动执行:")
            print(f"          {sys.executable} auto_portal_auth.py install")
            failed = True
    else:
        print("      已跳过（稍后可执行: python auto_portal_auth.py install）")

    # ---- 收尾 --------------------------------------------------------------
    py = f'"{sys.executable}"'
    print(f"\n{LINE}")
    print("  安装完成" if not failed else "  安装完成（有警告，请查看上面的 [!] 提示）")
    print(LINE)
    print(f"  查看状态:  {py} auto_portal_auth.py status")
    print(f"  查看统计:  {py} auto_portal_auth.py stats")
    print(f"  超时分析:  {py} auto_portal_auth.py analyze")
    print(f"  常驻运行:  {py} auto_portal_auth.py run")
    print(f"  卸载自启:  {py} auto_portal_auth.py uninstall")
    print(f"  日志文件:  {BASE / 'logs' / 'auto_portal_auth.log'}")
    print(LINE)
    print("  提示：把 config.yaml 中 auth.auto_login.enabled 改为 true 并填入")
    print("        账号密码，即可实现无人值守的全自动登录。")
    print(LINE)

    pause_at_end(not args.no_pause)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
