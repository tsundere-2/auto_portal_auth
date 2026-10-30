#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auto_portal_auth.py
===================
校园网 Portal 认证 自动登录 / 自动重连 / 唤醒恢复 守护程序。

问题背景
--------
校园网使用 Portal（Web 认证）机制：
  * 电脑睡眠唤醒后，网线已连接、也有 IP，但必须先打开浏览器访问网页，
    才会被重定向到认证页 -> 认证完成后才能上网。
  * 而"拔掉网线再插上"时，物理链路断开事件会让交换机/认证服务器清理会话，
    于是重连时再次弹出认证页，看起来"自动恢复了"。

结论：认证服务器在会话**空闲超时**后会清理会话，但空闲超时**不会**主动通知客户端；
只有物理链路闪断才会触发链路层重协商与重新认证。因此本程序要做的就是：

  1. 周期性地主动探测"到底能不能上网"，而不是等用户打开浏览器；
  2. 一旦发现被 Portal 拦截（HTTP 请求被重定向 / 返回了认证页），立刻主动
     触发一次认证（GET 认证页 -> 打开浏览器 / 直接 POST 登录）；
  3. 监听系统休眠唤醒与网络变化事件，唤醒后立刻检测，缩短恢复时间；
  4. 统计"空闲超时"规律，主动做 keepalive（心跳保活），把断连消灭在发生之前。

运行方式
--------
    python auto_portal_auth.py run            # 常驻守护（默认命令）
    python auto_portal_auth.py once           # 单次检测并退出（可配合计划任务）
    python auto_portal_auth.py status         # 查看当前状态（JSON）
    python auto_portal_auth.py stats          # 查看统计信息
    python auto_portal_auth.py analyze        # 分析空闲超时并给出保活建议
    python auto_portal_auth.py install        # 安装开机自启
    python auto_portal_auth.py uninstall      # 卸载开机自启
    python auto_portal_auth.py selftest       # 自检（指纹识别用例）

依赖：requests、PyYAML、psutil（见 requirements.txt）
"""

from __future__ import annotations

import argparse
import atexit
import collections
import copy
import ctypes
import faulthandler
import gzip
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

# ---------------------------------------------------------------------------
# 可选依赖：缺失时给出友好提示，而不是直接崩溃
# ---------------------------------------------------------------------------
try:
    import requests
    from requests import exceptions as requests_exc
except ImportError:  # pragma: no cover
    requests = None
    requests_exc = None

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

# 自动点击引擎（可选组件：缺 selenium 时模块仍可导入，只是不可用）
try:
    import portal_autoclick
except Exception:  # pragma: no cover
    portal_autoclick = None


__version__ = "1.0.0"
APP_NAME = "AutoPortalAuth"

LOG = logging.getLogger("portal")


# ===========================================================================
# 1. 配置管理
# ===========================================================================
DEFAULT_CONFIG: Dict[str, Any] = {
    "app": {
        "log_level": "INFO",
        # 相对路径一律相对于"配置文件所在目录"解析，便于整体搬迁
        "log_file": "logs/auto_portal_auth.log",
        "log_max_bytes": 2 * 1024 * 1024,
        "log_backup_count": 5,
        "stats_file": "data/stats.json",
        "state_file": "data/state.json",
        "crash_log_file": "logs/crash.log",  # 崩溃/未捕获异常/线程异常的完整栈
        "portal_cache_file": "data/last_portal.json",   # 记住上次认证页，唤醒后抢在浏览器前登录
        "lock_file": "data/auto_portal_auth.lock",
        "single_instance": True,
        "hide_console": True,
    },
    "detect": {
        # 单次 HTTP 探测超时（connect, read），秒
        "connect_timeout": 3,
        "read_timeout": 5,
        # 直接发请求比对而不是信任系统代理：校园网环境里系统代理常常会干扰探测
        "ignore_system_proxy": True,
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        ),
        # "在线上"的判定目标：全部按 HTTP 状态码 / 关键字校验。
        # 只要有一个目标通过，就认为网络正常；否则按"被重定向/内容不符"判定为 Portal 拦截。
        "probe_targets": [
            {
                "name": "msft",
                "url": "http://www.msftconnecttest.com/connecttest.txt",
                "expect_status": 200,
                "expect_contains": "Microsoft Connect Test",
            },
            {
                "name": "miui",
                "url": "http://connect.rom.miui.com/generate_204",
                "expect_status": 204,
                "expect_contains": "",
            },
            {
                "name": "gstatic",
                "url": "http://connectivitycheck.gstatic.com/generate_204",
                "expect_status": 204,
                "expect_contains": "",
            },
        ],
        "portal_max_hops": 5,          # 跟随重定向的最大跳数（用于抓取认证页真实地址）
        "probe_portal_page": True,     # 是否 GET 认证页正文用于指纹识别
        "probe_portal_page_max_bytes": 256 * 1024,
    },
    "network": {
        # 判定"物理链路已连接"时要忽略的网卡（不分大小写，子串匹配）
        "ignore_interfaces": [
            "loopback", "virtualbox", "vmware", "hyper-v", "vethernet",
            "docker", "veth", "tap", "tun", "bluetooth", "teredo",
            "isatap", "wsl", "npcap", "wan miniport",
        ],
    },
    "monitor": {
        "interval": 30,            # 网络正常时的巡检周期（秒）
        "portal_interval": 8,      # 需要认证 / 尝试认证时的重试周期（秒）
        "link_down_interval": 5,   # 链路断开 / 无 IP 时的巡检周期（秒）
        "unknown_interval": 15,    # 状态未知（探测失败）时的周期
        "wake_grace": 1,           # 唤醒后等待协议栈就绪的秒数（越小越快，失败会自动快重试）
        "wake_fast_probes": 12,    # 唤醒后快速重试次数（约每 1.5 秒一次）
        "wake_preauth": True,      # 唤醒后先用上次的认证页地址直连登录（不等 DNS）
        "wake_preauth_window": 25,  # 唤醒后抢跑窗口的秒数（这段时间内不快退、不误报断网）
        "wake_unknown_tolerance": 30,  # 唤醒后多久内的探测失败不当成"断网"（秒）
        "backoff_max": 300,        # 认证失败时的最大退避周期
        "detect_sleep_skew": 5.0,  # 时钟差超过该值即认为发生过休眠（秒）
    },
    "auth": {
        "enabled": True,
        "open_browser": True,      # 是否需要打开默认浏览器（绝大多数校园网 Portal 需要）
        "http_probe_portal": True, # 是否用 HTTP GET 主动"戳"一下认证页（部分 Portal 靠这个建立会话）
        "browser_cooldown": 90,    # 同一认证页重复打开浏览器的最小间隔（秒）
        "trigger_commands": [],    # 自定义触发命令列表，例如 [["curl", "-s", "{portal_url}"]]
        "auto_login": {
            # 自动填表登录：需要知道用户名密码，且页面是普通 form 表单或已知厂商接口
            "enabled": False,
            "username": "",
            "password": "",
            # 追加字段，例如某些 Portal 需要 wlanuserip / nasip 等
            "extra_fields": {},
            # 表单字段名包含这些关键字则填用户名 / 密码
            "username_field_keywords": ["user", "name", "account", "acct", "login", "sid", "uid"],
            "password_field_keywords": ["pass", "pwd", "password", "secret"],
            "verify_timeout": 25,  # 提交后等待联网成功的最大秒数
            # 网关明确说"密码错误/用户不存在"时，暂停自动登录的秒数（防止账号被锁）
            "fail_cooldown": 1800,
        },
        "keepalive": {
            "enabled": True,
            "interval": 0,   # 0 = 自动（根据空闲超时统计推断，默认 240 秒）
            "default_interval": 240,
        },
    },
    "notification": {
        "enabled": True,
        "on_success": True,     # 恢复联网时提醒
        "on_failure": True,     # 认证持续失败时提醒
        "on_wake": False,       # 唤醒事件是否提醒
        "cooldown": 60,
        "failure_threshold": 3,  # 连续失败多少次才提醒
    },
    # -------------------------------------------------------------------
    # 浏览器自动化：自动勾选条款 + 点击"连接/登录"按钮（Selenium）
    # 这是解决"页面已打开但还要人工点一下"的核心模块。
    # -------------------------------------------------------------------
    "browser_automation": {
        "enabled": True,
        "engine": "auto",              # auto | selenium | off
        "browser": "auto",             # auto | edge | chrome
        "binary": "",                  # 自定义浏览器可执行文件路径（留空自动查找）
        "headless": "auto",            # auto=先无头，失败再显示窗口 | true | false
        "timeout": 35,                 # 一次点击+验证的总预算（秒）
        "page_load_timeout": 20,
        "verify_interval": 3,          # 轮询"是否已联网"的间隔
        "click_delay": 0.8,            # 点击后等待页面反应
        "settle_seconds": 1.5,         # 打开页面后等待渲染
        "max_attempts": 2,             # 同一浏览器会话内最多点击几轮
        "max_frame_depth": 3,          # iframe 递归深度
        "profile_dir": "data/browser_profile",   # 专用浏览器配置（保留记住的登录态）
        "no_proxy": True,              # 认证页必须直连
        "ignore_cert_errors": True,    # Portal 常见自签证书
        "keep_browser_open": False,    # 成功后是否保留浏览器窗口
        "dump_on_failure": True,       # 失败时保存 HTML/截图，便于调参
        "screenshot_on_failure": True,
        "dump_dir": "data/autoclick",
        "keep_failure_dumps": 10,       # 只保留最近 N 次失败现场（截图+HTML）
        "score_threshold": 5,          # 低于该分数宁可不点，避免乱点
        "fill_credentials": True,      # 账号密码登录页：自动填入 auth.auto_login 的账号密码
        "skip_terms_checkbox": False,  # true = 不自动勾选服务条款
        "accept_alerts": True,         # 自动确认 alert/confirm
        "failure_threshold": 3,        # 连续失败几次后暂时停用
        "failure_cooldown": 600,       # 停用时长（秒）
        "button_texts": [],            # 追加"连接"类关键词（权重 9）
        "button_deny_texts": [],       # 追加"不要点"的关键词
        "checkbox_texts": [],          # 追加条款复选框关键词
        "extra_button_selectors": [],  # 追加 CSS 选择器
    },
    "stats": {
        "enabled": True,
        "max_sessions": 500,
        "max_idle_samples": 200,
    },
    "timeout_analysis": {
        "enabled": True,
        "min_samples": 3,        # 至少多少个样本才敢给保活建议
        "min_seconds": 60,       # 小于该时长不认为是"空闲超时"（可能只是抖动）
        "max_seconds": 12 * 3600,
    },
}

# 典型的 Portal 指纹库：厂商 - 匹配规则 - 权重
PORTAL_SIGNATURES: List[Tuple[str, str, float]] = [
    # (厂商 key, 正则, 权重)
    ("srun", r"srun|深澜|/srun_portal|ac_domain|portal\.srun|srunuid|srunuser", 3.0),
    ("ruijie", r"ruijie|锐捷|/eportal/|wlan\.ruijie|ess\.ruijie|RG[-_ ]?eportal", 3.0),
    ("drcom", r"drcom|dr\.com|城市热点|/drcom/|portal\.drcom|cp\.drcom", 3.0),
    ("h3c", r"h3c|华三|/portal/login|PortalServer|iMC|portal\.h3c", 2.5),
    ("huawei", r"huawei|华为|agile ?controller|portal\.huawei|/portal/page", 2.5),
    ("sangfor", r"sangfor|深信服|/ac_portal/|上网行为管理", 2.5),
    ("cisco", r"cisco|/guest/mgauth/|webauth", 2.0),
    ("array", r"array ?networks|/portal_", 1.5),
    ("zte", r"zte|中兴|/portal/index", 1.5),
    ("generic", r"认证|portal|登录|login|上网|网络接入|请连接|上网登录|web登录|sign ?in|welcome to", 1.0),
]

# Portal 页面 URL 中常见的协议化查询参数（可作为登录表单的补充字段）
PORTAL_URL_PARAM_HINTS = [
    "wlanuserip", "wlanacname", "wlanacip", "nasip", "userip", "usermac",
    "useripv6", "nasid", "mac", "ssid", "t", "acname", "auth_type",
]


class Config:
    """分层配置：DEFAULT_CONFIG 与用户 YAML 深度合并，支持 "a.b.c" 点号访问。"""

    def __init__(self, data: Optional[Dict[str, Any]] = None, path: Optional[Path] = None):
        self.path = Path(path) if path else None
        self.base_dir = self.path.parent if self.path else Path(__file__).resolve().parent
        self._data = deep_merge(copy.deepcopy(DEFAULT_CONFIG), data or {})

    # -- 读取 ---------------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self._data
        for part in dotted.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = self._data
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
            if not isinstance(cur, dict):  # 类型冲突时直接覆盖
                raise TypeError(f"配置路径冲突: {dotted}")
        cur[parts[-1]] = value

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    def resolve_path(self, relative: str) -> Path:
        """相对路径统一相对配置文件所在目录解析。"""
        p = Path(relative)
        return p if p.is_absolute() else (self.base_dir / p)

    # -- 加载 ---------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        cfg_path = Path(path).expanduser().resolve() if path else Path(__file__).resolve().parent / "config.yaml"
        if not cfg_path.exists():
            cfg = cls(path=cfg_path)
            if yaml is None:
                # 缺 PyYAML 时无法写默认配置；由调用方统一给"缺少依赖"提示，
                # 这里保持安静，避免再叠一条误导性的"生成失败"。
                return cfg
            try:
                cfg_path.parent.mkdir(parents=True, exist_ok=True)
                with cfg_path.open("w", encoding="utf-8") as f:
                    f.write("# AutoPortalAuth 默认配置（由程序自动生成）\n")
                    yaml.safe_dump(DEFAULT_CONFIG, f, allow_unicode=True, sort_keys=False)
                print(f"[i] 未找到配置文件，已生成默认配置: {cfg_path}", file=sys.stderr)
            except Exception as exc:  # 配置目录不可写时，仅使用内置默认值
                print(f"[!] 生成默认配置失败({exc})，将使用内置默认值", file=sys.stderr)
            return cfg

        if yaml is None:
            # 不是"配置文件写错了"，而是当前解释器没装 PyYAML。
            # 交给 main() 的依赖检查统一提示，避免误导用户去改配置。
            return cls(path=cfg_path)

        try:
            with cfg_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception as exc:
            print(f"[!] 解析配置文件失败({exc})，将使用内置默认值", file=sys.stderr)
            data = {}
        return cls(data=data, path=cfg_path)


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """递归合并字典：override 优先，但不会丢掉 base 中缺失的子键。"""
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


# ===========================================================================
# 2. 日志
# ===========================================================================
def setup_logging(cfg: Config, verbose: bool = False, level_override: Optional[str] = None) -> None:
    level_name = (level_override or cfg.get("app.log_level", "INFO") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-7s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    # 第三方库（尤其 Selenium）的 DEBUG 日志会把整个 WebDriver 报文打出来，
    # 即使 -v 也会淹没我们自己的日志，因此统一压到 WARNING。
    for noisy in ("selenium", "urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    console = logging.StreamHandler(sys.stdout if sys.stdout is not None else sys.stderr)
    console.setLevel(logging.DEBUG if verbose else level)
    console.setFormatter(fmt)
    # 注意：用 pythonw.exe（无控制台）启动时 sys.stdout/stderr 为 None，
    # 此时不能挂控制台 handler，否则每次写日志都会抛异常。
    if sys.stdout is not None or sys.stderr is not None:
        root.addHandler(console)

    log_file = cfg.get("app.log_file")
    if log_file:
        try:
            path = cfg.resolve_path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                path,
                maxBytes=int(cfg.get("app.log_max_bytes", 2 * 1024 * 1024)),
                backupCount=int(cfg.get("app.log_backup_count", 5)),
                encoding="utf-8",
            )
            fh.setLevel(logging.DEBUG)   # 文件里保留全部细节
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except Exception as exc:
            print(f"[!] 初始化日志文件失败: {exc}", file=sys.stderr)

    # 第三方库日志降噪
    for noisy in ("urllib3", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ===========================================================================
# 3. 崩溃 / 异常退出诊断
# ===========================================================================
# 背景：2026-10-29 21:01 守护进程静默消失，日志戛然而止、没有 WER 记录，
# 只能靠倒推系统事件才判断出"进程没了"。这个模块的目的就是让下次
# 死掉时能直接看到死因，而不是再猜一遍。

def install_crash_diagnostics(cfg: Config, crash_log: Optional[Path] = None) -> None:
    """安装三层退出诊断，全部写入 logs/crash.log。

    1. faulthandler：段错误 / abort / 栈溢出这类"Python 层抓不到"的硬崩溃，
       会打印完整 Python 调用栈（这是唯一能抓到 native 崩溃的手段）。
    2. excepthook：主线程未捕获异常。
    3. threading.excepthook：后台线程（电源监听、Selenium）抛的异常。
    另外挂一个 atexit 钩子，正常退出也会记一笔，便于区分"正常停"和"被杀"。
    """
    path = crash_log or cfg.resolve_path(
        cfg.get("app.crash_log_file", "logs/crash.log"))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        f = path.open("a", encoding="utf-8")
    except Exception as exc:      # 日志目录不可写时不影响主功能
        print(f"[!] 初始化崩溃日志失败: {exc}", file=sys.stderr)
        return

    # 1) 硬崩溃：保留全部线程栈
    try:
        faulthandler.enable(file=f, all_threads=True)
    except Exception:
        pass

    def _stamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _excepthook(exc_type, exc, tb):
        import traceback
        f.write(f"\n===== {_stamp()} 未捕获异常 pid={os.getpid()} =====\n")
        traceback.print_exception(exc_type, exc, tb, file=f)
        f.flush()
        LOG.error("未捕获异常，详情见 %s", path)

    def _thread_hook(args):
        import traceback
        if args.exc_type is SystemExit:
            return
        f.write(f"\n===== {_stamp()} 线程异常 {getattr(args.thread, 'name', '?')} "
                f"pid={os.getpid()} =====\n")
        traceback.print_exception(args.exc_type, args.exc_value,
                                  args.exc_traceback, file=f)
        f.flush()

    sys.excepthook = _excepthook
    try:
        threading.excepthook = _thread_hook
    except Exception:
        pass

    # 4) 正常退出也留一笔：没有这一笔又没崩溃记录 => 被外部强杀
    def _on_exit():
        try:
            f.write(f"\n===== {_stamp()} 进程正常退出 pid={os.getpid()} =====\n")
            f.flush()
        except Exception:
            pass

    atexit.register(_on_exit)
    LOG.debug("崩溃诊断已启用: %s", path)


# ===========================================================================
# 4. 数据结构
# ===========================================================================
class NetState(str, Enum):
    LINK_DOWN = "link_down"                # 物理链路未连接 / 无 IP
    NO_IP = "no_ip"                         # 链路 up 但没有可用（非 169.254）地址
    INTERNET_OK = "internet_ok"             # 能正常上网
    PORTAL_REQUIRED = "portal_required"     # 被 Portal 拦截，需要认证
    UNKNOWN = "unknown"                     # 探测异常（DNS 失败、超时等）

    @property
    def is_online(self) -> bool:
        return self is NetState.INTERNET_OK


@dataclass
class LinkInfo:
    up: bool = False
    interfaces: Dict[str, List[str]] = field(default_factory=dict)
    primary_ip: str = ""
    primary_iface: str = ""

    @property
    def has_ip(self) -> bool:
        return bool(self.interfaces)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PortalForm:
    action: str = ""
    method: str = "post"
    fields: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class Fingerprint:
    vendor: str = "unknown"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    portal_url: str = ""
    page_title: str = ""
    meta_refresh: str = ""
    login_form: Optional[PortalForm] = None
    matched_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["login_form"] = asdict(self.login_form) if self.login_form else None
        return d


@dataclass
class ProbeResult:
    target: str = ""
    kind: str = "error"            # ok | portal | error
    status_code: int = 0
    final_url: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    url: str = ""
    elapsed_ms: int = 0
    detail: str = ""
    body_sample: str = ""
    body_html: str = ""          # 完整认证页（body_sample 只有前 4000 字，锐捷的公钥在页面后段）


@dataclass
class NetStatus:
    state: NetState = NetState.UNKNOWN
    detail: str = ""
    interface: str = ""
    local_ip: str = ""
    portal_url: str = ""
    fingerprint: Optional[Fingerprint] = None
    probes: List[Dict[str, Any]] = field(default_factory=list)
    checked_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "detail": self.detail,
            "interface": self.interface,
            "local_ip": self.local_ip,
            "portal_url": self.portal_url,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "probes": self.probes,
            "checked_at": self.checked_at,
        }


# ===========================================================================
# 5. HTML 解析：抓取登录表单 / meta refresh
# ===========================================================================
class _FormParser(HTMLParser):
    """提取页面中的所有 form 及其 input/select 字段。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[PortalForm] = []
        self._current: Optional[PortalForm] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = PortalForm(
                action=a.get("action", ""),
                method=(a.get("method", "post") or "post").lower(),
            )
            self.forms.append(self._current)
        elif tag in ("input", "select", "textarea", "button") and self._current is not None:
            name = a.get("name") or a.get("id") or ""
            if not name:
                return
            self._current.fields.append({
                "name": name,
                "type": (a.get("type") or tag).lower(),
                "value": a.get("value", ""),
                "checked": "checked" in a,
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


class _MetaRefreshParser(HTMLParser):
    """提取 <meta http-equiv="refresh" content="0;url=..."> 形式的跳转。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.url = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag != "meta":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if a.get("http-equiv", "").lower() != "refresh":
            return
        m = re.search(r"url\s*=\s*['\"]?([^'\">\s]+)", a.get("content", ""), re.I)
        if m:
            self.url = m.group(1)


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def guess_vendor(url: str, html: str) -> Fingerprint:
    """根据 URL + 页面内容判定 Portal 厂商，并抽取登录表单。"""
    fp = Fingerprint(matched_at=now_iso())
    haystack_parts = [url or "", ] + re.findall(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    # 页面正文只取前 200KB，避免超大页面拖慢正则
    haystack = (" ".join(haystack_parts) + " " + (html or "")[:200_000]).lower()

    best_vendor, best_score = "unknown", 0.0
    for vendor, pattern, weight in PORTAL_SIGNATURES:
        try:
            hits = len(set(m.group(0) for m in re.finditer(pattern, haystack, re.I)))
        except re.error:
            hits = 0
        if not hits:
            continue
        # 命中条数越多、权重越高越可信；同一厂商收敛到 0~1
        score = weight * (1.0 - 0.5 ** hits)
        if score > best_score:
            best_vendor, best_score = vendor, score
        if vendor != "generic":
            fp.evidence.append(f"{vendor}:{hits}")

    if best_vendor != "unknown":
        fp.vendor = best_vendor
        fp.confidence = round(min(best_score / 3.0, 1.0), 2)

    # URL 里的 Portal 协议参数也是重要证据
    try:
        params = dict(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^&#]*)",
                                 urlparse(url).query or ""))
        for hint in PORTAL_URL_PARAM_HINTS:
            if any(hint == k.lower() for k in params):
                fp.evidence.append(f"url_param:{hint}")
                fp.confidence = min(1.0, fp.confidence + 0.05)
    except Exception:
        pass

    # 页面正文特征
    if re.search(r"<form[^>]*>", html or "", re.I):
        forms = _FormParser()
        try:
            forms.feed(html or "")
        except Exception:
            pass
        # 优先选择"包含密码框"的表单作为登录表单
        chosen = None
        for form in forms.forms:
            types = {f["type"] for f in form.fields}
            if "password" in types:
                chosen = form
                break
            if chosen is None and form.fields:
                chosen = form
        if chosen:
            fp.login_form = chosen
            fp.evidence.append(f"form_fields:{len(chosen.fields)}")

    title = _TitleParser()
    try:
        title.feed((html or "")[:50_000])
    except Exception:
        pass
    fp.page_title = (title.title or "")[:120]

    refresh = _MetaRefreshParser()
    try:
        refresh.feed((html or "")[:50_000])
    except Exception:
        pass
    if refresh.url:
        fp.meta_refresh = refresh.url
        fp.evidence.append("meta_refresh")

    return fp


# URL 打分：判断"这个地址像不像真正的认证页"
_ASSET_RE = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|mp4|mp3)(?:\?|#|$)", re.I)
_LINK_RE = re.compile(r"""https?://[^\s"'<>\\]+""", re.I)
_JS_NAV_RE = re.compile(
    r"""(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"""
    r"""|window\.open\s*\(\s*["']([^"']+)["']""", re.I)


def _portal_link_score(url: str) -> int:
    """给一个 URL 打分，越高越像认证页（0 表示完全不像）。"""
    if not url:
        return 0
    u = url.lower()
    if not u.startswith(("http://", "https://")) or _ASSET_RE.search(u) or len(url) > 2000:
        return 0
    score = 0
    if "eportal" in u:
        score += 4
    if "wlanuserip=" in u:
        score += 3
    if "portal" in u:
        score += 2
    if "login" in u or "logon" in u:
        score += 1
    if "auth" in u or "wlan" in u:
        score += 1
    try:
        host = urlparse(url).hostname or ""
        if ipaddress.ip_address(host).is_private:
            score += 1
    except ValueError:
        pass
    return score


def extract_portal_link(base_url: str, html: str) -> str:
    """从探测响应里找出真正的认证页地址。

    锐捷 / 深澜等网关在访问 connecttest.txt 这类地址时，经常返回一个
    "200 + meta/JS 跳转"的中间页，真正的 ePortal 地址还带着
    wlanuserip、mac、nasid 等参数。直接用探测地址打开，登录按钮
    可能因为缺参数而失效，所以这里尽量还原出完整地址。
    """
    if not html:
        return ""
    candidates: List[str] = []

    # 1) meta refresh
    try:
        refresh = _MetaRefreshParser()
        refresh.feed(html[:100_000])
        if refresh.url:
            candidates.append(urljoin(base_url, refresh.url))
    except Exception:
        pass

    # 2) 正文里的绝对地址
    for m in _LINK_RE.finditer(html[:200_000]):
        candidates.append(m.group(0).replace("&amp;", "&"))

    # 3) JS 跳转（location.href=... / window.open(...)）
    for m in _JS_NAV_RE.finditer(html[:200_000]):
        raw = m.group(1) or m.group(2) or ""
        if raw and not raw.lower().startswith(("javascript:", "#")):
            candidates.append(urljoin(base_url, raw))

    best, best_score = "", 0
    seen = set()
    for url in candidates:
        url = url.strip().rstrip(").,;\"'")
        if not url or url in seen or url == base_url:
            continue
        seen.add(url)
        score = _portal_link_score(url)
        if score > best_score:
            best, best_score = url, score
    return best if best_score >= 3 else ""


# ===========================================================================
# 4b. 锐捷 ePortal 直连接口
# ===========================================================================
# 页面 JS（login_bch.js + AuthInterFace.js）最终就是发这个请求：
#   POST {portal}/InterFace.do?method=login
#   userId / password / service / queryString / operatorPwd /
#   operatorUserId / validcode / passwordEncrypt
# 密码先用页面里的 RSA 公钥加密（security.js 那套老实现），
# 所以只要复刻加密算法，就能完全跳过浏览器。

# 网关明确说"账号/密码不对"时，别再自动重试（防止账号被锁）
_FATAL_AUTH_RE = re.compile(
    r"密码错误|密码不正确|用户名或密码|用户不存在|账号不存在|"
    r"PASSWORD[_ ]?ERROR|PWD[_ ]?ERROR|USER[_ ]?NOT[_ ]?FOUND|AUTH[_ ]?FAILED", re.I)


def _input_value(html: str, element_id: str) -> str:
    """取某个 <input id="..."> 的 value（不依赖属性顺序）。"""
    tag = re.search(
        rf"""<input\b[^>]*\bid=["']{re.escape(element_id)}["'][^>]*>""", html, re.I)
    if not tag:
        return ""
    value = re.search(r"""\bvalue=["']([^"']*)""", tag.group(0), re.I)
    return value.group(1) if value else ""


def _js_encode(value: str) -> str:
    """等价于 JS 的 encodeURIComponent（quote 默认会多编码 ! ' ( ) *）。"""
    return quote(str(value), safe="-_.!~*'()")


def ruijie_rsa_encrypt(text: str, exponent_hex: str, modulus_hex: str) -> str:
    """复刻锐捷 security.js 里的 RSAUtils.encryptedString。

    与标准 RSA 的差别（也是必须照抄的原因）：
      * 明文按 **小端 16 位字** 组成大整数（不是大端字节流）；
      * 分块长度 = 2 * 模数的最高 16 位字下标（1024 位密钥是 126 字节）；
      * 输出从高字到低字、每字 4 个十六进制字符（即标准大端 hex）。

    已用 Node 直接跑页面自带的 security.js 逐字节比对过，结果一致。
    """
    m = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    chunk = 2 * ((m.bit_length() - 1) // 16)
    if m <= 0 or e <= 0 or chunk <= 0:
        raise ValueError("无效的 RSA 公钥")
    data = [ord(ch) & 0xFF for ch in text]
    while len(data) % chunk:
        data.append(0)
    out: List[str] = []
    for i in range(0, len(data), chunk):
        block = 0
        for j in range(chunk // 2):
            block |= (data[i + 2 * j] | (data[i + 2 * j + 1] << 8)) << (16 * j)
        piece = format(pow(block, e, m), "x")
        if len(piece) % 4:
            piece = "0" * (4 - len(piece) % 4) + piece
        out.append(piece)
    return "".join(out)


# ===========================================================================
# 5. 网络检测器
# ===========================================================================
class NetworkChecker:
    """物理链路检测 + 主动连通性探测 + Portal 指纹识别。"""

    REDIRECT_CODES = (301, 302, 303, 307, 308)

    def __init__(self, cfg: Config):
        if requests is None:
            raise RuntimeError("缺少依赖 requests，请先执行: pip install -r requirements.txt")
        self.cfg = cfg
        self._session = requests.Session()
        # 上一次 check() 抓到的认证页正文，供认证流程复用（省一次 GET）
        self._last_portal_url = ""
        self._last_portal_html = ""
        # 唤醒后的"快重试"窗口里把超时压短，别让一次探测卡 3+5 秒
        self.fast_probe = False
        # 唤醒预认证：只用短超时，失败就下一轮，绝不让"抢跑"本身变成等待
        self.quick_auth = False
        # 关键：忽略系统代理。校园网/公司网络里的 HTTP_PROXY 会把探测请求导向代理，
        # 导致我们看不到 Portal 的重定向。
        if cfg.get("detect.ignore_system_proxy", True):
            self._session.trust_env = False
        self._session.headers.update({
            "User-Agent": cfg.get("detect.user_agent"),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            # 关键：锐捷 ePortal 会把 Content-Encoding 写成 "gzip  "（多个空格），
            # urllib3 认不出来就不解压，正文全是乱码，页面里的 RSA 公钥/服务名
            # 都读不到。直接要求不压缩，从根上绕开。
            "Accept-Encoding": "identity",
        })

    # ---- 物理链路 ---------------------------------------------------------
    def link_info(self, use_cache: bool = True) -> LinkInfo:
        """读取链路信息（带 3 秒缓存）。

        net_if_stats/net_if_addrs 单次约 12ms 且偶尔在 native 层崩溃，
        而 30 秒巡检里会连调多次（探测、保活、预认证），缓存能省掉大半开销。
        """
        if use_cache:
            now = time.monotonic()
            cached = getattr(self, "_link_cache", None)
            ttl = float(self.cfg.get("network.link_cache_seconds", 3.0))
            if cached and now - cached[0] < ttl:
                return cached[1]
        info = self._link_info_uncached()
        try:
            self._link_cache = (time.monotonic(), info)
        except Exception:
            pass
        return info

    def _link_info_uncached(self) -> LinkInfo:
        info = LinkInfo()
        if psutil is None:
            # 没有 psutil 时退化：只要本机拿得到出口 IP 就认为链路可用
            ip = self.local_outbound_ip()
            if ip:
                info.up = True
                info.interfaces = {"<unknown>": [ip]}
                info.primary_ip, info.primary_iface = ip, "<unknown>"
            return info

        ignore = [s.lower() for s in (self.cfg.get("network.ignore_interfaces") or [])]
        # 枚举网卡偶尔会在 native 层崩（crash.log 里见过 psutil net_if_stats 的
        # access violation）。连续失败 3 次就暂时停用枚举，只用出口 IP 判定，
        # 避免在坏掉的接口上空转。
        if getattr(self, "_enum_fail_streak", 0) >= 3:
            ip = self.local_outbound_ip()
            if ip:
                info.up, info.primary_ip = True, ip
                info.interfaces = {"<fallback>": [ip]}
                info.primary_iface = "<fallback>"
            return info
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            self._enum_fail_streak = 0
        except Exception as exc:
            self._enum_fail_streak = getattr(self, "_enum_fail_streak", 0) + 1
            LOG.debug("读取网卡信息失败(%s次): %s", self._enum_fail_streak, exc)
            ip = self.local_outbound_ip()
            if ip:
                info.up, info.primary_ip = True, ip
                info.primary_iface = "<fallback>"
            return info

        for name, st in stats.items():
            if not getattr(st, "isup", False):
                continue
            low = name.lower()
            if any(pat in low for pat in ignore):
                continue
            ips: List[str] = []
            for a in addrs.get(name, []):
                if a.family != socket.AF_INET:
                    continue
                addr = a.address or ""
                # 排除回环与自动私有地址（169.254.x.x 意味着 DHCP 没拿到地址）
                if addr.startswith("127.") or addr.startswith("169.254."):
                    continue
                ips.append(addr)
            if ips:
                info.interfaces[name] = ips

        info.up = bool(info.interfaces)
        if info.up:
            outbound = self.local_outbound_ip()
            if outbound:
                info.primary_ip = outbound
                for name, ips in info.interfaces.items():
                    if outbound in ips:
                        info.primary_iface = name
                        break
            if not info.primary_iface:
                info.primary_iface = next(iter(info.interfaces))
                info.primary_ip = info.primary_ip or info.interfaces[info.primary_iface][0]
        return info

    @staticmethod
    def local_outbound_ip() -> str:
        """通过 UDP socket "连" 一个公网地址来获取本机默认出口 IP（不会真的发包）。"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except Exception:
            return ""
        finally:
            if sock:
                sock.close()

    # ---- 网卡健康 ---------------------------------------------------------
    def stale_ipv4_interfaces(self, quiet_seconds: float = 120.0) -> List[Dict[str, str]]:
        """列出"有自动私有地址(169.254.x.x)且没有正常 IPv4"的网卡。

        这类网卡说明 DHCP 没拿到租约（常见于休眠后 Wi-Fi 驱动没重连上），
        它们不会进 link_info()，但会挂在系统里影响路由选择、拖慢 DNS，
        也是"僵尸网卡"的来源。返回 [{'name': ..., 'ip': ...}]，供 --fix-adapters 使用。
        """
        if psutil is None:
            return []
        ignore = [s.lower() for s in (self.cfg.get("network.ignore_interfaces") or [])]
        result: List[Dict[str, str]] = []
        now = time.time()
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
        except Exception:
            return []
        for name, st in stats.items():
            if any(pat in name.lower() for pat in ignore):
                continue
            ipv4 = [a.address for a in addrs.get(name, [])
                    if a.family == socket.AF_INET]
            good = [a for a in ipv4
                    if not a.startswith("127.") and not a.startswith("169.254.")]
            apipa = [a for a in ipv4 if a.startswith("169.254.")]
            if not apipa or good:
                continue
            isup = bool(getattr(st, "isup", False))
            # 网卡没启用却还挂着 169.254：属于系统残留地址（Tentative），
            # 不影响当前联网，但会让网卡列表/路由判断变脏，清掉即可。
            if not isup:
                result.append({"name": name, "ip": apipa[0], "reason": "stale"})
                continue
            # 刚醒来 2 分钟内的 169.254 属于正常过渡（DHCP 还在协商），不当异常报
            if now - getattr(st, "last_change", 0) < quiet_seconds:
                continue
            result.append({"name": name, "ip": apipa[0], "reason": "dhcp_failed"})
        return result

    @staticmethod
    def dns_ok(host: str = "www.msftconnecttest.com") -> bool:
        try:
            socket.getaddrinfo(host, 80)
            return True
        except Exception:
            return False

    # ---- HTTP 探测 --------------------------------------------------------
    def _timeout(self) -> Tuple[float, float]:
        if getattr(self, "quick_auth", False):
            # 网关在本地网段（10.10.9.9），正常 100ms 内就响应；
            # 唤醒瞬间 DNS 刚起来，1s 连 / 1.5s 读足够重试很多轮
            return (1.0, 1.5)
        if getattr(self, "fast_probe", False):
            return (1.0, 2.0)
        return (float(self.cfg.get("detect.connect_timeout", 3)),
                float(self.cfg.get("detect.read_timeout", 5)))

    @staticmethod
    def _body_text(resp) -> str:
        """取响应正文，顺手处理网关的"畸形 gzip"。

        锐捷 ePortal 的 Content-Encoding 写成 "gzip  "（带尾随空格），
        urllib3 认不出来就不会解压，resp.text 直接是压缩后的乱码 ——
        之前读不到页面里的 RSA 公钥、服务名，就是这里造成的。
        """
        raw = resp.content or b""
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        # 编码以响应头为准，不用 requests 推断出来的（没有 charset 时它会猜成 ISO-8859-1）
        for enc in ((getattr(resp, "encoding", None) or "").strip(), "utf-8", "gb18030"):
            if not enc:
                continue
            try:
                return raw.decode(enc)
            except (LookupError, UnicodeDecodeError):
                continue
        return raw.decode("utf-8", "replace")

    # ---- 瞬时故障判定（唤醒预认证用）-------------------------------------
    @staticmethod
    def _is_transient_error_text(text: str) -> bool:
        """这个错误是"网络还没就绪"（DNS 没起来 / 连不上 / 超时），不是配置或密码错。

        唤醒瞬间最常见的就是 getaddrinfo failed：此时 fast_probe 的 1s 超时还不够
        DNS 服务起来，整体会很快判 unknown —— 那种情况值得多抢几轮。
        """
        t = (text or "").lower()
        return any(k in t for k in (
            "name or service not known", "getaddrinfo", "name resolution",
            "temporary failure in name resolution", "failed to resolve",
            "connection refused", "connection aborted", "connection reset",
            "timed out", "timeout", "no route to host", "network is unreachable",
            "proxy error", "remote end closed", "errno 10061", "errno 11001",
        ))

    def quick_probe_ip(self) -> str:
        """极短超时（1s 连 / 1.5s 读）探测一次，返回 "ok" / "portal" / "transient"。

        唤醒后专用：不等 DNS、不抓认证页、不算指纹，只回答"现在到底通不通"。
        urllib3 的 DNS 解析不受 timeout 限制，所以用一个非阻塞 socket 先问 DNS；
        解析不出来就直接算 transient，立刻去抢认证，不白等。
        """
        target = None
        for t in (self.cfg.get("detect.probe_targets") or []):
            if t.get("url") and str(t.get("url")).startswith("http://"):
                target = t
                break
        if target is None:
            return "transient"
        try:
            host = (urlparse(target["url"]).hostname or "")
            if host and not re.fullmatch(r"[0-9.]+", host):
                ip = socket.gethostbyname(host)
                if not ip:
                    return "transient"
        except Exception:
            return "transient"           # DNS 还没就绪
        try:
            res = self.probe_target(target, fetch_portal=False, timeout=(1.0, 1.5))
        except Exception:
            return "transient"
        return "ok" if res.kind == "ok" else "portal"

    def probe_target(self, target: Dict[str, Any], fetch_portal: bool = True,
                     timeout: Optional[Tuple[float, float]] = None) -> ProbeResult:
        """探测单个目标，判定：ok / portal / error。

        fetch_portal=False 时不做"跟随跳转 + 抓认证页"（用于认证后的快速验证）。
        timeout 可覆盖本次超时（唤醒后抢跑时用更短的）。
        """
        name = target.get("name") or target.get("url") or "?"
        url = target["url"]
        expect_status = target.get("expect_status")
        expect_contains = target.get("expect_contains", "")
        res = ProbeResult(target=name, url=url)
        started = time.time()
        try:
            resp = self._session.get(url, timeout=timeout or self._timeout(),
                                     allow_redirects=False)
        except Exception as exc:
            res.kind = "error"
            res.elapsed_ms = int((time.time() - started) * 1000)
            res.detail = f"{type(exc).__name__}: {exc}"
            return res

        res.status_code = resp.status_code
        res.elapsed_ms = int((time.time() - started) * 1000)

        # 情况 A：被重定向 -> 几乎可以确定是 Portal
        if resp.status_code in self.REDIRECT_CODES:
            res.kind = "portal"
            res.redirect_chain = [resp.url]
            res.final_url = self._follow_redirects(resp, res.redirect_chain) if fetch_portal else resp.url
            res.detail = f"HTTP {resp.status_code} -> {res.final_url}"
            if fetch_portal and self.cfg.get("detect.probe_portal_page", True):
                html = self._fetch_portal_page(res.final_url)
                res.body_html = html
                res.body_sample = html[:4000]
            return res

        body = self._body_text(resp)

        # 情况 B：状态码不符（例如期望 204 却拿到 200 的认证页）
        if expect_status is not None and resp.status_code != expect_status:
            res.kind = "portal"
            res.final_url = resp.url
            res.detail = f"期望 HTTP {expect_status}，实际 {resp.status_code}（疑似认证页）"
            res.body_html = body
            res.body_sample = body[:4000]
            return res

        # 情况 C：内容不符（例如期望 "Microsoft Connect Test" 却拿到登录页）
        if expect_contains and expect_contains not in body:
            res.kind = "portal"
            res.final_url = resp.url
            res.detail = f"响应内容不含预期关键字 {expect_contains!r}"
            res.body_html = body
            res.body_sample = body[:4000]
            return res

        # 情况 D：通过
        res.kind = "ok"
        res.final_url = resp.url
        res.detail = f"HTTP {resp.status_code} OK"
        return res

    def _follow_redirects(self, resp: "requests.Response", chain: List[str]) -> str:
        """手动跟随重定向，抓取最终的认证页地址（限制跳数，避免环路）。"""
        final = resp
        max_hops = int(self.cfg.get("detect.portal_max_hops", 5))
        for _ in range(max_hops):
            location = final.headers.get("Location")
            if not location:
                break
            nxt = urljoin(final.url, location)
            if nxt in chain:
                break
            chain.append(nxt)
            try:
                final = self._session.get(nxt, timeout=self._timeout(), allow_redirects=False)
            except Exception:
                break
            if final.status_code not in self.REDIRECT_CODES:
                break
        return chain[-1] if chain else resp.url

    def _fetch_portal_page(self, url: str) -> str:
        if not url:
            return ""
        limit = int(self.cfg.get("detect.probe_portal_page_max_bytes", 256 * 1024))
        try:
            resp = self._session.get(url, timeout=self._timeout(), allow_redirects=True)
            return self._body_text(resp)[:limit]
        except Exception as exc:
            LOG.debug("抓取认证页失败 %s: %s", url, exc)
            return ""

    # ---- 综合判定 ---------------------------------------------------------
    def is_online(self) -> bool:
        """轻量判定：只跑探测目标，不抓认证页、不做指纹。

        认证流程里每秒轮询一次时用它，避免每次都重复抓取/解析整个门户页
        （那会把"从探测响应中定位到认证页"刷满日志，还拖慢验证）。
        """
        for target in (self.cfg.get("detect.probe_targets") or []):
            try:
                res = self.probe_target(target, fetch_portal=False)
            except Exception:
                continue
            if res.kind == "ok":
                return True
        return False

    def check(self) -> NetStatus:
        status = NetStatus(checked_at=now_iso())
        link = self.link_info()
        status.interface = link.primary_iface
        status.local_ip = link.primary_ip

        # 区分"未连接"与"需要认证"的第一步：链路层
        if not link.up:
            status.state = NetState.LINK_DOWN
            status.detail = "没有可用网卡/网线未连接"
            status.local_ip = ""
            status.interface = ""
            return status
        if not link.has_ip:
            status.state = NetState.NO_IP
            status.detail = "网卡已启用但未获取到有效 IP（DHCP 可能未完成）"
            return status

        portal_result: Optional[ProbeResult] = None
        errors: List[ProbeResult] = []
        for target in (self.cfg.get("detect.probe_targets") or []):
            res = self.probe_target(target)
            status.probes.append({
                "target": res.target, "kind": res.kind, "status": res.status_code,
                "final_url": res.final_url, "elapsed_ms": res.elapsed_ms, "detail": res.detail,
            })
            if res.kind == "ok":
                # 任意一个目标通过就认为"能上网"
                status.state = NetState.INTERNET_OK
                status.detail = f"探测通过: {res.target} ({res.elapsed_ms} ms)"
                return status
            if res.kind == "portal" and portal_result is None:
                portal_result = res
            if res.kind == "error":
                errors.append(res)

        if portal_result is not None:
            status.state = NetState.PORTAL_REQUIRED
            status.portal_url = portal_result.final_url or portal_result.url
            status.detail = portal_result.detail
            html = portal_result.body_html or portal_result.body_sample
            if not html and self.cfg.get("detect.probe_portal_page", True):
                html = self._fetch_portal_page(status.portal_url)
            # 探测地址常常只是"中间页"：正文里才有带 wlanuserip/mac 的
            # 真实 ePortal 地址。还原它，Selenium 点按钮时才不会缺参数。
            if _portal_link_score(status.portal_url) < 3:
                better = extract_portal_link(status.portal_url, html)
                if better:
                    LOG.info("从探测响应中定位到认证页: %s", better)
                    status.portal_url = better
                    if self.cfg.get("detect.probe_portal_page", True):
                        html = self._fetch_portal_page(better) or html
                    status.detail += " | 已定位认证页"
            status.fingerprint = guess_vendor(status.portal_url, html)
            status.fingerprint.portal_url = status.portal_url
            self._last_portal_url = status.portal_url
            self._last_portal_html = html
            return status

        status.state = NetState.UNKNOWN
        if errors:
            status.detail = "所有探测目标均失败: " + "; ".join(
                f"{e.target}({e.detail})" for e in errors[:3]
            )
            if not self.dns_ok():
                status.detail += " | DNS 解析失败"
        else:
            status.detail = "未配置有效的探测目标"
        return status


# ===========================================================================
# 6. 认证触发器（打开浏览器 / HTTP 戳 / 自动填表登录）
# ===========================================================================
class AuthTrigger:
    def __init__(self, cfg: Config, checker: NetworkChecker, stats: Optional["StatsStore"] = None):
        self.cfg = cfg
        self.checker = checker
        self.stats = stats
        self._last_browser_at: float = 0.0
        self._last_browser_url: str = ""
        self.attempts = 0
        self.successes = 0
        # 自动点击（Selenium）
        self.autoclicker = None
        self._autoclick_init_failed = False
        self._autoclick_fail_streak = 0
        self._autoclick_disabled_until = 0.0
        # 账号密码被网关明确拒绝时（密码错误等），一段时间内不再自动尝试，
        # 避免反复登录把校园网账号锁掉。
        self._auth_disabled_until = 0.0

    # ---- 自动点击引擎 -----------------------------------------------------
    def _get_autoclicker(self):
        if portal_autoclick is None or self._autoclick_init_failed:
            return None
        if not self.cfg.get("browser_automation.enabled", True):
            return None
        if str(self.cfg.get("browser_automation.engine", "auto")).lower() == "off":
            return None
        if self.autoclicker is None:
            try:
                self.autoclicker = portal_autoclick.PortalAutoClicker(self.cfg)
            except Exception as exc:
                LOG.warning("初始化自动点击引擎失败，将退回打开浏览器: %s", exc)
                self._autoclick_init_failed = True
                return None
        return self.autoclicker

    def selenium_click(self, status: NetStatus) -> bool:
        """用浏览器自动化勾选条款并点击"连接/登录"，返回是否确认恢复联网。"""
        if time.time() < self._autoclick_disabled_until:
            return False
        clicker = self._get_autoclicker()
        if clicker is None:
            return False
        if not clicker.available:
            reason = clicker.unavailable_reason()
            if reason:
                LOG.debug("自动点击不可用: %s", reason)
            return False
        if not status.portal_url:
            return False

        result = None
        try:
            result = clicker.click(
                status.portal_url,
                verify=lambda: self.checker.is_online(),
            )
        except Exception as exc:
            LOG.warning("自动点击过程异常: %s", exc)

        ok = bool(result and result.success)
        if self.stats:
            try:
                self.stats.add_autoclick_result(ok)
            except Exception:
                pass

        if ok:
            self._autoclick_fail_streak = 0
            if result.clicked:
                LOG.info("自动点击完成认证：点击了「%s」，勾选 %d 项，用时 %.1fs",
                         result.clicked_text, len(result.checkboxes or []), result.duration)
            else:
                LOG.info("网络已恢复（自动点击未点到按钮，可能由页面跳转或人工完成，用时 %.1fs）",
                         result.duration)
            return True

        # 失败：记录原因、递增退避
        self._autoclick_fail_streak += 1
        if result:
            if result.clicked:
                LOG.warning("已点击「%s」但未确认联网（可能需要人工确认或页面需要验证码）",
                            result.clicked_text)
            elif result.error:
                LOG.warning("自动点击失败: %s", result.error)
            if result.screenshot:
                LOG.info("诊断截图: %s", result.screenshot)
            if result.html_dump:
                LOG.info("页面快照: %s", result.html_dump)
        threshold = int(self.cfg.get("browser_automation.failure_threshold", 3))
        if self._autoclick_fail_streak >= threshold:
            cooldown = float(self.cfg.get("browser_automation.failure_cooldown", 600))
            self._autoclick_disabled_until = time.time() + cooldown
            self._autoclick_fail_streak = 0
            LOG.warning("自动点击连续失败 %d 次，暂停 %.0f 秒（期间只用浏览器触发兜底）",
                        threshold, cooldown)
        return False

    # ---- 打开浏览器 -------------------------------------------------------
    def open_browser(self, portal_url: str, force: bool = False) -> bool:
        if not self.cfg.get("auth.open_browser", True):
            return False
        cooldown = float(self.cfg.get("auth.browser_cooldown", 90))
        now = time.time()
        if not force:
            same_url = portal_url == self._last_browser_url
            if same_url and (now - self._last_browser_at) < cooldown:
                LOG.debug("浏览器冷却中（%ss 内已打开过同一认证页）", cooldown)
                return False
        try:
            # 用默认浏览器打开 —— 大多数 Portal 需要浏览器执行 JS 才能完成认证
            webbrowser.open(portal_url, new=2, autoraise=True)
            self._last_browser_at = now
            self._last_browser_url = portal_url
            LOG.info("已打开默认浏览器访问认证页: %s", portal_url)
            return True
        except Exception as exc:
            LOG.warning("打开浏览器失败: %s", exc)
            return False

    # ---- HTTP 戳 ---------------------------------------------------------
    def poke_portal(self, portal_url: str) -> bool:
        """主动 GET 认证页：部分 Portal 收到请求就会下发重定向/建立会话，
        这一步往往等价于"用户在浏览器里打开了一次网页"。"""
        if not self.cfg.get("auth.http_probe_portal", True) or not portal_url:
            return False
        try:
            resp = self.checker._session.get(portal_url, timeout=self.checker._timeout(),
                                            allow_redirects=True)
            LOG.info("已主动请求认证页: HTTP %s, %d 字节", resp.status_code, len(resp.content or b""))
            return True
        except Exception as exc:
            LOG.debug("请求认证页失败: %s", exc)
            return False

    # ---- 自动填表登录 -----------------------------------------------------
    def _build_form_data(self, fingerprint: Optional[Fingerprint], portal_url: str) -> Dict[str, str]:
        al = self.cfg.get("auth.auto_login") or {}
        user = str(al.get("username") or "")
        pwd = str(al.get("password") or "")
        user_kw = [k.lower() for k in (al.get("username_field_keywords") or [])]
        pwd_kw = [k.lower() for k in (al.get("password_field_keywords") or [])]

        data: Dict[str, str] = {}
        form = fingerprint.login_form if fingerprint else None
        if form:
            for f in form.fields:
                name = f.get("name", "")
                low = name.lower()
                ftype = (f.get("type") or "").lower()
                if ftype in ("checkbox", "radio") and not f.get("checked"):
                    continue          # 未勾选的复选框不要提交
                if ftype == "password" or any(k in low for k in pwd_kw):
                    data[name] = pwd
                elif any(k in low for k in user_kw):
                    data[name] = user
                elif f.get("value"):
                    # 隐藏域（如 lt / execution / nasip）必须原样回传
                    data[name] = f["value"]

            # 提交按钮的 name/value：不少 Portal 会校验"是哪个按钮提交的"，
            # 漏掉它就会一直返回"请点击连接"。
            for f in form.fields:
                if (f.get("type") in ("submit", "button", "image")) and f.get("name"):
                    data.setdefault(f["name"], f.get("value") or "")

        # 补上 URL 查询参数里的 Portal 协议字段（srun / ruijie 等常见要求）
        try:
            for key, value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^&#]*)", urlparse(portal_url).query or ""):
                if key.lower() in PORTAL_URL_PARAM_HINTS and key not in data:
                    data[key] = value
        except Exception:
            pass

        data.update({str(k): str(v) for k, v in (al.get("extra_fields") or {}).items()})
        return data

    def _ruijie_page_info(self, portal_url: str, query: str) -> Dict[str, Any]:
        """调用锐捷 InterFace.do?method=pageInfo，拿 RSA 公钥等页面信息。

        页面加载后本来就会调这个接口（静态 HTML 里的公钥可能是空的），
        返回 JSON 里带 publicKeyExponent / publicKeyModulus / passwordEncrypt /
        validCodeUrl / prefixValue。请求格式与页面一致：queryString 双重编码。
        """
        url = urljoin(portal_url, "InterFace.do?method=pageInfo")
        body = "queryString=" + _js_encode(_js_encode(query))
        try:
            resp = self.checker._session.post(
                url, data=body.encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Referer": portal_url,
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=self.checker._timeout(), allow_redirects=False)
        except Exception as exc:
            LOG.debug("锐捷 pageInfo 请求失败: %s", exc)
            return {}
        try:
            info = json.loads((resp.content or b"").decode("utf-8", "replace"))
        except Exception:
            LOG.debug("锐捷 pageInfo 返回不是 JSON: %s",
                      (resp.content or b"")[:80].decode("utf-8", "replace"))
            return {}
        return info if isinstance(info, dict) else {}

    def ruijie_login(self, status: NetStatus, verify_seconds: Optional[float] = None,
                     assume_success: bool = False) -> bool:
        """锐捷 ePortal：直接 POST InterFace.do?method=login。

        复刻页面 doauthen() 的请求（含 RSA 密码加密），约 1 秒完成，
        不需要启动浏览器，也不用等页面渲染。失败时静默返回 False，
        后面还有 Selenium 自动点击兜底。

        verify_seconds: 覆盖"提交后等联网"的秒数（唤醒预认证时用短的）。
        assume_success: 网关返回 success 就直接算成功（唤醒后 DNS 往往还没好）。
        """
        al = self.cfg.get("auth.auto_login") or {}
        if not al.get("enabled") or not al.get("username") or not al.get("password"):
            return False
        if time.time() < self._auth_disabled_until:
            return False
        if not status.portal_url:
            return False
        vendor = (status.fingerprint.vendor if status.fingerprint else "") or ""
        if vendor != "ruijie":
            return False
        # 用户明确关掉"用配置的账号密码"时，不能偷偷用
        if not self.cfg.get("browser_automation.fill_credentials", True):
            return False

        portal_url = status.portal_url
        # check() 刚刚抓过就用缓存，避免认证时再 GET 一次
        html = ""
        if getattr(self.checker, "_last_portal_url", "") == portal_url:
            html = getattr(self.checker, "_last_portal_html", "")
        if not html:
            html = self.checker._fetch_portal_page(portal_url)
        if not html:
            return False

        # 页面用隐藏域 passwordEncrypt 决定密码是否要 RSA 加密（默认 true）
        encrypt = (_input_value(html, "passwordEncrypt").strip().lower() or "true")
        query = urlparse(portal_url).query or ""
        mac = "111111111"
        for part in query.split("&"):
            if part.lower().startswith("mac="):
                mac = part[4:] or mac
                break
        username = str(al.get("username") or "").strip()
        # 服务名（页面隐藏域 net_access_type，例如 "shu"）：漏掉它网关会认为
        # 登录的服务不对，直接返回失败。
        service = _input_value(html, "net_access_type")
        if not service:
            # 有些页面这个隐藏域是 JS 在 pageInfo 之后才填的；服务列表里
            # 第一项就是默认的"校园网"。
            m = re.search(r"""selectService\(\s*["']([^"']+)["']""", html)
            if m:
                service = m.group(1)
                LOG.debug("锐捷服务名从服务列表推断: %s", service)
        exponent = _input_value(html, "publicKeyExponent")
        modulus = _input_value(html, "publicKeyModulus")
        if not (exponent and modulus):
            # 页面静态 HTML 里公钥有时是空的（由 JS 调 pageInfo 后填入），
            # 这时直接问接口要，别急着退回浏览器。
            info = self._ruijie_page_info(portal_url, query)
            exponent = str(info.get("publicKeyExponent") or "")
            modulus = str(info.get("publicKeyModulus") or "")
            flag = str(info.get("passwordEncrypt") or "").lower()
            if flag in ("true", "false"):
                encrypt = flag
            if info.get("validCodeUrl"):
                LOG.info("锐捷认证页要求验证码，改用浏览器自动点击")
                return False
        if encrypt == "true":
            if not (exponent and modulus):
                LOG.warning("锐捷页面未提供 RSA 公钥（pageInfo 也没有），改用浏览器自动点击")
                return False
            try:
                encrypted = ruijie_rsa_encrypt(
                    f"{al.get('password')}>{mac}"[::-1], exponent, modulus)
            except Exception as exc:
                LOG.warning("锐捷密码加密失败: %s", exc)
                return False
        else:
            encrypted = str(al.get("password") or "")

        body = (
            f"userId={_js_encode(_js_encode(username))}"
            f"&password={_js_encode(_js_encode(encrypted))}"
            f"&service={_js_encode(_js_encode(service))}"
            f"&queryString={_js_encode(_js_encode(query))}"
            f"&operatorPwd=&operatorUserId=&validcode="
            f"&passwordEncrypt={_js_encode(_js_encode(encrypt))}"
        )
        url = urljoin(portal_url, "InterFace.do?method=login")
        parsed = urlparse(portal_url)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": portal_url,
            "Origin": f"{parsed.scheme}://{parsed.netloc}",
            "X-Requested-With": "XMLHttpRequest",
        }
        try:
            resp = self.checker._session.post(
                url, data=body.encode("utf-8"), headers=headers,
                timeout=self.checker._timeout(), allow_redirects=False)
            text = self.checker._body_text(resp)
        except Exception as exc:
            LOG.warning("锐捷直连登录请求失败: %s", exc)
            return False

        if "已在线" in text or "already online" in text.lower():
            LOG.info("锐捷直连：网关提示账号已在线，视为已认证")
            return True

        if not re.search(r"""["']?result["']?\s*:\s*["']?success""", text):
            msg = re.search(r"""message\s*:\s*["']([^"']{0,120})""", text)
            detail = msg.group(1) if msg else text[:120].replace("\n", " ")
            if _FATAL_AUTH_RE.search(detail):
                cooldown = float(al.get("fail_cooldown", 1800))
                self._auth_disabled_until = time.time() + cooldown
                LOG.error("锐捷直连登录被拒绝（%s）。%.0f 分钟内不再自动尝试，"
                          "请检查 config.yaml 里的账号密码，避免账号被锁", detail, cooldown)
            else:
                LOG.warning("锐捷直连登录未成功: HTTP %s %s", resp.status_code, detail)
            return False

        if assume_success:
            LOG.info("锐捷直连登录已被网关接受（唤醒预认证，不等 DNS 验证）")
            return True

        LOG.info("锐捷直连登录已提交（HTTP %s），等待网络恢复...", resp.status_code)
        timeout = (float(verify_seconds) if verify_seconds is not None
                   else min(float(al.get("verify_timeout", 25)), 12.0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.checker.is_online():
                LOG.info("锐捷直连登录成功，网络已恢复")
                return True
            time.sleep(1.0)
        LOG.warning("锐捷直连登录返回成功，但 %.0f 秒内仍未联网", timeout)
        return False

    def auto_login(self, status: NetStatus) -> bool:
        """尝试用配置的账号密码自动登录，然后验证是否真的联网成功。"""
        al = self.cfg.get("auth.auto_login") or {}
        if not al.get("enabled"):
            return False
        if not al.get("username") or not al.get("password"):
            LOG.warning("已启用自动登录但未配置用户名/密码，跳过")
            return False
        if time.time() < self._auth_disabled_until:
            return False
        if not status.portal_url:
            return False

        target = status.portal_url
        form = status.fingerprint.login_form if status.fingerprint else None
        vendor = (status.fingerprint.vendor if status.fingerprint else "") or ""
        # 锐捷 ePortal（index.jsp + doauthen）的认证由页面 JS 完成；
        # 页面上的表单多半是隐藏的初始化表单（如 validateHaijun.do），
        # 把账号密码 POST 过去既无效、又可能触发风控，直接交给自动点击。
        if vendor == "ruijie" and not (al.get("extra_fields") or {}):
            LOG.debug("锐捷 ePortal 由页面 JS(doauthen) 完成认证，跳过通用表单登录")
            return False
        method = "post"
        if form and form.action:
            target = urljoin(status.portal_url, form.action)
            method = form.method if form.method in ("get", "post") else "post"
        data = self._build_form_data(status.fingerprint, status.portal_url)

        # 没有表单、也没有手工配置的 extra_fields 时，POST 到认证页本身没有意义
        # （典型如 MAC 无感认证：页面上只有一个"连接"按钮）。
        # 直接跳过，把机会留给后面的"自动点击"，避免白等 verify_timeout 秒。
        if not (form and form.fields) and not (al.get("extra_fields") or {}):
            LOG.debug("认证页没有可提交的表单，跳过 HTTP 自动登录（交给自动点击）")
            return False

        LOG.info("尝试自动登录: %s %s（%d 个字段）", method.upper(), target, len(data))
        try:
            if method == "get":
                resp = self.checker._session.get(target, params=data,
                                                timeout=self.checker._timeout(), allow_redirects=True)
            else:
                resp = self.checker._session.post(target, data=data,
                                                  timeout=self.checker._timeout(), allow_redirects=True)
            LOG.info("登录请求已发送: HTTP %s", resp.status_code)
        except Exception as exc:
            LOG.warning("登录请求失败: %s", exc)
            return False

        # 提交后轮询验证，直到超时（用轻量探测，避免每次都重抓认证页）
        deadline = time.time() + float(al.get("verify_timeout", 25))
        while time.time() < deadline:
            time.sleep(1.0)
            if self.checker.is_online():
                LOG.info("自动登录成功，网络已恢复")
                return True
        LOG.warning("自动登录后仍无法联网（可能账号密码错误或页面需要 JS/验证码）")
        return False

    # ---- 统一入口 ---------------------------------------------------------
    def trigger(self, status: NetStatus, force_browser: bool = False) -> bool:
        """触发一次认证流程，返回是否"成功恢复联网"。"""
        self.attempts += 1
        portal_url = status.portal_url
        if not portal_url:
            LOG.warning("需要认证但未能获取认证页地址")
            return False

        vendor = status.fingerprint.vendor if status.fingerprint else "unknown"
        LOG.info("触发认证: 厂商=%s 置信度=%s URL=%s",
                 vendor, status.fingerprint.confidence if status.fingerprint else 0, portal_url)

        # 网关明确拒绝了账号密码：冷却期内什么都别做，避免把账号试锁
        if time.time() < self._auth_disabled_until:
            LOG.debug("账号密码之前被网关拒绝，冷却中，跳过自动认证")
            return False

        # 1) 锐捷 ePortal：直连接口最快（复刻页面 doauthen，~1 秒）
        if self.ruijie_login(status):
            self.successes += 1
            return True

        # 2) 其它 Portal：有账号密码时尝试通用表单登录（无需人工）
        if self.auto_login(status):
            self.successes += 1
            return True

        # 2) 自定义触发命令（例如调用 campus 专用脚本）
        for cmd in (self.cfg.get("auth.trigger_commands") or []):
            try:
                args = [str(x).format(portal_url=portal_url, state=status.state.value) for x in cmd]
                subprocess.Popen(args, shell=False,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                LOG.info("已执行自定义触发命令: %s", args)
            except Exception as exc:
                LOG.warning("自定义触发命令失败: %s", exc)

        # 3) 方案 A：浏览器自动化 —— 自动勾选条款 + 点击"连接/登录"
        #    这一步直接解决"浏览器打开了但按钮还要人手点"的问题。
        if self.selenium_click(status):
            self.successes += 1
            return True

        # 4) HTTP 戳一下认证页（很多 Portal 以此建立/刷新会话）
        self.poke_portal(portal_url)

        # 5) 最后兜底：打开浏览器（让用户点一下，或页面的 JS 自动完成认证）
        if self.open_browser(portal_url, force=force_browser):
            # 已经交给默认浏览器了：给用户/页面 JS 一点时间，别马上又拉起
            # 自动化窗口去抢操作（之前就是这样和用户的手动登录撞在一起的）。
            self._autoclick_disabled_until = time.time() + float(
                self.cfg.get("auth.browser_cooldown", 90))
        return False


# ===========================================================================
# 7. 唤醒 / 休眠检测
# ===========================================================================
class WindowsPowerMonitor(threading.Thread):
    """Windows 下通过监听 WM_POWERBROADCAST 消息捕获休眠/唤醒事件。

    WM_POWERBROADCAST 是系统广播给所有顶层窗口的，因此只要创建一个隐藏的顶层窗口
    并在消息循环里接收即可，无需注册电源设置通知，也不需要管理员权限。
    """

    WM_DESTROY = 0x0002
    WM_CLOSE = 0x0010
    WM_POWERBROADCAST = 0x0218
    PBT_APMSUSPEND = 0x0004
    PBT_APMRESUMESUSPEND = 0x0007
    PBT_APMRESUMEAUTOMATIC = 0x0012

    def __init__(self, on_suspend=None, on_resume=None):
        super().__init__(name="win-power-monitor", daemon=True)
        self.on_suspend = on_suspend
        self.on_resume = on_resume
        self.available = platform.system() == "Windows"
        self.failed = False
        self._hwnd = None
        self._wndproc_ref = None     # 必须保留引用，否则回调会被 GC 回收导致崩溃

    def run(self) -> None:  # pragma: no cover - 平台相关
        if not self.available:
            return
        try:
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            # 必须显式声明 argtypes：lparam 是 64 位整数/指针，
            # 否则 ctypes 会按 C int 转换并抛 OverflowError。
            user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                              wintypes.WPARAM, wintypes.LPARAM]
            user32.DefWindowProcW.restype = ctypes.c_ssize_t
            user32.RegisterClassW.argtypes = [ctypes.c_void_p]
            user32.RegisterClassW.restype = wintypes.ATOM
            user32.CreateWindowExW.argtypes = [
                wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p,
            ]
            user32.CreateWindowExW.restype = wintypes.HWND
            user32.DestroyWindow.argtypes = [wintypes.HWND]
            user32.PostQuitMessage.argtypes = [ctypes.c_int]
            user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                            wintypes.WPARAM, wintypes.LPARAM]
            user32.GetMessageW.argtypes = [ctypes.c_void_p, wintypes.HWND,
                                           wintypes.UINT, wintypes.UINT]
            user32.DispatchMessageW.argtypes = [ctypes.c_void_p]
            user32.TranslateMessage.argtypes = [ctypes.c_void_p]

            WNDPROC = ctypes.WINFUNCTYPE(
                ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                wintypes.WPARAM, wintypes.LPARAM,
            )

            def _wndproc(hwnd, msg, wparam, lparam):
                try:
                    if msg == self.WM_POWERBROADCAST:
                        if wparam in (self.PBT_APMRESUMEAUTOMATIC, self.PBT_APMRESUMESUSPEND):
                            LOG.debug("收到系统唤醒广播 (wparam=0x%X)", wparam)
                            if self.on_resume:
                                self.on_resume()
                        elif wparam == self.PBT_APMSUSPEND:
                            LOG.debug("收到系统休眠广播")
                            if self.on_suspend:
                                self.on_suspend()
                        return 1  # TRUE：已处理该电源事件
                    if msg == self.WM_CLOSE:
                        user32.DestroyWindow(hwnd)
                        return 0
                    if msg == self.WM_DESTROY:
                        user32.PostQuitMessage(0)
                        return 0
                    return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
                except Exception as exc:      # 绝不能让异常穿透 ctypes 回调
                    LOG.debug("电源窗口过程异常: %s", exc)
                    return 0

            wndproc = WNDPROC(_wndproc)
            self._wndproc_ref = wndproc

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", wintypes.UINT),
                    ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE),
                    ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", wintypes.LPCWSTR),
                    ("lpszClassName", wintypes.LPCWSTR),
                ]

            hinstance = kernel32.GetModuleHandleW(None)
            cls_name = f"{APP_NAME}PowerWnd_{os.getpid()}"
            wc = WNDCLASSW()
            wc.lpfnWndProc = wndproc
            wc.hInstance = hinstance
            wc.lpszClassName = cls_name
            if not user32.RegisterClassW(ctypes.byref(wc)):
                err = kernel32.GetLastError()
                if err != 1410:  # 1410 = 类已注册
                    raise ctypes.WinError(err)
            self._wc_ref = wc

            # 必须是普通顶层窗口（不能用 HWND_MESSAGE），否则收不到系统广播
            self._hwnd = user32.CreateWindowExW(
                0, cls_name, APP_NAME, 0, 0, 0, 0, 0, None, None, hinstance, None,
            )
            if not self._hwnd:
                raise ctypes.WinError(kernel32.GetLastError())
            LOG.debug("Windows 电源事件监听已启动 (hwnd=%s)", self._hwnd)

            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:
            self.failed = True
            LOG.warning("Windows 电源事件监听不可用（将改用时钟差值启发式）: %s", exc)

    def stop(self) -> None:
        try:
            if self._hwnd:
                ctypes.windll.user32.PostMessageW(self._hwnd, self.WM_CLOSE, 0, 0)
        except Exception:
            pass


class WakeWatcher:
    """统一封装"休眠/唤醒"检测：

    1. 平台增强：Windows 上监听 WM_POWERBROADCAST（最快、最准）。
    2. 通用兜底：时钟差值启发式。
       休眠时"墙钟时间(time.time)"会继续前进，而"单调时钟(time.monotonic)"
       通常不前进，两者差值超过阈值即判定发生过休眠；另外若两次 poll 之间的
       间隔远超预期周期，也说明进程被挂起过（Linux/容器里的常见情况）。
    """

    def __init__(self, expected_interval: float, skew_threshold: float = 5.0):
        self._lock = threading.Lock()
        self._events: collections.deque = collections.deque()
        self._last_wall = time.time()
        self._last_mono = time.monotonic()
        self._expected = max(float(expected_interval), 1.0)
        self._skew = float(skew_threshold)
        self._sleeping = False
        self.power = WindowsPowerMonitor(on_suspend=self._on_suspend, on_resume=self._on_resume)

    # 电源线程回调：只做入队，保持轻量
    def _on_suspend(self) -> None:
        self._push("suspend")

    def _on_resume(self) -> None:
        self._push("resume")

    def _push(self, event: str) -> None:
        with self._lock:
            self._events.append(event)

    def start(self) -> None:
        if self.power.available:
            self.power.start()

    def stop(self) -> None:
        self.power.stop()

    def poll(self) -> List[str]:
        with self._lock:
            events = list(self._events)
            self._events.clear()

        now_wall, now_mono = time.time(), time.monotonic()
        wall_delta = now_wall - self._last_wall
        mono_delta = now_mono - self._last_mono
        self._last_wall, self._last_mono = now_wall, now_mono

        threshold = max(self._skew, self._expected * 0.5)
        detected = ""
        # 墙钟比单调钟走得多 -> 期间发生过休眠
        if wall_delta - mono_delta > threshold:
            detected = f"时钟差值 {wall_delta - mono_delta:.1f}s"
        # 进程被冻结（mono 也一起被冻结的情况）
        elif mono_delta > self._expected * 4 + threshold:
            detected = f"巡检间隔异常 {mono_delta:.1f}s"

        if detected:
            LOG.info("检测到系统休眠/挂起（%s）", detected)
            if "suspend" not in events:
                events.append("suspend")
            if events[-1] != "resume":
                events.append("resume")
        return events


# ===========================================================================
# 8. 统计存储
# ===========================================================================
class StatsStore:
    """把在线时长、断连次数、认证结果、空闲超时样本持久化为 JSON。"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.enabled = bool(cfg.get("stats.enabled", True))
        self.path = cfg.resolve_path(cfg.get("app.stats_file", "data/stats.json"))
        self._lock = threading.Lock()
        self._last_save = 0.0
        self.data: Dict[str, Any] = self._empty()
        self._load()

    @staticmethod
    def _empty() -> Dict[str, Any]:
        return {
            "created_at": now_iso(),
            "totals": {
                "sessions": 0,
                "online_seconds": 0,
                "disconnects": 0,
                "idle_timeouts": 0,
                "auth_attempts": 0,
                "auth_success": 0,
                "auth_fail": 0,
                "wake_events": 0,
                "autoclick_attempts": 0,
                "autoclick_success": 0,
            },
            "sessions": [],       # 最近 N 次在线会话
            "idle_timeouts": [],  # 观测到的空闲超时样本（秒）
            "daily": {},          # "YYYY-MM-DD": {"online_seconds":.., "disconnects":..}
        }

    def _load(self) -> None:
        try:
            if self.path.exists():
                with self.path.open("r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    # 兼容旧版本：缺失键补默认值
                    base = self._empty()
                    deep_merge(base, loaded)
                    self.data = base
        except Exception as exc:
            LOG.warning("读取统计文件失败(%s)，将重建: %s", self.path, exc)

    def save(self, force: bool = False) -> None:
        """写盘。默认 5 秒限流；统计事件用 force=True，避免进程被结束时丢计数。"""
        if not self.enabled:
            return
        now = time.time()
        if not force and now - self._last_save < 5:
            return  # 限流，避免频繁写盘
        self._last_save = now
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            tmp.replace(self.path)   # 原子替换，避免断电写坏文件
        except Exception as exc:
            LOG.warning("保存统计失败: %s", exc)

    # ---- 写入接口 ---------------------------------------------------------
    def _bump(self, key: str, value: int = 1) -> None:
        self.data["totals"][key] = int(self.data["totals"].get(key, 0)) + value

    def add_session(self, start_ts: float, end_ts: float, reason: str,
                    vendor: str = "unknown", wake: bool = False) -> None:
        if not self.enabled:
            return
        seconds = max(0.0, end_ts - start_ts)
        record = {
            "start": iso_from_ts(start_ts),
            "end": iso_from_ts(end_ts),
            "seconds": round(seconds, 1),
            "duration": human_duration(seconds),
            "end_reason": reason,
            "portal_vendor": vendor,
            "after_wake": bool(wake),
        }
        with self._lock:
            self.data["sessions"].append(record)
            max_sessions = int(self.cfg.get("stats.max_sessions", 500))
            if len(self.data["sessions"]) > max_sessions:
                self.data["sessions"] = self.data["sessions"][-max_sessions:]
            self._bump("sessions")
            self.data["totals"]["online_seconds"] = round(
                float(self.data["totals"].get("online_seconds", 0)) + seconds, 1)
            day = iso_from_ts(start_ts)[:10]
            daily = self.data["daily"].setdefault(day, {"online_seconds": 0, "disconnects": 0})
            daily["online_seconds"] = round(float(daily.get("online_seconds", 0)) + seconds, 1)
        self.save(force=True)

    def add_idle_timeout(self, seconds: float) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.data["idle_timeouts"].append(round(float(seconds), 1))
            max_samples = int(self.cfg.get("stats.max_idle_samples", 200))
            if len(self.data["idle_timeouts"]) > max_samples:
                self.data["idle_timeouts"] = self.data["idle_timeouts"][-max_samples:]
            self._bump("idle_timeouts")
        self.save(force=True)

    def add_disconnect(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._bump("disconnects")
            day = now_iso()[:10]
            daily = self.data["daily"].setdefault(day, {"online_seconds": 0, "disconnects": 0})
            daily["disconnects"] = int(daily.get("disconnects", 0)) + 1
        self.save(force=True)

    def add_auth_result(self, success: bool) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._bump("auth_attempts")
            self._bump("auth_success" if success else "auth_fail")
        self.save(force=True)

    def add_wake_event(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._bump("wake_events")
        self.save(force=True)

    def add_autoclick_result(self, success: bool) -> None:
        """记录一次"自动点击"尝试（与 HTTP 自动登录分开统计）。"""
        if not self.enabled:
            return
        with self._lock:
            self._bump("autoclick_attempts")
            if success:
                self._bump("autoclick_success")
        self.save(force=True)

    # ---- 分析 -------------------------------------------------------------
    def analyze_timeouts(self) -> Dict[str, Any]:
        samples = [float(x) for x in (self.data.get("idle_timeouts") or [])]
        result: Dict[str, Any] = {
            "samples": len(samples),
            "min": None, "max": None, "median": None, "mean": None,
            "suggested_keepalive": None,
        }
        if not samples:
            return result
        result.update({
            "min": round(min(samples), 1),
            "max": round(max(samples), 1),
            "median": round(statistics.median(samples), 1),
            "mean": round(statistics.fmean(samples), 1),
        })
        # 取中位数打 6 折作为保活间隔，留足安全裕量
        if len(samples) >= int(self.cfg.get("timeout_analysis.min_samples", 3)):
            suggest = max(60.0, statistics.median(samples) * 0.6)
            result["suggested_keepalive"] = int(round(suggest / 10.0) * 10)
        return result

    def summary(self) -> Dict[str, Any]:
        totals = self.data.get("totals", {})
        sessions = self.data.get("sessions") or []
        durations = [float(s.get("seconds", 0)) for s in sessions]
        return {
            "totals": totals,
            "total_online": human_duration(float(totals.get("online_seconds", 0))),
            "session_count_recorded": len(sessions),
            "avg_session_seconds": round(statistics.fmean(durations), 1) if durations else 0,
            "longest_session_seconds": round(max(durations), 1) if durations else 0,
            "recent_sessions": sessions[-5:],
            "daily": self.data.get("daily", {}),
            "timeout_analysis": self.analyze_timeouts(),
        }


# ===========================================================================
# 9. 通知
# ===========================================================================
class Notifier:
    """跨平台系统通知：Windows(托盘气泡) / macOS(osascript) / Linux(notify-send)。"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.enabled = bool(cfg.get("notification.enabled", True))
        self._last_at: Dict[str, float] = {}
        self._fail_streak = 0

    def _cooldown_ok(self, key: str) -> bool:
        cooldown = float(self.cfg.get("notification.cooldown", 60))
        now = time.time()
        if now - self._last_at.get(key, 0.0) < cooldown:
            return False
        self._last_at[key] = now
        return True

    def notify(self, title: str, message: str, key: str = "default") -> None:
        if not self.enabled:
            return
        if not self._cooldown_ok(key):
            return
        LOG.info("通知: %s - %s", title, message)
        try:
            system = platform.system()
            if system == "Windows":
                self._notify_windows(title, message)
            elif system == "Darwin":
                self._notify_macos(title, message)
            else:
                self._notify_linux(title, message)
        except Exception as exc:
            LOG.debug("系统通知失败（忽略）: %s", exc)

    def on_success(self, state, seconds_ago: Optional[float] = None) -> None:
        if not self.cfg.get("notification.on_success", True):
            return
        self._fail_streak = 0
        extra = f"（中断 {human_duration(seconds_ago)}）" if seconds_ago else ""
        vendor = ""
        if state and getattr(state, "fingerprint", None):
            vendor = f" [{state.fingerprint.vendor}]"
        self.notify(f"{APP_NAME} 网络已恢复", f"自动认证成功，网络可用{vendor}{extra}", key="success")

    def on_failure(self, state) -> None:
        if not self.cfg.get("notification.on_failure", True):
            return
        self._fail_streak += 1
        threshold = int(self.cfg.get("notification.failure_threshold", 3))
        if self._fail_streak < threshold:
            return
        url = getattr(state, "portal_url", "") or ""
        if not url:
            detail = getattr(state, "detail", "")
            self.notify(f"{APP_NAME} 网络异常", f"连续 {self._fail_streak} 次未恢复: {detail[:120]}", key="failure")
        else:
            self.notify(
                f"{APP_NAME} 需要手动认证",
                f"无法自动完成认证，请打开浏览器登录。认证页: {url[:120]}",
                key="failure",
            )

    def on_wake(self) -> None:
        if not self.cfg.get("notification.on_wake", False):
            return
        self.notify(f"{APP_NAME}", "检测到系统唤醒，正在检查校园网认证状态", key="wake")

    # ---- 平台实现 ---------------------------------------------------------
    @staticmethod
    def _ps_escape(text: str) -> str:
        return text.replace("`", "``").replace('"', '`"').replace("$", "`$")

    def _notify_windows(self, title: str, message: str) -> None:
        if not self.cfg.get("notification.native_windows", True):
            return
        script = (
            '[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms");'
            '[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing");'
            '$n = New-Object System.Windows.Forms.NotifyIcon;'
            '$n.Icon = [System.Drawing.SystemIcons]::Information;'
            '$n.Visible = $true;'
            f'$n.ShowBalloonTip(8000, "{self._ps_escape(title)}", "{self._ps_escape(message)}", '
            '[System.Windows.Forms.ToolTipIcon]::Info);'
            'Start-Sleep -Milliseconds 9000;'
            '$n.Dispose();'
        )
        creationflags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = subprocess.CREATE_NO_WINDOW
        subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )

    def _notify_macos(self, title: str, message: str) -> None:
        def esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')
        subprocess.Popen(
            ["osascript", "-e",
             f'display notification "{esc(message)}" with title "{esc(title)}" sound name "Ping"'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _notify_linux(self, title: str, message: str) -> None:
        subprocess.Popen(
            ["notify-send", "-a", APP_NAME, "-u", "normal", title, message],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


# ===========================================================================
# 10. 单实例锁
# ===========================================================================
class SingleInstance:
    def __init__(self, path: Path):
        self.path = path
        self.acquired = False

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        if psutil is not None:
            try:
                return psutil.pid_exists(pid)
            except Exception:
                pass
        try:
            os.kill(pid, 0)   # POSIX
            return True
        except Exception:
            return False

    def acquire(self) -> bool:
        try:
            if self.path.exists():
                raw = self.path.read_text(encoding="utf-8").strip()
                pid = int(raw or 0)
                if pid and pid != os.getpid() and self._pid_alive(pid):
                    LOG.error("已有实例在运行 (pid=%s)，本次退出。锁文件: %s", pid, self.path)
                    return False
                LOG.debug("发现陈旧锁文件(pid=%s)，接管", pid)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(str(os.getpid()), encoding="utf-8")
            self.acquired = True
            return True
        except Exception as exc:
            LOG.warning("创建单实例锁失败(%s)，继续运行", exc)
            self.acquired = False
            return True

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            if self.path.exists() and self.path.read_text(encoding="utf-8").strip() == str(os.getpid()):
                self.path.unlink()
        except Exception:
            pass


# ===========================================================================
# 11. 主应用：状态机 + 巡检循环
# ===========================================================================
class AutoPortalAuth:
    STATE_REASONS = {
        NetState.INTERNET_OK: "internet_ok",
        NetState.PORTAL_REQUIRED: "idle_timeout",
        NetState.LINK_DOWN: "link_down",
        NetState.NO_IP: "no_ip",
        NetState.UNKNOWN: "unknown",
    }

    def __init__(self, cfg: Config, config_path: Optional[str] = None):
        self.cfg = cfg
        self.config_path = Path(config_path).resolve() if config_path else cfg.path
        self.checker = NetworkChecker(cfg)
        self.stats = StatsStore(cfg)
        self.trigger = AuthTrigger(cfg, self.checker, self.stats)
        self.notifier = Notifier(cfg)
        self.watcher = WakeWatcher(
            expected_interval=float(cfg.get("monitor.interval", 30)),
            skew_threshold=float(cfg.get("monitor.detect_sleep_skew", 5.0)),
        )
        self.state_path = cfg.resolve_path(cfg.get("app.state_file", "data/state.json"))

        self.stop_event = threading.Event()
        self.status = NetStatus(state=NetState.UNKNOWN)
        self.session_start: Optional[float] = None
        self.last_ok_ts: Optional[float] = None
        self.last_link_up = True          # 上次检测时链路是否可用（用于区分空闲超时 vs 掉线）
        self.after_wake = False           # 当前会话是否由唤醒触发
        self.keepalive_last = 0.0
        self.keepalive_interval = 0.0
        self._fail_streak = 0
        self._last_resume_mono = 0.0      # 最近一次唤醒（monotonic，用于同一次唤醒去重）
        self._last_resume_wall = 0.0      # 最近一次唤醒（wall clock，用于容忍唤醒后的探测失败）
        self._wake_fast_left = 0          # 唤醒后还剩几次"快重试"（跨多轮休眠有效）
        self._wake_unknown_logged = False  # 唤醒后的"还没就绪"是否已提示过（避免刷屏）
        self._wake_preauth_ok = False      # 本次唤醒的预认证是否已成功
        self._wake_preauth_tries = 0       # 本次唤醒已尝试预认证的次数（用于抑制重复日志）
        self._wake_level = "quick"         # 本次唤醒的抢跑档位：quick（短超时）-> normal
        self._wake_deadline = 0.0          # 本次唤醒的抢跑截止时刻（monotonic，兜底上限）
        self._skip_tick = False            # 本轮跳过完整探测（抢跑窗口内 DNS 未就绪）
        self._portal_cache_path = cfg.resolve_path(
            cfg.get("app.portal_cache_file", "data/last_portal.json"))
        self._portal_cache = self._load_portal_cache()

    # ---- 生命周期 ---------------------------------------------------------
    def install_signals(self) -> None:
        def handler(signum, _frame):
            LOG.info("收到信号 %s，准备退出...", signum)
            self.stop_event.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except Exception:
                pass

    def run(self) -> int:
        self.watcher.start()
        self.install_signals()
        LOG.info("=" * 68)
        LOG.info("%s v%s 启动 平台=%s Python=%s", APP_NAME, __version__,
                 platform.system(), platform.python_version())
        LOG.info("配置文件: %s", self.config_path or "(内置默认)")
        LOG.info("巡检周期: 正常 %ss / 待认证 %ss / 掉线 %ss",
                 self.cfg.get("monitor.interval"), self.cfg.get("monitor.portal_interval"),
                 self.cfg.get("monitor.link_down_interval"))
        LOG.info("自动登录: %s | 浏览器触发: %s | 保活: %s",
                 "开" if self.cfg.get("auth.auto_login.enabled") else "关",
                 "开" if self.cfg.get("auth.open_browser") else "关",
                 "开" if self.cfg.get("auth.keepalive.enabled") else "关")
        clicker = self.trigger._get_autoclicker()
        if clicker is None:
            LOG.info("自动点击: 关（可在 config.yaml -> browser_automation.enabled 开启）")
        elif clicker.available:
            key, exe = portal_autoclick.find_browser(self.cfg.get("browser_automation.browser", "auto"))
            LOG.info("自动点击: 开（selenium %s, 浏览器=%s, headless=%s）",
                     portal_autoclick.selenium_version(), key,
                     self.cfg.get("browser_automation.headless"))
        else:
            LOG.warning("自动点击: 配置已开启但不可用 —— %s", clicker.unavailable_reason())
        LOG.info("=" * 68)

        # 启动时先跑一次，避免"开机后干等 30 秒"
        self._tick(initial=True)

        while not self.stop_event.is_set():
            interval = self._next_interval()
            self._sleep(interval)
            if self.stop_event.is_set():
                break
            if self._skip_tick:
                # 唤醒抢跑窗口里 DNS 还没起来，完整探测只会白等几个超时，
                # 状态也不会变 —— 直接进入下一轮抢跑。
                self._skip_tick = False
                continue
            self._tick()

        self._end_session("program_exit")
        self.stats.save(force=True)
        self.watcher.stop()
        LOG.info("已退出。")

    def _sleep(self, seconds: float) -> None:
        """可中断休眠：同时监听停止信号与唤醒事件，唤醒后立即返回继续检测。"""
        # 唤醒后的"抢跑窗口"（默认 25s）：这段时间里不被正常巡检周期拖住。
        # 刚唤醒时 DNS/DHCP 往往还没就绪，等 15 秒再试就太慢了 ——
        # 浏览器打开网页只要几百毫秒，慢一步就是用户看到认证页。
        if self._wake_window_active():
            self.checker.fast_probe = True          # 探测超时压到 1s/2s
            self.checker.quick_auth = True          # 直连登录也只用 1s/1.5s
            verdict = "transient"
            try:
                verdict = self.checker.quick_probe_ip()
            except Exception as exc:
                LOG.debug("唤醒快速探测异常: %s", exc)
            if verdict == "ok":
                LOG.info("唤醒后网络已可用")
                self._end_wake_window()
                seconds = 0.0
            elif verdict == "portal":
                # 已经是认证页：立刻交给正常认证流程（含浏览器兜底）
                LOG.debug("唤醒快速探测已看到认证页，立即认证")
                self._end_wake_window()
                seconds = 0.0
            elif self._wake_preauth():
                seconds = 0.4                       # 已提交登录，短等 DNS/链路就绪
                self._skip_tick = True
            else:
                seconds = 0.25                      # 还没就绪，连着抢，不空等
                self._skip_tick = True
        elif self._wake_fast_left > 0:
            self._wake_fast_left -= 1
            self.checker.fast_probe = True
            seconds = min(seconds, 1.5)
        else:
            self.checker.fast_probe = False
            self.checker.quick_auth = False
            self._wake_level = "quick"

        end = time.monotonic() + seconds
        while not self.stop_event.is_set():
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            self.stop_event.wait(min(0.5, remaining) if remaining > 0.05 else remaining)
            events = self.watcher.poll()
            if "suspend" in events and "resume" not in events:
                # 休眠期间不做任何事，等唤醒事件
                LOG.debug("系统进入休眠")
            if "resume" in events:
                # 同一次唤醒可能被"时钟启发式"和"电源广播"各报一次，只处理第一次
                now = time.monotonic()
                if now - self._last_resume_mono < 15:
                    continue
                self._last_resume_mono = now
                self._last_resume_wall = time.time()
                self.after_wake = True
                self._wake_fast_left = int(self.cfg.get("monitor.wake_fast_probes", 12))
                self._wake_unknown_logged = False
                self._wake_preauth_ok = False
                self._wake_preauth_tries = 0
                self._wake_level = "quick"
                self._wake_deadline = now + max(
                    3.0, float(self.cfg.get("monitor.wake_preauth_window", 25)))
                self.checker.fast_probe = True
                self.checker.quick_auth = True
                self.stats.add_wake_event()
                self.notifier.on_wake()
                # 休眠中断的会话在这里收尾（不是 Portal 空闲超时，别污染统计）
                self._end_session("sleep")
                grace = float(self.cfg.get("monitor.wake_grace", 1))
                LOG.info("系统已唤醒，%ss 后开始预认证/检测网络...", grace)
                self.stop_event.wait(grace)
                # 抢在浏览器前面：用缓存下来的认证页地址直连登录（网关 IP 直连，不需要 DNS）
                self._wake_preauth()
                return

    # ---- 唤醒抢跑 ---------------------------------------------------------
    def _wake_window_active(self) -> bool:
        """是否仍在"唤醒后抢跑"窗口内（未被正常流程接管）。"""
        return (self._wake_deadline > 0.0 and self.after_wake
                and time.monotonic() < self._wake_deadline)

    def _end_wake_window(self) -> None:
        """结束抢跑窗口，交回正常巡检节奏。"""
        self._wake_deadline = 0.0
        self._wake_fast_left = 0
        self.checker.quick_auth = False

    def _wake_preauth(self) -> bool:
        """唤醒后抢在浏览器之前，用上次缓存下来的认证页直连登录。

        刚唤醒时 DNS 常常还没就绪（探测会直接报 DNS 错误），但锐捷网关是
        IP 直连（10.10.9.9），只要本机 IP 没变，用缓存地址 POST 一次往往
        1 秒内就能恢复，用户浏览器还没反应过来。

        返回 True 表示"这次已经提交并被网关接受"，后续只需简短确认。
        """
        if self._wake_preauth_ok:
            return True
        if not self.cfg.get("monitor.wake_preauth", True):
            return False
        retry = self._wake_preauth_tries > 0
        self._wake_preauth_tries += 1
        log = LOG.debug if retry else LOG.info
        cache = self._portal_cache or {}
        url = str(cache.get("url") or "")
        if not url:
            log("唤醒预认证跳过：还没有缓存过认证页地址")
            return False
        if str(cache.get("vendor") or "") != "ruijie":
            log("唤醒预认证跳过：上次的认证页不是锐捷（%s）", cache.get("vendor"))
            return False
        al = self.cfg.get("auth.auto_login") or {}
        if not (al.get("enabled") and al.get("username") and al.get("password")):
            log("唤醒预认证跳过：没有配置自动登录账号密码")
            return False
        if time.time() < self.trigger._auth_disabled_until:
            return False

        link = self.checker.link_info()
        if not link.up or not link.has_ip or not link.primary_ip:
            log("唤醒预认证跳过：网卡还没拿到 IP，等 DHCP")
            return False
        cached_ip = str(cache.get("ip") or "")
        if cached_ip and cached_ip != link.primary_ip:
            log("唤醒预认证跳过：本机 IP 变了（%s -> %s），按正常流程重新探测",
                cached_ip, link.primary_ip)
            self._end_wake_window()
            return False

        status = NetStatus(
            state=NetState.PORTAL_REQUIRED, portal_url=url, local_ip=link.primary_ip,
            interface=link.primary_iface,
            fingerprint=Fingerprint(vendor="ruijie", confidence=1.0, portal_url=url),
        )
        log("唤醒预认证：用缓存的认证页直连登录（%s）", url.split("?")[0])
        quick_was = self.checker.quick_auth
        self.checker.quick_auth = True
        try:
            # 注意：ruijie_login 是 AuthTrigger 的方法（之前这里写成 self.ruijie_login，
            # 直接 AttributeError 被 except 吞掉，抢跑从来没真正执行过）
            ok = self.trigger.ruijie_login(status, verify_seconds=0.0, assume_success=True)
        finally:
            self.checker.quick_auth = quick_was
        if ok:
            self._wake_preauth_ok = True
            self.trigger.successes += 1
            self.stats.add_auth_result(True)
            LOG.info("唤醒预认证成功（未等探测，浏览器不会先弹认证页）")
            return True
        log("唤醒预认证未成功，继续快重试/正常探测")
        return False

    def _next_interval(self) -> float:
        state = self.status.state
        if state is NetState.INTERNET_OK:
            if self.cfg.get("auth.keepalive.enabled", True):
                return min(float(self.cfg.get("monitor.interval", 30)), self._effective_keepalive())
            return float(self.cfg.get("monitor.interval", 30))
        if state is NetState.PORTAL_REQUIRED:
            # 认证失败时指数退避，避免无脑刷爆 Portal
            base = float(self.cfg.get("monitor.portal_interval", 8))
            backoff = min(base * (2 ** min(self._fail_streak, 5)),
                          float(self.cfg.get("monitor.backoff_max", 300)))
            return backoff
        if state in (NetState.LINK_DOWN, NetState.NO_IP):
            return float(self.cfg.get("monitor.link_down_interval", 5))
        return float(self.cfg.get("monitor.unknown_interval", 15))

    def _effective_keepalive(self) -> float:
        if self.keepalive_interval > 0:
            return self.keepalive_interval
        interval = float(self.cfg.get("auth.keepalive.interval", 0) or 0)
        if interval <= 0:
            analysis = self.stats.analyze_timeouts()
            interval = float(analysis.get("suggested_keepalive") or 0)
        if interval <= 0:
            interval = float(self.cfg.get("auth.keepalive.default_interval", 240))
        self.keepalive_interval = interval
        LOG.info("保活间隔设为 %ss", interval)
        return interval

    # ---- 单次巡检 ---------------------------------------------------------
    def _tick(self, initial: bool = False) -> NetStatus:
        prev = self.status
        status = self.checker.check()
        self.status = status

        LOG.debug("状态=%s 详情=%s", status.state.value, status.detail)

        if status.state is NetState.INTERNET_OK:
            self._handle_online(status, prev, initial)
        elif status.state is NetState.PORTAL_REQUIRED:
            self._handle_portal(status, prev, initial)
        elif status.state in (NetState.LINK_DOWN, NetState.NO_IP):
            self._handle_offline(status, prev)
        else:
            self._handle_unknown(status, prev)

        self.last_link_up = status.state not in (NetState.LINK_DOWN, NetState.NO_IP)
        self._write_state_file()
        return status

    def _handle_online(self, status: NetStatus, prev: NetStatus, initial: bool) -> None:
        was_ok = prev.state is NetState.INTERNET_OK
        self._fail_streak = 0
        self._wake_fast_left = 0          # 已恢复，不用再快重试
        self.checker.fast_probe = False
        self.trigger._last_browser_url = ""   # 已恢复，允许下次用浏览器

        if self.session_start is None:
            self.session_start = time.time()
            # 只有"刚休眠醒来"或"刚从认证页恢复"才算真正的恢复；单纯重启守护进程
            # 不该发"自动认证成功"的通知（那时本来就在线）。
            if prev.state is NetState.PORTAL_REQUIRED or self.after_wake:
                downtime = (self.session_start - self.last_ok_ts) if self.last_ok_ts else None
                LOG.info("网络恢复%s", f"（中断 {human_duration(downtime)}）" if downtime else "")
                self.stats.add_auth_result(True)
                self.notifier.on_success(status, downtime)
            else:
                LOG.info("网络正常: %s", status.detail)
        elif not was_ok:
            LOG.info("网络已恢复: %s", status.detail)

        self.last_ok_ts = time.time()
        self.after_wake = False

        # 保活：定期发一个小请求，防止空闲超时掉线
        if self.cfg.get("auth.keepalive.enabled", True):
            self._maybe_keepalive()

    def _maybe_keepalive(self) -> None:
        interval = self._effective_keepalive()
        now = time.monotonic()
        if now - self.keepalive_last < interval:
            return
        self.keepalive_last = now
        targets = self.cfg.get("detect.probe_targets") or []
        if not targets:
            return
        target = targets[0]
        try:
            resp = self.checker._session.get(target["url"], timeout=self.checker._timeout(),
                                             allow_redirects=False)
            ok = resp.status_code != 0 and (
                target.get("expect_status") is None or resp.status_code == target.get("expect_status")
            )
            LOG.debug("保活心跳: HTTP %s (%s)", resp.status_code, "ok" if ok else "异常")
            if not ok:
                # 心跳发现被拦截，立刻重新判定（不要等到下个周期）
                LOG.info("保活心跳异常，立即重新检测网络状态")
                self.status = self.checker.check()
                if self.status.state is NetState.PORTAL_REQUIRED:
                    self._end_session("idle_timeout")
                    self._handle_portal(self.status, NetStatus(state=NetState.INTERNET_OK), False)
        except Exception as exc:
            LOG.debug("保活心跳失败: %s", exc)

    def _handle_portal(self, status: NetStatus, prev: NetStatus, initial: bool) -> None:
        vendor = status.fingerprint.vendor if status.fingerprint else "unknown"
        # 指纹可能是 None（探测没抓到认证页），此时照样按"上次见过的厂商"记缓存，
        # 否则唤醒抢跑会因为 vendor 对不上而一直被跳过。
        if status.fingerprint is None:
            status.fingerprint = Fingerprint(
                vendor=str((self._portal_cache or {}).get("vendor") or "unknown"),
                confidence=0.5, portal_url=status.portal_url)
        self._save_portal_cache(status, status.portal_url)
        # 区分"空闲超时"和"掉线后重新认证"：链路一直在，说明是会话被空闲清理
        if prev.state is NetState.INTERNET_OK and not self.after_wake:
            LOG.warning("检测到 Portal 拦截（厂商=%s）：%s", vendor, status.detail)
            self._end_session("idle_timeout", status)
        elif self.after_wake and prev.state is NetState.INTERNET_OK:
            # 刚睡醒：会话已经按 "sleep" 收尾过，这里不该再报"空闲超时"
            LOG.info("唤醒后需要重新认证（厂商=%s）", vendor)
        elif initial:
            LOG.warning("启动时检测到需要认证（厂商=%s）", vendor)
        else:
            LOG.info("仍在等待认证（厂商=%s, 第 %d 次尝试）", vendor, self._fail_streak + 1)

        if not self.cfg.get("auth.enabled", True):
            LOG.warning("认证触发已被配置关闭（auth.enabled=false），仅报告状态")
            return

        wake_was_open = self._wake_window_active()
        recovered = self.trigger.trigger(status)

        if recovered:
            # 抢跑窗口里认证成功：会话按 "sleep" 收尾过了，这里补回来，
            # 否则下次 _handle_online 会以为"没断过"，不发恢复通知也不记在线时长
            if wake_was_open and self.session_start is None:
                self.session_start = time.time()
            self._fail_streak = 0
            self.session_start = time.time()
            self.last_ok_ts = self.session_start
            self.after_wake = False
            self.stats.add_auth_result(True)
            # prev_checked() 在"首次启动、还没有历史时间戳"时会返回 None，
            # 这里必须先判断，否则通知里的中断时长计算会抛 TypeError。
            prev_ts = prev_checked(prev)
            downtime = (self.session_start - prev_ts) if prev_ts else None
            self.notifier.on_success(status, downtime)
            LOG.info("认证成功，网络已恢复%s",
                     f"（中断 {human_duration(downtime)}）" if downtime else "")
            self._end_wake_window()
            return

        self._fail_streak += 1
        self.stats.add_auth_result(False)
        self.notifier.on_failure(status)

    def _handle_offline(self, status: NetStatus, prev: NetStatus) -> None:
        if prev.state not in (NetState.LINK_DOWN, NetState.NO_IP):
            LOG.warning("网络链路不可用: %s", status.detail)
            if prev.state is NetState.INTERNET_OK:
                self._end_session("link_down", status)
                self.stats.add_disconnect()
            elif self.session_start is not None:
                self._end_session("link_down", status)
        else:
            LOG.debug("链路仍未恢复: %s", status.detail)

    def _handle_unknown(self, status: NetStatus, prev: NetStatus) -> None:
        # 刚唤醒时 DNS/协议栈往往还没就绪，第一次探测失败是常态，不是真的断网：
        # 不要结束会话、也别刷一屏警告，快重试几次就好。
        since_wake = (time.time() - self._last_resume_wall) if self._last_resume_wall else None
        tolerance = float(self.cfg.get("monitor.wake_unknown_tolerance", 30))
        if since_wake is not None and since_wake < tolerance:
            if not self._wake_unknown_logged:
                self._wake_unknown_logged = True
                LOG.info("唤醒后网络尚未就绪（%.1fs），快速重试中: %s", since_wake, status.detail)
            else:
                LOG.debug("唤醒后重试仍未就绪（%.1fs）: %s", since_wake, status.detail)
            # 探测要等 DNS，直连登录不用 —— 每轮都抢一次
            if self._wake_preauth():
                # 网关已接受：下一轮只做一次短确认，别一直当"没就绪"
                self._wake_deadline = min(
                    self._wake_deadline or (time.monotonic() + 2.0), time.monotonic() + 2.0)
            return
        if prev.state is NetState.INTERNET_OK:
            LOG.warning("网络探测异常（可能上游故障）: %s", status.detail)
            self._end_session("unknown", status)
        else:
            LOG.info("状态未知: %s", status.detail)

    def _end_session(self, reason: str, status: Optional[NetStatus] = None) -> None:
        if self.session_start is None:
            return
        start, self.session_start = self.session_start, None
        end = time.time()
        vendor = "unknown"
        if status and status.fingerprint:
            vendor = status.fingerprint.vendor
        LOG.info("会话结束: 原因=%s 时长=%s", reason, human_duration(end - start))
        self.stats.add_session(start, end, reason, vendor=vendor, wake=self.after_wake)

        # 只有"链路一直正常却被 Portal 拦截"才算一次真正的空闲超时样本
        if reason == "idle_timeout" and self.last_link_up:
            ta = self.cfg.get("timeout_analysis") or {}
            if ta.get("enabled", True):
                seconds = end - start
                if float(ta.get("min_seconds", 60)) <= seconds <= float(ta.get("max_seconds", 12 * 3600)):
                    self.stats.add_idle_timeout(seconds)
                    self.keepalive_interval = 0.0   # 有新样本 -> 重新推算保活间隔
                    self._log_timeout_advice()

    def _log_timeout_advice(self) -> None:
        analysis = self.stats.analyze_timeouts()
        if analysis.get("suggested_keepalive"):
            LOG.info("空闲超时统计: 样本=%s 中位数=%ss 建议保活间隔=%ss",
                     analysis["samples"], analysis["median"], analysis["suggested_keepalive"])

    # ---- 认证页缓存 -------------------------------------------------------
    def _load_portal_cache(self) -> Dict[str, Any]:
        path = self._portal_cache_path
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("url"):
                    LOG.debug("已加载认证页缓存: %s (%s)", str(data.get("url")).split("?")[0],
                              data.get("saved_at"))
                    return data
        except Exception as exc:
            LOG.debug("读取认证页缓存失败: %s", exc)
        return {}

    def _save_portal_cache(self, status: NetStatus, portal_url: str = "") -> None:
        """记住这次看到的认证页地址，下次唤醒可以不等探测直接登录。"""
        if not portal_url:
            return
        payload = {
            "url": portal_url,
            "vendor": status.fingerprint.vendor if status.fingerprint else "",
            "ip": status.local_ip or "",
            "saved_at": now_iso(),
        }
        if self._portal_cache and all(
                payload.get(k) == self._portal_cache.get(k) for k in ("url", "vendor", "ip")):
            return
        self._portal_cache = payload
        try:
            self._portal_cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._portal_cache_path.with_suffix(self._portal_cache_path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self._portal_cache_path)
        except Exception as exc:
            LOG.debug("写入认证页缓存失败: %s", exc)

    # ---- 状态文件 ---------------------------------------------------------
    def _write_state_file(self) -> None:
        try:
            payload = self.status.to_dict()
            payload.update({
                "version": __version__,
                "pid": os.getpid(),
                "session_seconds": round(time.time() - self.session_start, 1) if self.session_start else 0,
                "last_ok": iso_from_ts(self.last_ok_ts),
                "fail_streak": self._fail_streak,
                "keepalive_interval": self.keepalive_interval or None,
            })
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            tmp.replace(self.state_path)
        except Exception as exc:
            LOG.debug("写入状态文件失败: %s", exc)

    # ---- 单次模式 ---------------------------------------------------------
    def run_once(self, trigger_auth: bool = True) -> int:
        status = self.checker.check()
        self.status = status
        log = LOG.info
        if status.state is NetState.INTERNET_OK:
            log("网络正常: %s", status.detail)
        elif status.state is NetState.PORTAL_REQUIRED:
            vendor = status.fingerprint.vendor if status.fingerprint else "unknown"
            log("需要 Portal 认证（厂商=%s）: %s", vendor, status.portal_url)
            if trigger_auth:
                recovered = self.trigger.trigger(status)
                log("认证触发结果: %s", "已恢复" if recovered else "已发起（可能需要人工确认）")
                if not recovered:
                    return 2
        elif status.state in (NetState.LINK_DOWN, NetState.NO_IP):
            log("链路不可用: %s", status.detail)
            return 3
        else:
            log("状态未知: %s", status.detail)
            return 1
        return 0


def prev_checked(prev: NetStatus) -> Optional[float]:
    """从上次状态里推算"上次在线时间"，用于通知里显示中断时长（尽力而为）。"""
    try:
        if prev.checked_at:
            return datetime.fromisoformat(prev.checked_at).timestamp()
    except Exception:
        pass
    return None


# ===========================================================================
# 12. 开机自启安装 / 卸载
# ===========================================================================
def autostart_command(cfg: Config, config_path: Optional[str],
                      python_exe: Optional[str] = None) -> Tuple[List[str], str]:
    """返回 (命令参数列表, 用于展示的命令行字符串)。

    python_exe：外部指定解释器（看门狗用 pick_daemon_python() 挑带 selenium 的那个）；
    不传则用当前解释器，保持原有行为。
    """
    exe = python_exe or sys.executable
    if platform.system() == "Windows":
        # pythonw.exe 运行时不弹黑框
        cand = Path(exe).with_name("pythonw.exe")
        if cand.exists():
            exe = str(cand)
    script = str(Path(__file__).resolve())
    # -X utf8：保证日志/输出在任何代码页下都是 UTF-8，避免中文乱码
    args = [exe, "-X", "utf8", script]
    if config_path:
        args += ["-c", str(Path(config_path).resolve())]
    args += ["run"]
    pretty = " ".join(f'"{a}"' if " " in a else a for a in args)
    return args, pretty


def install_autostart(cfg: Config, config_path: Optional[str], method: str = "auto",
                      start_now: bool = False) -> bool:
    args, pretty = autostart_command(cfg, config_path)
    system = platform.system()
    if method == "auto":
        method = {"Windows": "registry", "Darwin": "launchd", "Linux": "systemd"}.get(system, "registry")

    LOG.info("安装开机自启（方式=%s）: %s", method, pretty)

    if system == "Windows":
        return _install_windows(args, pretty, method, start_now, cfg)
    if system == "Darwin":
        return _install_launchd(args, start_now)
    return _install_systemd(args, start_now)


def _install_windows(args: List[str], pretty: str, method: str,
                     start_now: bool, cfg: Config) -> bool:
    ok = False
    if method in ("registry", "auto"):
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, pretty)
            winreg.CloseKey(key)
            LOG.info("已写入注册表自启项 HKCU\\...\\Run\\%s", APP_NAME)
            ok = True
        except Exception as exc:
            LOG.error("写入注册表失败: %s", exc)

    if method in ("startup",):
        try:
            startup = Path(os.environ.get("APPDATA", "")) / \
                r"Microsoft\Windows\Start Menu\Programs\Startup"
            startup.mkdir(parents=True, exist_ok=True)
            vbs = startup / f"{APP_NAME}.vbs"
            # 用 VBS 以隐藏窗口方式启动，避免开机弹出黑框
            body = (
                'Set sh = CreateObject("WScript.Shell")\r\n'
                'sh.Run "' + pretty.replace('"', '""') + '", 0, False\r\n'
            )
            vbs.write_text(body, encoding="utf-8")
            LOG.info("已创建启动脚本: %s", vbs)
            ok = True
        except Exception as exc:
            LOG.error("创建启动脚本失败: %s", exc)

    if method in ("task",):
        try:
            cmd = ["schtasks", "/Create", "/TN", APP_NAME, "/TR", pretty,
                   "/SC", "ONLOGON", "/RL", "LIMITED", "/F"]
            subprocess.run(cmd, check=True, capture_output=True)
            LOG.info("已创建计划任务（登录时启动）: %s", APP_NAME)
            # 额外：注册"从睡眠/休眠恢复"触发（部分系统需要管理员权限）
            resume_trigger = (
                "*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] "
                "and (EventID=1)]]"
            )
            cmd2 = ["schtasks", "/Create", "/TN", f"{APP_NAME}-Resume", "/TR", pretty,
                    "/SC", "ONEVENT", "/EC", "System", "/MO", resume_trigger, "/F"]
            proc = subprocess.run(cmd2, capture_output=True, text=True)
            if proc.returncode == 0:
                LOG.info("已创建唤醒触发任务: %s-Resume", APP_NAME)
            else:
                LOG.warning("创建唤醒触发任务失败（通常需要管理员权限，可用 --method task 以管理员运行）: %s",
                            (proc.stderr or proc.stdout or "").strip()[:200])
            ok = True
        except Exception as exc:
            LOG.error("创建计划任务失败: %s", exc)

    if start_now and ok:
        _spawn_now(args)
    return ok


def _install_systemd(args: List[str], start_now: bool) -> bool:
    try:
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        quoted = " ".join(f'"{a}"' if " " in a else a for a in args)
        unit = f"""[Unit]
Description=Campus Network Portal Auto Authentication
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={quoted}
Restart=always
RestartSec=10
# 睡眠唤醒后立即重试
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"""
        path = unit_dir / f"{APP_NAME.lower()}.service"
        path.write_text(unit, encoding="utf-8")
        LOG.info("已写入 systemd 用户服务: %s", path)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "--user", "enable", f"{APP_NAME.lower()}.service"], check=False)
        if start_now:
            subprocess.run(["systemctl", "--user", "restart", f"{APP_NAME.lower()}.service"], check=False)
        LOG.info("提示：如需开机（未登录）也生效，可执行 "
                 "sudo loginctl enable-linger $USER")
        return True
    except Exception as exc:
        LOG.error("安装 systemd 服务失败: %s", exc)
        return False


def _install_launchd(args: List[str], start_now: bool) -> bool:
    import plistlib
    try:
        agents = Path.home() / "Library" / "LaunchAgents"
        agents.mkdir(parents=True, exist_ok=True)
        label = "com.campus.autoportal"
        path = agents / f"{label}.plist"
        payload = {
            "Label": label,
            "ProgramArguments": args,
            "RunAtLoad": True,
            "KeepAlive": True,
            "StandardOutPath": str(Path.home() / "Library" / "Logs" / "autoportal.out.log"),
            "StandardErrorPath": str(Path.home() / "Library" / "Logs" / "autoportal.err.log"),
        }
        with path.open("wb") as f:
            plistlib.dump(payload, f)
        LOG.info("已写入 launchd 配置: %s", path)
        subprocess.run(["launchctl", "unload", str(path)], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        load = subprocess.run(["launchctl", "load", "-w", str(path)], check=False,
                              capture_output=True, text=True)
        if load.returncode != 0 and start_now:
            LOG.warning("launchctl load 失败: %s", (load.stderr or "").strip()[:200])
        return True
    except Exception as exc:
        LOG.error("安装 launchd 配置失败: %s", exc)
        return False


def _spawn_now(args: List[str]) -> None:
    try:
        creationflags = 0
        if hasattr(subprocess, "DETACHED_PROCESS"):
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=creationflags, close_fds=True)
        LOG.info("已启动后台进程")
    except Exception as exc:
        LOG.warning("启动后台进程失败: %s", exc)


def uninstall_autostart() -> bool:
    system = platform.system()
    removed = False
    if system == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, APP_NAME)
            winreg.CloseKey(key)
            LOG.info("已删除注册表自启项")
            removed = True
        except FileNotFoundError:
            pass
        except Exception as exc:
            LOG.warning("删除注册表项失败: %s", exc)

        try:
            vbs = Path(os.environ.get("APPDATA", "")) / \
                r"Microsoft\Windows\Start Menu\Programs\Startup" / f"{APP_NAME}.vbs"
            if vbs.exists():
                vbs.unlink()
                LOG.info("已删除启动文件夹脚本: %s", vbs)
                removed = True
        except Exception as exc:
            LOG.warning("删除启动脚本失败: %s", exc)

        for task in (APP_NAME, f"{APP_NAME}-Resume"):
            proc = subprocess.run(["schtasks", "/Delete", "/TN", task, "/F"],
                                  capture_output=True, text=True)
            if proc.returncode == 0:
                LOG.info("已删除计划任务: %s", task)
                removed = True
        return removed

    if system == "Darwin":
        path = Path.home() / "Library" / "LaunchAgents" / "com.campus.autoportal.plist"
        subprocess.run(["launchctl", "unload", "-w", str(path)], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if path.exists():
            path.unlink()
            LOG.info("已删除 launchd 配置: %s", path)
            removed = True
        return removed

    path = Path.home() / ".config" / "systemd" / "user" / f"{APP_NAME.lower()}.service"
    subprocess.run(["systemctl", "--user", "disable", "--now", f"{APP_NAME.lower()}.service"],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if path.exists():
        path.unlink()
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        LOG.info("已删除 systemd 服务: %s", path)
        removed = True
    return removed


# ===========================================================================
# 13. 自检
# ===========================================================================
SELFTEST_CASES = [
    ("深澜 srun 认证页",
     "http://10.0.0.1/srun_portal_pc?ac_id=1&wlanuserip=10.1.2.3",
     '<html><head><title>深澜认证</title></head><body>'
     '<form action="/srun_portal_pc" method="post">'
     '<input type="text" name="username"><input type="password" name="password">'
     '<input type="hidden" name="ac_id" value="1"></form></body></html>',
     "srun"),
    ("锐捷 eportal",
     "http://1.1.1.1/eportal/index.jsp?wlanuserip=10.1.2.3&wlanacname=ac1",
     '<html><title>RG-ePortal</title><body><form action="/eportal/InterFace.do?method=login">'
     '<input name="userId"><input type="password" name="password"></form></body></html>',
     "ruijie"),
    ("Dr.COM",
     "http://192.168.1.1/drcom/login?ip=10.1.2.3",
     '<html><title>Dr.COM 城市热点</title><body><form id="form1" action="login" method="post">'
     '<input name="0MKKey"><input type="password" name="DDDDD"></form></body></html>',
     "drcom"),
    ("H3C PortalServer",
     "http://10.10.10.1/portal/login",
     '<html><title>PortalServer</title><form action="/portal/login" method="post">'
     '<input name="userName"><input type="password" name="passWord"></form></html>',
     "h3c"),
    ("通用认证页（无厂商特征）",
     "http://gw.local/portal",
     '<html><title>校园网认证</title><body>请登录后上网'
     '<form action="/login"><input name="account"><input type="password" name="pwd"></form>'
     '</body></html>',
     "generic"),
    ("meta refresh 跳转",
     "http://gw.local/index",
     '<html><head><meta http-equiv="refresh" content="0;url=/portal/login.html"></head></html>',
     "unknown"),
]


def selftest() -> int:
    failures = 0
    print(f"{APP_NAME} 自检 v{__version__}")
    print("-" * 68)
    for name, url, html, expected_vendor in SELFTEST_CASES:
        fp = guess_vendor(url, html)
        ok = fp.vendor == expected_vendor or (expected_vendor == "unknown")
        has_form = fp.login_form is not None
        if expected_vendor in ("srun", "ruijie", "drcom", "h3c", "generic"):
            ok = fp.vendor == expected_vendor and has_form
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"[{status}] {name}: 识别为 {fp.vendor} (期望 {expected_vendor}) "
              f"置信度={fp.confidence} 表单={'有' if has_form else '无'} 证据={fp.evidence[:3]}")
    # 附加：表单字段抽取
    fp = guess_vendor(SELFTEST_CASES[0][1], SELFTEST_CASES[0][2])
    fields = [f["name"] for f in (fp.login_form.fields if fp.login_form else [])]
    print(f"[{'PASS' if fields == ['username', 'password', 'ac_id'] else 'FAIL'}] 表单字段抽取: {fields}")
    if fields != ["username", "password", "ac_id"]:
        failures += 1

    print("-" * 68)
    print("全部通过" if failures == 0 else f"{failures} 项失败")
    return 0 if failures == 0 else 1


def load_config_local_only(path: Optional[str]) -> Config:
    """给 driver / install-extension 这类纯本地命令加载配置。

    它们只需要"浏览器路径 / 配置目录"等少量信息，不应该因为当前 Python
    没装 PyYAML 就报"解析配置文件失败"。读不了就直接用内置默认值。
    """
    if yaml is not None:
        return Config.load(path)
    cfg_path = Path(path).expanduser().resolve() if path else Path(__file__).resolve().parent / "config.yaml"
    return Config(path=cfg_path)


def _watchdog_task_name() -> str:
    return "AutoPortalAuthWatchdog"


def _watchdog_xml(command: str, workdir: str, interval_minutes: int,
                  arguments: str = "-X utf8 watchdog") -> str:
    """生成计划任务 XML。

    关键三点（对应实战中"睡醒后没人拉起进程"的问题）：
      * 多个触发器：登录时 + 每 N 分钟 + **唤醒时（BootTrigger 不行，用 EventTrigger
        监听 Kernel-Power 107 恢复事件）**，保证一醒来就有人检查；
      * 任务设置为"唤醒后立即运行"、"错过则尽快补跑"；
      * 用 pythonw 静默运行，不弹黑框。
    """
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AutoPortalAuth 看门狗：守护进程不在就拉起；唤醒后立即检查一次。</Description>
    <URI>\\{_watchdog_task_name()}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT20S</Delay>
    </LogonTrigger>
    <TimeTrigger>
      <Repetition>
        <Interval>PT{interval_minutes}M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=107 or EventID=131)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{_current_user()}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{_xml_escape(command)}</Command>
      <Arguments>{_xml_escape(arguments)}</Arguments>
      <WorkingDirectory>{_xml_escape(workdir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _current_user() -> str:
    try:
        user = os.environ.get("USERNAME") or ""
        domain = os.environ.get("USERDOMAIN") or ""
        return f"{domain}\\{user}" if domain else user
    except Exception:
        return ""


def _xml_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def pick_daemon_python() -> str:
    """挑一个"真正装了依赖"的解释器来跑守护进程。

    坑点：本工具自身的运行时 Python 只带了最小依赖（没有 selenium），
    直接 sys.executable 会把守护进程以"浏览器兜底不可用"的状态拉起来。
    所以优先选：项目 venv > 系统 Python（selenium 可用）> 自身。
    判断标准是能 import selenium —— 那才是完整功能所需的解释器。
    """
    root = Path(__file__).resolve().parent
    candidates: List[str] = []
    for venv in ("venv", ".venv"):
        for exe in ("Scripts/pythonw.exe", "Scripts/python.exe"):
            candidates.append(str(root / venv / exe))
    # 常见系统安装位置 + PATH 里的 python
    local = os.environ.get("LOCALAPPDATA") or ""
    if local:
        for ver in ("Python313", "Python312", "Python311"):
            candidates.append(str(Path(local) / "Programs" / "Python" / ver / "pythonw.exe"))
    found = shutil.which("pythonw.exe") or shutil.which("python.exe")
    if found:
        candidates.append(found)
    candidates.append(sys.executable)

    seen = set()
    for exe in candidates:
        path = Path(exe)
        if not path.exists():
            continue
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            exe_plain = path.with_name("python.exe") if path.name.startswith("pythonw") else path
            if not exe_plain.exists():
                continue
            r = subprocess.run([str(exe_plain), "-c", "import selenium"],
                               capture_output=True, timeout=15,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0:
                LOG.debug("看门狗选用解释器（selenium 可用）: %s", path)
                return str(path)
        except Exception:
            continue
    LOG.warning("未找到装了 selenium 的解释器，退回当前解释器: %s", sys.executable)
    return sys.executable


def find_running_daemon(cfg: Config) -> Optional[int]:
    """找到正在运行的守护进程 PID（读锁文件，并校验进程真的活着）。"""
    lock_path = cfg.resolve_path(cfg.get("app.lock_file", "data/auto_portal_auth.lock"))
    try:
        if not lock_path.exists():
            return None
        pid = int((lock_path.read_text(encoding="utf-8") or "0").strip() or 0)
    except Exception:
        return None
    return pid if SingleInstance._pid_alive(pid) else None


def cmd_watchdog(cfg: Config, args) -> int:
    """看门狗本体：守护进程不在就拉起。

    设计要点：
      * 只用"锁文件 + 进程存活"判断，不碰网络，秒级完成；
      * 拉起后短暂等待确认，失败则重试（默认 3 次）；
      * 被计划任务每 N 分钟 + 系统唤醒时触发，自身不常驻，零资源占用。
    """
    pid = find_running_daemon(cfg)
    if pid:
        print(f"守护进程在运行 (pid={pid})，无需处理。")
        return 0
    if getattr(args, "check", False):
        print("守护进程未运行。")
        return 1

    args_list, pretty = autostart_command(cfg, args.config, python_exe=pick_daemon_python())
    tries = max(1, int(getattr(args, "retries", 3) or 1))
    for attempt in range(1, tries + 1):
        print(f"[{attempt}/{tries}] 拉起守护进程: {pretty}")
        try:
            kwargs = {"close_fds": True}
            if platform.system() == "Windows":
                kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | \
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            subprocess.Popen(args_list, cwd=str(Path(__file__).resolve().parent),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, **kwargs)
        except Exception as exc:
            print(f"    启动失败: {exc}")
        for _ in range(20):            # 最多等 6 秒
            time.sleep(0.3)
            pid = find_running_daemon(cfg)
            if pid:
                print(f"    [OK] 已拉起 (pid={pid})")
                return 0
        time.sleep(1)
    print("    [FAIL] 多次尝试仍未拉起，请手动运行 `python auto_portal_auth.py run` 查看报错。")
    return 1


def cmd_watchdog_install(cfg: Config, args) -> int:
    """把看门狗注册成 Windows 计划任务（登录 / 每 N 分钟 / 系统唤醒 三种触发）。"""
    if platform.system() != "Windows":
        print("该命令目前只支持 Windows。")
        return 2
    interval = max(1, int(getattr(args, "interval", 5) or 5))
    python = Path(pick_daemon_python())
    # 用 pythonw 启动，避免计划任务里闪黑框
    pyw = python.with_name("pythonw.exe")
    exe = pyw if pyw.exists() else python
    script = Path(__file__).resolve()
    workdir = str(script.parent)
    command = f'"{exe}" "{script}"'
    # 注意：参数里必须带 watchdog 子命令，否则计划任务会把 daemon 的 run 再起一遍
    xml = _watchdog_xml(command, workdir, interval, arguments="-X utf8 watchdog")

    tmp = Path(tempfile.gettempdir()) / "apa_watchdog.xml"
    # schtasks 要求 UTF-16
    tmp.write_text(xml, encoding="utf-16")
    name = _watchdog_task_name()
    try:
        if getattr(args, "remove", False):
            subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"],
                           capture_output=True)
            print(f"已删除计划任务 {name}")
            return 0
        r = subprocess.run(["schtasks", "/Create", "/TN", name, "/XML", str(tmp), "/F"],
                           capture_output=True, text=True, encoding="mbcs", errors="replace")
        if r.returncode != 0:
            err = (r.stdout or "") + (r.stderr or "")
            print("创建计划任务失败：", err.strip())
            if "拒绝访问" in err or "Access is denied" in err:
                print("提示：需要以管理员身份运行一次本命令。")
            return 1
        print(f"已创建计划任务 {name}")
        print(f"  触发：登录后 20 秒 / 每 {interval} 分钟 / 系统唤醒后 3 秒")
        print(f"  命令：{command} watchdog")
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass

    if not getattr(args, "no_start", False):
        print("\n立即执行一次看门狗检查：")
        return cmd_watchdog(cfg, args)
    return 0


def cmd_fix_adapters(cfg: Config, args) -> int:
    """清理"拿到 169.254 自动私有地址"的僵尸网卡。

    休眠唤醒后 Wi-Fi 驱动经常只完成重新关联、不做 DHCP，网卡就卡在
    169.254.x.x。这类网卡不参与认定（link_info 会跳过），但仍挂在系统里
    影响路由和 DNS 解析。修复顺序由轻到重：
      1. ipconfig /renew（只续租，无感）
      2. netsh 禁用 / 启用该网卡（会短暂断一下该网卡）
    默认 --dry-run 只报告不动手，避免误伤正在用的链路。
    """
    checker = NetworkChecker(cfg)
    stale = checker.stale_ipv4_interfaces()
    print(f"检测到 {len(stale)} 个异常网卡（169.254 自动私有地址，DHCP 未成功）：")
    for item in stale:
        print(f"  - {item['name']}  {item['ip']}")
    if not stale:
        print("无需处理。")
        return 0

    names = [item["name"] for item in stale]
    if args.only:
        names = [n for n in names if any(k.lower() in n.lower() for k in args.only)]
        if not names:
            print("按 --only 过滤后没有需要处理的网卡。")
            return 0

    if getattr(args, "dry_run", False):
        print("\n[dry-run] 未做任何改动。加 --apply 才会真正执行。")
        return 0

    ok, fail = [], []
    reasons = {item["name"]: item.get("reason") for item in stale}
    for name in names:
        print(f"\n>>> 处理: {name}")
        if reasons.get(name) == "stale":
            # 网卡本身没启用，残留地址是系统留下的：直接删地址，不动网卡状态
            subprocess.run(["netsh", "interface", "ip", "delete", "address",
                            f"name={name}", "address=all"],
                           capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            time.sleep(1)
            if name not in [x["name"] for x in checker.stale_ipv4_interfaces()]:
                print("    [OK] 残留地址已清除")
                ok.append(name)
            else:
                print("    [FAIL] 残留地址仍在（可能需要管理员权限）")
                fail.append(name)
            continue
        # 1) 续租：先试最轻的手段
        r = subprocess.run(["ipconfig", "/renew", name], capture_output=True,
                           text=True, encoding="mbcs", errors="replace",
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        print(f"    ipconfig /renew -> rc={r.returncode}")
        time.sleep(2)
        left = [x["name"] for x in checker.stale_ipv4_interfaces()]
        if name not in left:
            print(f"    [OK] {name} 已拿到正常地址")
            ok.append(name)
            continue
        # 2) 重启网卡
        for action in ("disable", "enable"):
            subprocess.run(["netsh", "interface", "set", "interface",
                            f"name={name}", f"admin={action}"],
                           capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            time.sleep(3 if action == "disable" else 6)
        left = [x["name"] for x in checker.stale_ipv4_interfaces()]
        if name not in left:
            print(f"    [OK] {name} 重启网卡后已恢复")
            ok.append(name)
        else:
            print(f"    [FAIL] {name} 仍是 169.254，可能需要重装/更新驱动")
            fail.append(name)

    print(f"\n完成：成功 {len(ok)}，失败 {len(fail)}")
    if fail:
        print("失败项建议手动处理（设备管理器里禁用再启用，或更新驱动）：", ", ".join(fail))
        return 2
    return 0


def cmd_driver(cfg: Config, args) -> int:
    """检查 / 预下载浏览器驱动。纯本地命令，不需要 requests 或 PyYAML。"""
    if portal_autoclick is None:
        print("[X] 找不到 portal_autoclick.py（请确认目录完整）", file=sys.stderr)
        return 1
    if not portal_autoclick.selenium_available():
        print(f"[X] 当前 Python 未安装 selenium：{sys.executable}", file=sys.stderr)
        print(f"    请执行: \"{sys.executable}\" -m pip install selenium", file=sys.stderr)
        return 1

    if not getattr(args, "download", False):
        key, exe = portal_autoclick.find_browser(getattr(args, "browser", "auto"))
        print(json.dumps({
            "python": sys.executable,
            "selenium": portal_autoclick.selenium_version(),
            "browser": key or None,
            "executable": exe or None,
        }, ensure_ascii=False, indent=2))
        if not key:
            print("[X] 未找到 Edge / Chrome", file=sys.stderr)
            return 1
        return 0

    ok, msg = portal_autoclick.ensure_driver(
        cfg, getattr(args, "browser", "auto"),
        headless=not getattr(args, "headed", False))
    print(("[OK] " if ok else "[X] ") + msg)
    if not ok:
        print("提示：首次下载驱动需要能上网；可在能上网时先执行一次本命令。")
    return 0 if ok else 1


def cmd_install_extension() -> int:
    """方案 C：把浏览器扩展装进 Edge/Chrome（需要用户手工确认一次）。"""
    ext = Path(__file__).resolve().parent / "extension"
    if not (ext / "manifest.json").exists():
        LOG.error("找不到扩展目录或 manifest.json: %s", ext)
        return 1

    print(f"""
浏览器扩展目录：
    {ext}

安装步骤（只需做一次）：
    1. 浏览器会自动打开扩展管理页（没打开就手动输入下方地址）
    2. 打开右上角「开发人员模式 / Developer mode」
    3. 点击「加载解压缩的扩展 / Load unpacked」
    4. 选择上面的目录
    5. 之后认证页一打开，扩展会自动勾选条款并点击"连接"

  扩展管理页地址：Edge -> edge://extensions    Chrome -> chrome://extensions
""")

    key, exe = "", ""
    try:
        if portal_autoclick is not None:
            key, exe = portal_autoclick.find_browser("auto")
    except Exception:
        pass

    page = "edge://extensions" if key == "edge" else "chrome://extensions"
    try:
        if exe:
            subprocess.Popen([exe, page], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            LOG.info("已打开扩展管理页: %s", page)
        else:
            webbrowser.open(page)
    except Exception as exc:
        LOG.warning("无法自动打开扩展管理页（请手动打开 %s）: %s", page, exc)

    try:
        system = platform.system()
        if system == "Windows":
            opener = getattr(os, "startfile", None)
            if opener:
                opener(str(ext))
        elif system == "Darwin":
            subprocess.Popen(["open", str(ext)])
        else:
            subprocess.Popen(["xdg-open", str(ext)])
        LOG.info("已在文件管理器中打开扩展目录")
    except Exception as exc:
        LOG.debug("打开目录失败: %s", exc)

    return 0


# ===========================================================================
# 14. 工具函数
# ===========================================================================
def now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def iso_from_ts(ts: Optional[float]) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts).replace(microsecond=0).isoformat()


def human_duration(seconds: Optional[float]) -> str:
    if seconds is None or seconds <= 0:
        return "0秒"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}天")
    if hours:
        parts.append(f"{hours}小时")
    if minutes:
        parts.append(f"{minutes}分")
    if secs or not parts:
        parts.append(f"{secs}秒")
    return "".join(parts)


# ===========================================================================
# 15. 命令行
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto_portal_auth.py",
        description=f"{APP_NAME} - 校园网 Portal 自动认证 / 自动重连守护程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python auto_portal_auth.py run            # 常驻运行\n"
               "  python auto_portal_auth.py once           # 单次检测（并尝试触发认证）\n"
               "  python auto_portal_auth.py status         # 查看状态\n"
               "  python auto_portal_auth.py install --start-now\n",
    )
    parser.add_argument("-c", "--config", help="配置文件路径（默认 ./config.yaml）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出 DEBUG 日志")
    parser.add_argument("--log-level", help="覆盖日志级别 (DEBUG/INFO/WARNING/ERROR)")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")

    # 让 -c/-v/--log-level 放在子命令后面也能用。
    # default=SUPPRESS 很关键：子解析器未显式给出这些参数时不会覆盖全局值。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=argparse.SUPPRESS, help="配置文件路径")
    common.add_argument("-v", "--verbose", action="store_true",
                        default=argparse.SUPPRESS, help="输出 DEBUG 日志")
    common.add_argument("--log-level", default=argparse.SUPPRESS, help="覆盖日志级别")

    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", parents=[common], help="常驻运行（默认）")
    p_run.add_argument("--interval", type=float, help="覆盖正常巡检周期（秒）")
    p_run.add_argument("--no-lock", action="store_true", help="跳过多实例检查")

    p_once = sub.add_parser("once", parents=[common], help="单次检测")
    p_once.add_argument("--no-trigger", action="store_true", help="只检测，不触发认证")

    sub.add_parser("status", parents=[common], help="打印当前状态（JSON）")
    sub.add_parser("stats", parents=[common], help="打印统计信息（JSON）")
    sub.add_parser("analyze", parents=[common], help="分析空闲超时并给出建议")
    sub.add_parser("selftest", parents=[common], help="运行内置自检")

    p_install = sub.add_parser("install", parents=[common], help="安装开机自启")
    p_install.add_argument("--method", default="auto",
                           choices=["auto", "registry", "startup", "task", "systemd", "launchd"],
                           help="Windows: registry/startup/task；Linux: systemd；macOS: launchd")
    p_install.add_argument("--start-now", action="store_true", help="安装后立即启动后台进程")

    p_uninstall = sub.add_parser("uninstall", parents=[common], help="卸载开机自启")
    p_uninstall.add_argument("--method", default="auto", help="保留参数以兼容 install")

    p_ac = sub.add_parser("autoclick", parents=[common],
                          help="检测认证页并自动勾选+点击（方案 A）")
    p_ac.add_argument("--url", help="认证页地址；省略则自动探测当前 Portal")
    p_ac.add_argument("--explain", action="store_true",
                      help="只打印候选元素的打分表，不点击（调参神器）")
    p_ac.add_argument("--headed", action="store_true", help="使用可见浏览器窗口")
    p_ac.add_argument("--keep-open", action="store_true", help="结束后不关闭浏览器")
    p_ac.add_argument("--timeout", type=float, help="覆盖总超时（秒）")
    p_ac.add_argument("--selector", action="append", default=[],
                      help="追加 CSS 选择器（可多次指定），帮助定位特殊按钮")

    p_drv = sub.add_parser("driver", parents=[common], help="检查/预下载浏览器驱动")
    p_drv.add_argument("--browser", choices=["auto", "edge", "chrome"], default="auto")
    p_drv.add_argument("--download", action="store_true",
                       help="初始化一次驱动（首次需要联网下载）")
    p_drv.add_argument("--headed", action="store_true", help="使用可见窗口测试")

    p_fix = sub.add_parser("fix-adapters", parents=[common],
                           help="清理拿到 169.254 地址的僵尸网卡（休眠后 DHCP 失败）")
    p_fix.add_argument("--apply", dest="apply", action="store_true",
                       help="真正执行修复（默认只报告）")
    p_fix.add_argument("--dry-run", dest="dry_run", action="store_true", default=True,
                       help="只报告，不改动（默认行为）")
    p_fix.add_argument("--only", action="append", metavar="NAME",
                       help="只处理名字包含该关键字的网卡，可重复")

    p_wd = sub.add_parser("watchdog", parents=[common],
                          help="看门狗：守护进程不在就拉起（供计划任务调用）")
    p_wd.add_argument("--check", action="store_true", help="只检查，不拉起（未运行返回 1）")
    p_wd.add_argument("--retries", type=int, default=3, help="拉起失败的重试次数")
    p_wd.add_argument("--install", action="store_true",
                      help="注册计划任务：登录 + 每 N 分钟 + 系统唤醒")
    p_wd.add_argument("--remove", action="store_true", help="删除计划任务")
    p_wd.add_argument("--interval", type=int, default=5, help="巡检间隔分钟数（默认 5）")
    p_wd.add_argument("--no-start", action="store_true", help="安装后不立即检查")

    sub.add_parser("install-extension", parents=[common],
                   help="打开浏览器扩展管理页（方案 C）")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or "run"

    # ---- 纯本地命令：不依赖 requests / PyYAML -----------------------------
    # driver 只需要 selenium（找浏览器、下载驱动），install-extension 只需要浏览器。
    # 放在 Config.load() 之前，避免"当前 Python 缺 PyYAML"时先打一条
    # "解析配置文件失败"的噪音，再被依赖检查挡住。
    if command in ("driver", "install-extension", "fix-adapters", "watchdog"):
        cfg = load_config_local_only(args.config)
        setup_logging(cfg, verbose=args.verbose, level_override=args.log_level)
        if command == "driver":
            return cmd_driver(cfg, args)
        if command == "fix-adapters":
            if getattr(args, "apply", False):
                args.dry_run = False
            return cmd_fix_adapters(cfg, args)
        if command == "watchdog":
            if getattr(args, "remove", False) or getattr(args, "install", False):
                return cmd_watchdog_install(cfg, args)
            return cmd_watchdog(cfg, args)
        return cmd_install_extension()

    cfg = Config.load(args.config)
    setup_logging(cfg, verbose=args.verbose, level_override=args.log_level)

    if requests is None or yaml is None:
        missing = [n for n, m in (("requests", requests), ("PyYAML", yaml)) if m is None]
        LOG.error("当前 Python 缺少依赖: %s", ", ".join(missing))
        LOG.error("解释器: %s", sys.executable)
        LOG.error("请执行: \"%s\" -m pip install -r \"%s\"",
                  sys.executable, Path(__file__).resolve().parent / "requirements.txt")
        LOG.error("提示：机器上可能装了多个 Python，请用装了依赖的那个"
                  "（py -0p 可列出全部解释器）。")
        return 1
    if psutil is None:
        LOG.warning("未安装 psutil，网卡状态检测能力将降级（建议安装: pip install psutil）")

    # ---- 不依赖 AutoPortalAuth 的命令 ------------------------------------
    if command == "selftest":
        return selftest()

    if command == "analyze":
        stats = StatsStore(cfg)
        result = stats.analyze_timeouts()
        summary = stats.summary()
        print(json.dumps({"timeout_analysis": result,
                          "totals": summary["totals"],
                          "total_online": summary["total_online"]},
                         ensure_ascii=False, indent=2))
        if result.get("suggested_keepalive"):
            print(f"\n建议保活间隔: {result['suggested_keepalive']} 秒"
                  f"（可写入 config.yaml -> auth.keepalive.interval）")
        else:
            print("\n样本不足，暂无法给出保活建议（保持 auth.keepalive.interval=0 表示自动）。")
        return 0

    if command == "install":
        ok = install_autostart(cfg, args.config, method=args.method, start_now=args.start_now)
        return 0 if ok else 1

    if command == "uninstall":
        ok = uninstall_autostart()
        LOG.info("卸载完成" if ok else "没有找到需要卸载的自启配置")
        return 0

    if command == "driver":
        return cmd_driver(cfg, args)

    # ---- 需要 AutoPortalAuth 实例的命令 ----------------------------------
    if command == "run" and getattr(args, "interval", None):
        cfg.set("monitor.interval", float(args.interval))

    app = AutoPortalAuth(cfg, config_path=args.config)

    if command == "status":
        status = app.checker.check()
        app.status = status
        app._write_state_file()
        payload = status.to_dict()
        payload["capabilities"] = {
            "selenium": portal_autoclick.selenium_version() if portal_autoclick else "",
            "browser": (portal_autoclick.find_browser(
                cfg.get("browser_automation.browser", "auto"))[0] if portal_autoclick else ""),
            "autoclick_enabled": bool(cfg.get("browser_automation.enabled", True)),
            "extension_dir": str(Path(__file__).resolve().parent / "extension"),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if command == "stats":
        print(json.dumps(app.stats.summary(), ensure_ascii=False, indent=2))
        return 0

    if command == "once":
        return app.run_once(trigger_auth=not getattr(args, "no_trigger", False))

    if command == "autoclick":
        if portal_autoclick is None:
            LOG.error("找不到 portal_autoclick.py（请确认文件完整）")
            return 1
        if not portal_autoclick.selenium_available():
            LOG.error("未安装 selenium，请执行: python -m pip install selenium")
            return 1
        for sel in (getattr(args, "selector", None) or []):
            cfg.set("browser_automation.extra_button_selectors",
                    list(cfg.get("browser_automation.extra_button_selectors") or []) + [sel])
        if getattr(args, "timeout", None):
            cfg.set("browser_automation.timeout", float(args.timeout))

        clicker = portal_autoclick.PortalAutoClicker(cfg)
        if not clicker.available:
            LOG.error("自动点击不可用: %s", clicker.unavailable_reason())
            return 1

        url = getattr(args, "url", None)
        if not url:
            status = app.checker.check()
            LOG.info("当前状态: %s（%s）", status.state.value, status.detail)
            url = status.portal_url
            if not url:
                print("当前网络正常或未发现认证页，无需点击。")
                return 0
            LOG.info("使用探测到的认证页: %s", url)

        if getattr(args, "explain", False):
            rows = clicker.explain(url, headless=not getattr(args, "headed", False))
            if not rows:
                print("没有采集到任何可点击元素（页面可能未加载完或需要登录）")
                return 1
            print(f"{'分数':>7}  {'点击':<4} {'frame':<10} {'元素':<10} 文本 / 属性")
            print("-" * 90)
            for r in rows:
                flag = "YES" if r.get("would_click") else "-"
                ident = f"id={r.get('id','')[:18]!r} cls={r.get('cls','')[:22]!r}"
                print(f"{r['score']:>7.1f}  {flag:<4} {r['frame']:<10} "
                      f"<{r['tag']:<8}> {r['text'][:34]!r}  {ident}")
            best = rows[0]
            print("-" * 90)
            print(f"最高分: {best['score']} ({best['text'][:40]!r}) "
                  f"{'会被点击' if best.get('would_click') else '低于阈值，不会点击'}")
            return 0

        result = clicker.click(
            url,
            verify=lambda: app.checker.is_online(),
            headless=False if getattr(args, "headed", False) else None,
            keep_open=True if getattr(args, "keep_open", False) else None,
        )
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.success else 2

    # ---- run：常驻守护 ---------------------------------------------------
    # 进程级退出诊断：硬崩溃(native)/未捕获异常/线程异常 全部落盘，
    # 避免再出现"日志戛然而止、只能靠系统事件倒推死因"的情况。
    install_crash_diagnostics(cfg)

    lock = None
    if cfg.get("app.single_instance", True) and not getattr(args, "no_lock", False):
        lock = SingleInstance(cfg.resolve_path(cfg.get("app.lock_file", "data/app.lock")))
        if not lock.acquire():
            return 1
    try:
        return app.run()
    except KeyboardInterrupt:
        LOG.info("用户中断")
        return 0
    except Exception as exc:
        LOG.exception("运行时发生未处理异常: %s", exc)
        return 1
    finally:
        if lock:
            lock.release()


if __name__ == "__main__":
    sys.exit(main())
