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
import collections
import copy
import ctypes
import json
import logging
import logging.handlers
import os
import platform
import re
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

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
        "wake_grace": 3,           # 唤醒后等待协议栈就绪的秒数
        "wake_fast_probes": 12,    # 唤醒后快速探测的次数（每 2 秒一次）
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
        "score_threshold": 5,          # 低于该分数宁可不点，避免乱点
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
            try:
                cfg_path.parent.mkdir(parents=True, exist_ok=True)
                with cfg_path.open("w", encoding="utf-8") as f:
                    f.write("# AutoPortalAuth 默认配置（由程序自动生成）\n")
                    yaml.safe_dump(DEFAULT_CONFIG, f, allow_unicode=True, sort_keys=False)
                print(f"[i] 未找到配置文件，已生成默认配置: {cfg_path}", file=sys.stderr)
            except Exception as exc:  # 配置目录不可写时，仅使用内置默认值
                print(f"[!] 生成默认配置失败({exc})，将使用内置默认值", file=sys.stderr)
            return cfg

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
# 3. 数据结构
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
# 4. HTML 解析：抓取登录表单 / meta refresh
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
        })

    # ---- 物理链路 ---------------------------------------------------------
    def link_info(self) -> LinkInfo:
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
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
        except Exception as exc:
            LOG.debug("读取网卡信息失败: %s", exc)
            ip = self.local_outbound_ip()
            if ip:
                info.up, info.primary_ip = True, ip
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

    @staticmethod
    def dns_ok(host: str = "www.msftconnecttest.com") -> bool:
        try:
            socket.getaddrinfo(host, 80)
            return True
        except Exception:
            return False

    # ---- HTTP 探测 --------------------------------------------------------
    def _timeout(self) -> Tuple[float, float]:
        return (float(self.cfg.get("detect.connect_timeout", 3)),
                float(self.cfg.get("detect.read_timeout", 5)))

    def probe_target(self, target: Dict[str, Any]) -> ProbeResult:
        """探测单个目标，判定：ok / portal / error。"""
        name = target.get("name") or target.get("url") or "?"
        url = target["url"]
        expect_status = target.get("expect_status")
        expect_contains = target.get("expect_contains", "")
        res = ProbeResult(target=name, url=url)
        started = time.time()
        try:
            resp = self._session.get(url, timeout=self._timeout(), allow_redirects=False)
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
            res.final_url = self._follow_redirects(resp, res.redirect_chain)
            res.detail = f"HTTP {resp.status_code} -> {res.final_url}"
            if self.cfg.get("detect.probe_portal_page", True):
                html = self._fetch_portal_page(res.final_url)
                res.body_sample = html[:4000]
            return res

        body = resp.text or ""

        # 情况 B：状态码不符（例如期望 204 却拿到 200 的认证页）
        if expect_status is not None and resp.status_code != expect_status:
            res.kind = "portal"
            res.final_url = resp.url
            res.detail = f"期望 HTTP {expect_status}，实际 {resp.status_code}（疑似认证页）"
            res.body_sample = body[:4000]
            return res

        # 情况 C：内容不符（例如期望 "Microsoft Connect Test" 却拿到登录页）
        if expect_contains and expect_contains not in body:
            res.kind = "portal"
            res.final_url = resp.url
            res.detail = f"响应内容不含预期关键字 {expect_contains!r}"
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
            return (resp.text or "")[:limit]
        except Exception as exc:
            LOG.debug("抓取认证页失败 %s: %s", url, exc)
            return ""

    # ---- 综合判定 ---------------------------------------------------------
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
            html = portal_result.body_sample
            if not html and self.cfg.get("detect.probe_portal_page", True):
                html = self._fetch_portal_page(status.portal_url)
            status.fingerprint = guess_vendor(status.portal_url, html)
            status.fingerprint.portal_url = status.portal_url
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
                verify=lambda: self.checker.check().state is NetState.INTERNET_OK,
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
            LOG.info("自动点击完成认证：点击了「%s」，勾选 %d 项，用时 %.1fs",
                     result.clicked_text, len(result.checkboxes or []), result.duration)
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

    def auto_login(self, status: NetStatus) -> bool:
        """尝试用配置的账号密码自动登录，然后验证是否真的联网成功。"""
        al = self.cfg.get("auth.auto_login") or {}
        if not al.get("enabled"):
            return False
        if not al.get("username") or not al.get("password"):
            LOG.warning("已启用自动登录但未配置用户名/密码，跳过")
            return False
        if not status.portal_url:
            return False

        target = status.portal_url
        form = status.fingerprint.login_form if status.fingerprint else None
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

        # 提交后轮询验证，直到超时
        deadline = time.time() + float(al.get("verify_timeout", 25))
        while time.time() < deadline:
            time.sleep(2)
            verify = self.checker.check()
            if verify.state is NetState.INTERNET_OK:
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

        # 1) 有账号密码 -> 优先静默自动登录（最省事、无需人工）
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
        self.open_browser(portal_url, force=force_browser)
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
            self._sleep(interval, wake_fast=True)
            if self.stop_event.is_set():
                break
            self._tick()

        self._end_session("program_exit")
        self.stats.save(force=True)
        self.watcher.stop()
        LOG.info("已退出。")

    def _sleep(self, seconds: float, wake_fast: bool = False) -> None:
        """可中断休眠：同时监听停止信号与唤醒事件，唤醒后立即返回继续检测。"""
        end = time.monotonic() + seconds
        fast_probes = int(self.cfg.get("monitor.wake_fast_probes", 0)) if wake_fast else 0
        fast_used = 0
        while not self.stop_event.is_set():
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            self.stop_event.wait(min(0.5, remaining))
            events = self.watcher.poll()
            if "suspend" in events:
                # 休眠期间不做任何事，等唤醒事件
                LOG.debug("系统进入休眠")
            if "resume" in events:
                self.after_wake = True
                self.stats.add_wake_event()
                self.notifier.on_wake()
                grace = float(self.cfg.get("monitor.wake_grace", 3))
                LOG.info("系统已唤醒，%ss 后开始检测网络...", grace)
                self.stop_event.wait(grace)
                # 唤醒后前几次快速探测，尽快恢复网络
                if fast_used < fast_probes:
                    fast_used += 1
                    return
                end = time.monotonic() + 2.0

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
        self.trigger._last_browser_url = ""   # 已恢复，允许下次用浏览器

        if self.session_start is None:
            self.session_start = time.time()
            if prev.state is NetState.PORTAL_REQUIRED or self.after_wake or initial:
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
        # 区分"空闲超时"和"掉线后重新认证"：链路一直在，说明是会话被空闲清理
        if prev.state is NetState.INTERNET_OK:
            LOG.warning("检测到 Portal 拦截（厂商=%s）：%s", vendor, status.detail)
            self._end_session("idle_timeout", status)
        elif initial:
            LOG.warning("启动时检测到需要认证（厂商=%s）", vendor)
        else:
            LOG.info("仍在等待认证（厂商=%s, 第 %d 次尝试）", vendor, self._fail_streak + 1)

        if not self.cfg.get("auth.enabled", True):
            LOG.warning("认证触发已被配置关闭（auth.enabled=false），仅报告状态")
            return

        recovered = self.trigger.trigger(status)

        if recovered:
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
def autostart_command(cfg: Config, config_path: Optional[str]) -> Tuple[List[str], str]:
    """返回 (命令参数列表, 用于展示的命令行字符串)。"""
    exe = sys.executable
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

    sub.add_parser("install-extension", parents=[common],
                   help="打开浏览器扩展管理页（方案 C）")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    cfg = Config.load(args.config)
    setup_logging(cfg, verbose=args.verbose, level_override=args.log_level)

    if requests is None or yaml is None:
        missing = [n for n, m in (("requests", requests), ("PyYAML", yaml)) if m is None]
        LOG.error("缺少依赖: %s，请执行: pip install -r requirements.txt", ", ".join(missing))
        return 1
    if psutil is None:
        LOG.warning("未安装 psutil，网卡状态检测能力将降级（建议安装: pip install psutil）")

    command = args.command or "run"

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
        if portal_autoclick is None:
            LOG.error("找不到 portal_autoclick.py（请确认文件完整）")
            return 1
        if not portal_autoclick.selenium_available():
            LOG.error("未安装 selenium，请执行: python -m pip install selenium")
            return 1
        if not args.download:
            key, exe = portal_autoclick.find_browser(args.browser)
            print(json.dumps({
                "selenium": portal_autoclick.selenium_version(),
                "browser": key or None,
                "executable": exe or None,
            }, ensure_ascii=False, indent=2))
            if not key:
                LOG.error("未找到 Edge / Chrome")
                return 1
            return 0
        ok, msg = portal_autoclick.ensure_driver(cfg, args.browser,
                                                 headless=not args.headed)
        (LOG.info if ok else LOG.error)(msg)
        if not ok:
            LOG.info("提示：首次下载驱动需要能上网；可在能上网时先执行一次本命令。")
        return 0 if ok else 1

    if command == "install-extension":
        return cmd_install_extension()

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
            verify=lambda: app.checker.check().state is NetState.INTERNET_OK,
            headless=False if getattr(args, "headed", False) else None,
            keep_open=True if getattr(args, "keep_open", False) else None,
        )
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.success else 2

    # ---- run：常驻守护 ---------------------------------------------------
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
