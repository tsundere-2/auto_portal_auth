#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portal_autoclick.py —— Portal 认证页面"自动点击"引擎（方案 A：Selenium）
=======================================================================

解决的问题
----------
浏览器已经自动打开了认证页，但页面上的"连接 / 登录"按钮仍然要人手点一下。
本模块用 WebDriver 真正去操作浏览器：

    1. 打开认证页（可复用专用浏览器配置，保留"记住我"、MAC 无感认证所需的状态）
    2. 逐层扫描 DOM（含 iframe / frame / Shadow DOM）
    3. 自动勾选"同意服务条款 / 我已阅读"之类的复选框
    4. 按"文本 + 属性 + 元素类型 + 是否在表单内"打分，找出最像"连接/登录"的元素
    5. 点击它，并自动接受 alert / confirm、跟进 window.open 弹出窗口
    6. 轮询真实网络连通性（由上层传入的回调判定），确认是否真的恢复上网
    7. 失败时保存截图 + HTML 快照，便于事后调参

设计要点
--------
* **懒加载 selenium**：没装 selenium 时模块照常可导入，只是 `available` 为 False，
  上层自动退回"打开浏览器让用户点"的老方案，不会让守护进程崩掉。
* **headless 自动降级**：`headless: auto` 会先尝试无头（不打扰用户），
  失败后自动换可见窗口再试一次（有些 Portal 的 JS 在无头下会拒绝执行）。
* **离线可用**：Selenium 4.6+ 由 Selenium Manager 自动管理驱动，但**首次需要联网**
  下载 msedgedriver/chromedriver。请先在有网时执行一次：
      python auto_portal_auth.py driver --download
  之后驱动会缓存在 ~/.cache/selenium，断网也能用。
* **不做危险操作**：只点击"可见、未禁用、分数超过阈值"的元素；
  明确的"取消/退出/断开/下载/注册/忘记密码"等会被扣成负分，绝不会乱点。

独立使用
--------
    from portal_autoclick import PortalAutoClicker
    clicker = PortalAutoClicker(cfg)              # cfg 需支持 cfg.get("a.b")
    result = clicker.click("http://10.0.0.1/portal", verify=my_check)
    print(result.success, result.clicked_text)

命令行入口在 auto_portal_auth.py 里：
    python auto_portal_auth.py autoclick --explain
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

LOG = logging.getLogger("portal.autoclick")

# ---------------------------------------------------------------------------
# 1. 按钮文本权重表
#    规则：文本"包含"关键词即得分；完全相等额外 +2。
#    权重越高，说明越像"完成认证"的按钮。
# ---------------------------------------------------------------------------
DEFAULT_BUTTON_TEXTS: Dict[str, float] = {
    # 中文：完成认证类（最高优先级）
    "同意并登录": 12, "同意并连接": 12, "同意并上网": 12, "同意并继续": 9,
    "一键登录": 10, "一键连接": 10, "一键上网": 10,
    "立即登录": 9, "立即连接": 9, "立即上网": 9,
    "点击登录": 9, "点击连接": 9, "点击上网": 9,
    "开始上网": 9, "免费上网": 8, "认证上网": 9,
    "连接": 8, "登录": 8, "登陆": 8, "认证": 7, "上网": 7,
    "确认": 4, "确定": 4, "继续": 3, "同意": 5,
    # 英文
    "access internet": 9, "quick login": 10, "click to connect": 9,
    "connect": 8, "login": 8, "log in": 8, "sign in": 8, "signin": 8,
    "authenticate": 8, "authorize": 6,
    "confirm": 4, "continue": 3, "agree": 5, "i agree": 7, "accept": 4,
}

# 明确"不要点"的词：这些元素通常是取消/退出/干扰项
DEFAULT_DENY_TEXTS: List[str] = [
    "取消", "关闭", "返回", "退出", "断开", "注销", "下线", "帮助", "下载",
    "注册", "忘记", "重置", "修改", "语言", "切换", "客服", "公告", "详情",
    "了解更多", "常见问题", "使用说明", "客户端", "二维码", "扫码", "其他",
    # "状态文字"不是按钮：已连接 / 已认证 / 在线 等
    "已连接", "已登陆", "已登录", "已认证", "已经连接", "已经登录", "已经认证",
    "当前在线", "已在线", "连接成功", "登录成功", "认证成功", "上网成功",
    "cancel", "close", "back", "exit", "logout", "log out", "sign out",
    "disconnect", "help", "download", "register", "sign up", "forgot",
    "reset", "language", "english", "more", "faq", "qrcode", "scan",
    "already connected", "already logged in", "you are online", "success",
]

# 属性（id/class/name/onclick/href）里的关键词加分
ATTR_KEYWORDS: Dict[str, float] = {
    "connect": 3, "login": 3, "signin": 3, "submit": 3, "auth": 2,
    "connect-btn": 5, "login-btn": 5, "loginbutton": 5, "submit-btn": 4,
    "btn-primary": 2, "btn-success": 2, "primary": 1,
    "连接": 3, "登录": 3, "认证": 2, "上网": 3,
}

# 条款复选框的文本特征
TERMS_KEYWORDS = [
    "同意", "已阅读", "已同意", "服务条款", "服务协议", "隐私政策", "隐私",
    "用户协议", "我已", "阅读并同意", "agree", "terms", "policy",
    "privacy", "accept", "i have read",
]

# 认证成功的页面文本（仅在没有外部 verify 回调时作为弱判定）
SUCCESS_TEXTS = [
    "认证成功", "登录成功", "连接成功", "已连接", "上网成功", "已上线",
    "您已在线", "已经在线", "success", "connected", "authenticated",
]

# ---------------------------------------------------------------------------
# 2. 注入页面的 JS
# ---------------------------------------------------------------------------
# 采集"可点击候选元素"。为了支持 Shadow DOM，递归遍历 shadowRoot。
# 元素本体保存在 window.__APA_ELEMENTS 里，Python 侧只用下标索引去点，
# 避免 WebElement 在切换 frame / 页面刷新后失效。
_JS_COLLECT = r"""
return (function (extraSel) {
  if (!window.__APA_ELEMENTS) window.__APA_ELEMENTS = [];
  var SEL = 'button,input[type="submit"],input[type="button"],input[type="image"],a,' +
            '[role="button"],[onclick],[class*="btn"],[class*="button"],' +
            '[class*="login"],[class*="connect"],[class*="submit"],' +
            '[id*="btn"],[id*="login"],[id*="connect"],[id*="submit"]';
  if (extraSel) SEL += ',' + extraSel;
  var MAXN = 500;

  function visible(el) {
    try {
      var r = el.getBoundingClientRect();
      if (!r || r.width < 2 || r.height < 2) return false;
      var s = window.getComputedStyle(el);
      if (!s) return true;
      if (s.visibility === 'hidden' || s.display === 'none') return false;
      if (parseFloat(s.opacity || '1') === 0) return false;
      return true;
    } catch (e) { return false; }
  }

  var elements = [], summaries = [], seen = new Set();

  function walk(root) {
    var nodes;
    try { nodes = root.querySelectorAll(SEL); } catch (e) { return; }
    for (var i = 0; i < nodes.length && elements.length < MAXN; i++) {
      var el = nodes[i];
      if (seen.has(el)) continue;
      seen.add(el);
      var r;
      try { r = el.getBoundingClientRect(); } catch (e) { r = {left:0,top:0,width:0,height:0}; }
      elements.push(el);
      summaries.push({
        tag: (el.tagName || '').toLowerCase(),
        id: el.id || '',
        cls: (typeof el.className === 'string' ? el.className : (el.getAttribute('class') || '')).slice(0, 160),
        name: el.getAttribute('name') || '',
        type: (el.getAttribute('type') || '').toLowerCase(),
        text: ((el.innerText || el.value || el.getAttribute('aria-label') ||
                el.getAttribute('title') || el.getAttribute('alt') || '') + '')
                .replace(/\s+/g, ' ').trim().slice(0, 140),
        onclick: (el.getAttribute('onclick') || '').slice(0, 220),
        href: (el.getAttribute('href') || '').slice(0, 220),
        visible: visible(el),
        disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
        in_form: !!(el.closest && el.closest('form')),
        w: Math.round(r.width), h: Math.round(r.height)
      });
    }
    // 递归 Shadow DOM
    var all;
    try { all = root.querySelectorAll('*'); } catch (e) { return; }
    for (var j = 0; j < all.length; j++) {
      var sr = all[j].shadowRoot;
      if (sr) walk(sr);
    }
  }

  window.__APA_ELEMENTS = elements;
  elements.length = 0; summaries.length = 0;
  walk(document);
  return summaries;
})(arguments[0]);
"""

_JS_CLICK = r"""
return (function (i) {
  var el = window.__APA_ELEMENTS && window.__APA_ELEMENTS[i];
  if (!el) return 'missing';
  try { el.scrollIntoView({block: 'center', inline: 'center'}); } catch (e) {}
  try { el.focus(); } catch (e) {}
  try {
    el.click();
    return 'clicked';
  } catch (e) {
    try {
      el.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true, view: window}));
      return 'dispatched';
    } catch (e2) { return 'failed:' + e2; }
  }
})(arguments[0]);
"""

# 采集复选框 / 条款同意框
_JS_COLLECT_BOXES = r"""
return (function () {
  var SEL = 'input[type="checkbox"],[role="checkbox"],label';
  var out = [], els = [], seen = new Set();

  function visible(el) {
    try {
      var r = el.getBoundingClientRect();
      if (!r || r.width < 2 || r.height < 2) return false;
      var s = window.getComputedStyle(el);
      if (!s) return true;
      return !(s.visibility === 'hidden' || s.display === 'none' || parseFloat(s.opacity || '1') === 0);
    } catch (e) { return false; }
  }

  function boxText(el) {
    var t = '';
    try {
      var lab = el.closest ? el.closest('label') : null;
      if (lab) t = lab.innerText || '';
      if (!t && el.id) {
        var l2 = document.querySelector('label[for="' + el.id + '"]');
        if (l2) t = l2.innerText || '';
      }
      if (!t && el.parentElement) t = el.parentElement.innerText || '';
    } catch (e) {}
    return (t || '').replace(/\s+/g, ' ').trim().slice(0, 140);
  }

  var nodes;
  try { nodes = document.querySelectorAll(SEL); } catch (e) { return []; }
  for (var i = 0; i < nodes.length && out.length < 60; i++) {
    var el = nodes[i];
    if (seen.has(el)) continue;
    if (el.tagName && el.tagName.toLowerCase() === 'label') {
      // 只保留"看起来像条款同意框"的 label
      var lt = (el.innerText || '').replace(/\s+/g, ' ').trim();
      if (!lt || lt.length > 160) continue;
      if (!/同意|已阅读|服务条款|服务协议|隐私|用户协议|agree|terms|policy|privacy|accept/i.test(lt)) continue;
      if (!visible(el)) continue;
      // 关键：如果 label 关联了真实的 checkbox，就交给那个 checkbox 处理。
      // 否则会出现"勾选 input -> 再点 label -> 又把勾去掉"的经典 bug。
      var linked = null;
      try {
        if (el.htmlFor) linked = document.getElementById(el.htmlFor);
        if (!linked) linked = el.querySelector('input[type="checkbox"]');
      } catch (e) {}
      if (linked) continue;
      seen.add(el);
      els.push(el);
      out.push({
        tag: 'label', id: el.id || '', text: lt.slice(0, 140), checked: null, visible: true,
        ticked: el.getAttribute('data-apa-ticked') === '1'
      });
      continue;
    }
    if (!visible(el)) continue;
    seen.add(el);
    els.push(el);
    var checkedState = null;
    if (typeof el.checked === 'boolean') checkedState = el.checked;
    else if (el.getAttribute('aria-checked') === 'true') checkedState = true;
    else if (el.getAttribute('aria-checked') === 'false') checkedState = false;
    out.push({
      tag: (el.tagName || '').toLowerCase(),
      id: el.id || '',
      text: boxText(el),
      checked: checkedState,
      visible: true,
      ticked: el.getAttribute('data-apa-ticked') === '1'
    });
  }
  window.__APA_BOXES = els;
  return out;
})();
"""

_JS_TICK_BOX = r"""
return (function (i) {
  var el = window.__APA_BOXES && window.__APA_BOXES[i];
  if (!el) return 'missing';
  if (el.getAttribute('data-apa-ticked') === '1') return 'already';
  try { el.scrollIntoView({block: 'center'}); } catch (e) {}
  try {
    el.click();
    el.setAttribute('data-apa-ticked', '1');
    return 'clicked';
  } catch (e) {
    try {
      el.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true, view: window}));
      el.setAttribute('data-apa-ticked', '1');
      return 'dispatched';
    } catch (e2) { return 'failed'; }
  }
})(arguments[0]);
"""

_JS_RESET_DOC = r"""
return (function () {
  window.__APA_ELEMENTS = [];
  window.__APA_BOXES = [];
  return true;
})();
"""


# ---------------------------------------------------------------------------
# 3. 结果对象
# ---------------------------------------------------------------------------
@dataclass
class AutoclickResult:
    success: bool = False          # 点击后确认恢复联网
    clicked: bool = False          # 是否真的点了某个按钮
    clicked_text: str = ""
    clicked_tag: str = ""
    score: float = 0.0
    checkboxes: List[str] = field(default_factory=list)
    frames: int = 0
    browser: str = ""
    headless: bool = False
    duration: float = 0.0
    attempts: int = 0
    error: str = ""
    hint: str = ""
    screenshot: str = ""
    html_dump: str = ""
    candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


# ---------------------------------------------------------------------------
# 4. 浏览器 / 驱动辅助
# ---------------------------------------------------------------------------
def selenium_available() -> bool:
    try:
        import selenium  # noqa: F401
        return True
    except Exception:
        return False


def selenium_version() -> str:
    try:
        import selenium
        return getattr(selenium, "__version__", "?")
    except Exception:
        return ""


def find_browser(prefer: str = "auto") -> Tuple[str, str]:
    """返回 (browser_key, executable_path)；找不到返回 ("", "")。"""
    system = platform.system()
    candidates: List[Tuple[str, List[str]]] = []
    if system == "Windows":
        base = [
            ("edge", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            ("edge", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            ("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            ("chrome", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
            ("chrome", os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")),
        ]
        candidates = [(k, [p]) for k, p in base]
    elif system == "Darwin":
        candidates = [
            ("edge", ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]),
            ("chrome", ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]),
        ]
    else:
        candidates = [
            ("chrome", ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
                        "/usr/bin/chromium", "/usr/bin/chromium-browser",
                        "/snap/bin/chromium"]),
            ("edge", ["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"]),
        ]

    found: Dict[str, str] = {}
    for key, paths in candidates:
        for p in paths:
            if p and Path(p).exists():
                found.setdefault(key, p)

    if prefer in ("edge", "chrome") and prefer in found:
        return prefer, found[prefer]
    for key in ("edge", "chrome"):
        if key in found:
            return key, found[key]
    # 最后尝试 PATH
    for exe in ("msedge", "google-chrome", "chromium", "chrome"):
        p = shutil.which(exe)
        if p:
            key = "edge" if "edge" in exe else "chrome"
            return key, p
    return "", ""


def _chrome_like_options(browser: str, cfg, headless: bool, profile_dir: Optional[Path]):
    """构造 Edge/Chrome 的启动参数。"""
    if browser == "edge":
        from selenium.webdriver.edge.options import Options
    else:
        from selenium.webdriver.chrome.options import Options

    opts = Options()
    opts.add_argument("--no-first-run")
    opts.add_argument("--no-default-browser-check")
    opts.add_argument("--disable-notifications")
    opts.add_argument("--disable-popup-blocking")          # Portal 经常用 window.open
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--disable-features=PasswordLeakDetection,AutofillServerCommunication")
    opts.add_argument("--password-store=basic")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument("--lang=zh-CN")
    if headless:
        opts.add_argument("--headless=new")
        opts.add_argument("--disable-gpu")
    if cfg.get("browser_automation.no_proxy", True):
        # 认证页必须直连；系统代理会把请求带偏
        opts.add_argument("--no-proxy-server")
    if cfg.get("browser_automation.ignore_cert_errors", True):
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--allow-insecure-localhost")
        # 自签证书的 Portal 很常见
        try:
            opts.set_capability("acceptInsecureCerts", True)
        except Exception:
            pass
    if profile_dir:
        try:
            profile_dir.mkdir(parents=True, exist_ok=True)
            opts.add_argument(f"--user-data-dir={profile_dir}")
        except Exception as exc:
            LOG.debug("无法使用专用浏览器配置目录 %s: %s", profile_dir, exc)
    try:
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        opts.add_experimental_option("useAutomationExtension", False)
    except Exception:
        pass
    binary = cfg.get("browser_automation.binary", "") or ""
    if binary:
        opts.binary_location = binary
    return opts


def create_driver(cfg, browser: str = "auto", headless: bool = True,
                  use_profile: bool = True):
    """创建一个 WebDriver；调用方负责 quit()。"""
    from selenium import webdriver  # 懒加载

    key, exe = find_browser(browser)
    if not key:
        raise RuntimeError("未找到 Edge / Chrome，请安装其一，或在 config.yaml 里设置 browser_automation.binary")

    profile = ""
    if use_profile:
        profile = cfg.get("browser_automation.profile_dir", "data/browser_profile") or ""
    profile_dir = cfg.resolve_path(profile) if profile else None

    opts = _chrome_like_options(key, cfg, headless, profile_dir)
    LOG.debug("启动浏览器: %s (%s) headless=%s profile=%s", key, exe, headless, profile_dir)

    if key == "edge":
        driver = webdriver.Edge(options=opts)
    else:
        driver = webdriver.Chrome(options=opts)

    page_timeout = float(cfg.get("browser_automation.page_load_timeout", 20))
    try:
        driver.set_page_load_timeout(page_timeout)
    except Exception:
        pass
    try:
        driver.set_script_timeout(15)
    except Exception:
        pass
    # 进一步降低"自动化浏览器"特征（部分 Portal 的 JS 会检测）
    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        })
    except Exception:
        pass
    return key, driver


# ---------------------------------------------------------------------------
# 5. 打分
# ---------------------------------------------------------------------------
def score_candidate(c: Dict[str, Any],
                    button_texts: Dict[str, float],
                    deny_texts: List[str]) -> float:
    """给一个候选元素打分，分数越高越像"完成认证"的按钮。"""
    text = (c.get("text") or "").strip()
    text_l = text.lower()
    attrs = " ".join([
        str(c.get("id", "")), str(c.get("cls", "")), str(c.get("name", "")),
        str(c.get("onclick", "")), str(c.get("href", "")),
    ]).lower()

    score = 0.0
    if not c.get("visible"):
        score -= 100.0          # 不可见的基本不可能是要点的按钮
    if c.get("disabled"):
        score -= 60.0

    # 文本匹配（取最匹配的那个关键词）
    best = 0.0
    for kw, weight in button_texts.items():
        k = kw.lower()
        if k and k in text_l:
            add = weight + (2.0 if text_l == k else 0.0)
            best = max(best, add)
    score += best

    # 属性匹配
    for kw, weight in ATTR_KEYWORDS.items():
        if kw in attrs:
            score += weight

    if c.get("type") == "submit":
        score += 3.0
    if c.get("tag") == "button":
        score += 2.0
    if c.get("in_form"):
        score += 2.0

    # 很长的文本通常是说明文字而不是按钮
    if len(text) > 40:
        score -= 3.0

    # 干扰项
    for kw in deny_texts:
        if kw and kw.lower() in text_l:
            score -= 14.0

    return round(score, 2)


def looks_like_portal_page(url: str, title: str, body_sample: str) -> bool:
    """给浏览器扩展 / --explain 用的粗判：这个页面像不像校园网认证页。"""
    hay = f"{url} {title} {body_sample}".lower()
    keys = ("portal", "认证", "登录", "上网", "connect", "login", "eportal",
            "srun", "drcom", "wlan", "校园网", "网络接入", "welcome")
    return any(k in hay for k in keys)


# ---------------------------------------------------------------------------
# 6. 主类
# ---------------------------------------------------------------------------
class PortalAutoClicker:
    """自动打开 Portal 页面并完成"勾选 + 点击"的引擎。"""

    def __init__(self, cfg, logger: Optional[logging.Logger] = None):
        self.cfg = cfg
        self.log = logger or LOG
        self.button_texts = dict(DEFAULT_BUTTON_TEXTS)
        for kw in (cfg.get("browser_automation.button_texts") or []):
            self.button_texts[str(kw)] = 9.0       # 用户自定义的关键词给高权重
        self.deny_texts = list(DEFAULT_DENY_TEXTS) + [
            str(x) for x in (cfg.get("browser_automation.button_deny_texts") or [])
        ]
        self.threshold = float(cfg.get("browser_automation.score_threshold", 5))
        self.dump_dir = cfg.resolve_path(
            cfg.get("browser_automation.dump_dir", "data/autoclick"))

    # -- 对外能力 ---------------------------------------------------------
    @property
    def available(self) -> bool:
        return bool(self.cfg.get("browser_automation.enabled", True)) and selenium_available()

    def unavailable_reason(self) -> str:
        if not self.cfg.get("browser_automation.enabled", True):
            return "browser_automation.enabled = false"
        if not selenium_available():
            return "未安装 selenium（pip install selenium）"
        if not find_browser(self.cfg.get("browser_automation.browser", "auto"))[0]:
            return "未找到 Edge / Chrome 浏览器"
        return ""

    def _extra_selectors(self) -> str:
        """用户在 config.yaml 里追加的 CSS 选择器（逗号分隔）。"""
        try:
            items = self.cfg.get("browser_automation.extra_button_selectors") or []
            return ",".join(str(x) for x in items if x)
        except Exception:
            return ""

    # -- 采集 / 解释 -------------------------------------------------------
    def explain(self, url: str, max_frames: Optional[int] = None,
                headless: bool = True) -> List[Dict[str, Any]]:
        """打开页面并返回各 frame 内所有候选元素的打分表（不点击）。"""
        result: List[Dict[str, Any]] = []
        key, driver = create_driver(
            self.cfg,
            browser=self.cfg.get("browser_automation.browser", "auto"),
            headless=headless,
        )
        try:
            try:
                driver.get(url)
            except Exception as exc:
                self.log.warning("页面加载超时/失败（继续尝试解析）: %s", exc)
            time.sleep(float(self.cfg.get("browser_automation.settle_seconds", 1.5)))
            depth = int(max_frames if max_frames is not None
                        else self.cfg.get("browser_automation.max_frame_depth", 3))

            def walk(d: Any, level: int, frame_path: str) -> None:
                try:
                    d.execute_script(_JS_RESET_DOC)
                    cands = d.execute_script(_JS_COLLECT, self._extra_selectors()) or []
                except Exception:
                    cands = []
                scored = []
                for c in cands:
                    c = dict(c)
                    c["score"] = score_candidate(c, self.button_texts, self.deny_texts)
                    scored.append(c)
                scored.sort(key=lambda x: x.get("score", 0), reverse=True)
                for c in scored[:15]:
                    c["frame"] = frame_path
                    c["would_click"] = c["score"] >= self.threshold
                    result.append(c)
                if level >= depth:
                    return
                try:
                    n = int(d.execute_script(
                        "return document.querySelectorAll('iframe,frame').length") or 0)
                except Exception:
                    return
                for i in range(n):
                    try:
                        d.switch_to.frame(i)
                    except Exception:
                        continue
                    try:
                        walk(d, level + 1, f"{frame_path}>{i}")
                    finally:
                        try:
                            d.switch_to.parent_frame()
                        except Exception:
                            try:
                                d.switch_to.default_content()
                            except Exception:
                                pass

            walk(driver, 0, "top")
            result.sort(key=lambda x: x.get("score", 0), reverse=True)
            return result
        finally:
            try:
                driver.quit()
            except Exception:
                pass

    # -- 主入口 -----------------------------------------------------------
    def click(self, portal_url: str,
              verify: Optional[Callable[[], bool]] = None,
              headless: Optional[bool] = None,
              keep_open: Optional[bool] = None) -> AutoclickResult:
        """打开认证页、勾选条款、点击连接，并验证是否恢复联网。

        verify: 返回 True 表示"已经能上网"。为 None 时退化为检查页面上
                是否出现"认证成功/已连接"等字样（弱判定）。
        """
        started = time.time()
        res = AutoclickResult()
        reason = self.unavailable_reason()
        if reason:
            res.error = reason
            res.hint = "安装 selenium 并在 config.yaml 中启用 browser_automation"
            return res

        browser_pref = self.cfg.get("browser_automation.browser", "auto")
        total_timeout = float(self.cfg.get("browser_automation.timeout", 30))
        max_attempts = int(self.cfg.get("browser_automation.max_attempts", 2))

        # headless: auto -> 先无头，失败再可见
        if headless is None:
            mode = self.cfg.get("browser_automation.headless", "auto")
            modes = [True, False] if mode == "auto" else [bool(mode)]
        else:
            modes = [bool(headless)]

        for idx, hl in enumerate(modes):
            res.headless = hl
            driver = None
            try:
                try:
                    key, driver = create_driver(self.cfg, browser_pref, hl)
                except Exception as first_exc:
                    # 专用配置目录被占用/损坏时（Chrome 已用同一目录启动等），
                    # 退回临时配置再试一次，保证认证不被卡住。
                    if self.cfg.get("browser_automation.profile_dir"):
                        self.log.debug("专用浏览器配置启动失败(%s)，改用临时配置重试", first_exc)
                        key, driver = create_driver(self.cfg, browser_pref, hl, use_profile=False)
                    else:
                        raise
                res.browser = key
                budget = total_timeout / max(1, len(modes)) if len(modes) > 1 else total_timeout
                ok = self._run_session(driver, portal_url, res, verify,
                                       attempts=max_attempts, budget=budget)
                res.success = ok
                if ok:
                    self._log_done(res, started)
                    return res
                # 本次没成功：如果还有"可见窗口"这一档，继续重试
                if idx < len(modes) - 1:
                    self.log.info("无头模式未能确认联网，改用可见窗口重试 ...")
            except Exception as exc:
                res.error = f"{type(exc).__name__}: {exc}"
                self.log.warning("浏览器自动化失败（%s）: %s", "headless" if hl else "headed", exc)
                if "driver" in str(exc).lower() or "manager" in str(exc).lower():
                    res.hint = ("首次使用需要联网下载浏览器驱动；请先在有网时执行: "
                                "python auto_portal_auth.py driver --download")
            finally:
                try:
                    if driver is not None and not res.success:
                        self._dump_artifacts(driver, res, prefix="fail")
                except Exception:
                    pass
                try:
                    keep = bool(keep_open if keep_open is not None
                                else self.cfg.get("browser_automation.keep_browser_open", False))
                    if driver is not None and not keep:
                        driver.quit()
                except Exception:
                    pass

        res.duration = round(time.time() - started, 2)
        return res

    # -- 单次浏览器会话 ----------------------------------------------------
    def _run_session(self, driver, portal_url: str, res: AutoclickResult,
                     verify: Optional[Callable[[], bool]],
                     attempts: int, budget: float) -> bool:
        try:
            driver.get(portal_url)
        except Exception as exc:
            # 认证页经常有自签证书 / 停不下来的加载动画，超时也继续解析
            self.log.debug("页面加载未在超时内完成（继续解析 DOM）: %s", exc)

        settle = float(self.cfg.get("browser_automation.settle_seconds", 1.5))
        time.sleep(settle)

        deadline = time.time() + max(3.0, budget - settle)
        for attempt in range(1, attempts + 1):
            res.attempts = attempt
            clicked = self._walk_frames(driver, res, depth=0)
            if not clicked:
                # 没找到按钮时，等一下 DOM 可能还在渲染
                if verify and verify():
                    return True
                self._dismiss_dialogs(driver)
                time.sleep(1.0)
                continue

            self._dismiss_dialogs(driver)
            self._follow_new_window(driver, res)
            self._dismiss_dialogs(driver)

            if self._wait_verified(driver, verify, deadline):
                return True

            self.log.info("已点击「%s」，但尚未确认联网，准备再试一次 ...", res.clicked_text)
            time.sleep(0.8)
            try:
                driver.switch_to.default_content()
            except Exception:
                pass

        return self._wait_verified(driver, verify, deadline, poll_only=True)

    # -- 遍历 frame --------------------------------------------------------
    def _walk_frames(self, driver, res: AutoclickResult, depth: int) -> bool:
        max_depth = int(self.cfg.get("browser_automation.max_frame_depth", 3))
        res.frames = max(res.frames, depth + 1)

        if self._attempt_here(driver, res):
            return True
        if depth >= max_depth:
            return False

        try:
            n = int(driver.execute_script(
                "return document.querySelectorAll('iframe,frame').length") or 0)
        except Exception:
            return False

        for i in range(n):
            try:
                driver.switch_to.frame(i)
            except Exception:
                continue
            try:
                if self._walk_frames(driver, res, depth + 1):
                    return True
            finally:
                try:
                    driver.switch_to.parent_frame()
                except Exception:
                    try:
                        driver.switch_to.default_content()
                    except Exception:
                        pass
        return False

    def _attempt_here(self, driver, res: AutoclickResult) -> bool:
        # 1) 勾选"同意条款"类复选框
        try:
            boxes = driver.execute_script(_JS_COLLECT_BOXES) or []
        except Exception:
            boxes = []

        skip_terms = bool(self.cfg.get("browser_automation.skip_terms_checkbox", False))
        extra_box_kw = [str(x) for x in (self.cfg.get("browser_automation.checkbox_texts") or [])]
        box_kw = TERMS_KEYWORDS + extra_box_kw

        for i, box in enumerate(boxes):
            text = (box.get("text") or "").strip()
            checked = box.get("checked")
            if checked is True:
                continue          # 已经是勾选状态，绝不能再点（会取消勾选）
            if box.get("ticked"):
                continue          # 本轮已经点过（自定义复选框）
            # label 元素（自定义复选框）也只在文本像"同意条款"时才点
            if not any(k.lower() in text.lower() for k in box_kw):
                continue
            if skip_terms:
                res.checkboxes.append(f"跳过: {text[:40]}")
                continue
            try:
                state = driver.execute_script(_JS_TICK_BOX, i)
                if state in ("clicked", "dispatched"):
                    res.checkboxes.append(text[:60] or f"<{box.get('tag')}>")
                    self.log.info("已勾选条款复选框: %s", (text[:60] or box.get("tag")))
                    time.sleep(0.2)
            except Exception as exc:
                self.log.debug("勾选复选框失败: %s", exc)

        # 2) 采集候选按钮并打分
        try:
            driver.execute_script(_JS_RESET_DOC)
            cands = driver.execute_script(_JS_COLLECT, self._extra_selectors()) or []
        except Exception:
            return False

        best_idx, best = -1, None
        scored: List[Tuple[float, int, Dict[str, Any]]] = []
        for i, c in enumerate(cands):
            c = dict(c)
            c["score"] = score_candidate(c, self.button_texts, self.deny_texts)
            scored.append((c["score"], i, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        if scored and scored[0][0] >= self.threshold:
            best_idx = scored[0][1]
            best = scored[0][2]

        # 3) 没有把握就放弃（宁可不点，也不乱点）
        if best is None:
            if scored:
                self.log.debug("未找到足够可信的按钮（最高分 %.1f < 阈值 %.1f: %r）",
                               scored[0][0], self.threshold, scored[0][2].get("text", "")[:40])
            return False

        # 4) 点击
        res.clicked_text = (best.get("text") or "").strip()[:60] or f"<{best.get('tag')}>"
        res.clicked_tag = best.get("tag", "")
        res.score = best["score"]
        try:
            before_handles = set(driver.window_handles)
        except Exception:
            before_handles = set()
        try:
            state = driver.execute_script(_JS_CLICK, best_idx)
        except Exception as exc:
            self.log.warning("点击元素时出错: %s", exc)
            return False
        if not state or str(state).startswith("failed") or state == "missing":
            self.log.warning("点击未成功（%s），元素可能已失效", state)
            return False

        res.clicked = True
        self.log.info("已点击认证按钮: 「%s」 (tag=%s score=%.1f, %s)",
                      res.clicked_text, res.clicked_tag, res.score, state)
        # 只记录"点击后新出现"的窗口，避免误把浏览器已有的其它窗口当成弹窗
        try:
            self._pending_new_windows = [
                h for h in driver.window_handles if h not in before_handles
            ]
        except Exception:
            self._pending_new_windows = []
        time.sleep(float(self.cfg.get("browser_automation.click_delay", 0.8)))
        return True

    # -- 弹窗 / 新窗口 -----------------------------------------------------
    def _dismiss_dialogs(self, driver) -> None:
        if not self.cfg.get("browser_automation.accept_alerts", True):
            return
        for _ in range(3):
            try:
                alert = driver.switch_to.alert
                text = alert.text
                alert.accept()
                self.log.info("已自动确认弹窗: %s", (text or "")[:60])
            except Exception:
                return

    def _follow_new_window(self, driver, res: AutoclickResult) -> None:
        """点击后 portal 可能 window.open 一个新窗口，需要切过去继续操作。"""
        pending = list(getattr(self, "_pending_new_windows", []) or [])
        self._pending_new_windows = []
        if not pending:
            return
        try:
            original = driver.current_window_handle
        except Exception:
            original = None
        try:
            driver.switch_to.window(pending[-1])
            self.log.info("检测到弹出窗口，已切换过去继续处理")
            time.sleep(0.8)
            # 新窗口里可能还有"确认/继续"按钮
            tmp = AutoclickResult()
            if self._attempt_here(driver, tmp):
                res.clicked = True
                res.clicked_text = tmp.clicked_text or res.clicked_text
                res.score = tmp.score or res.score
            self._dismiss_dialogs(driver)
        except Exception as exc:
            self.log.debug("处理弹出窗口失败: %s", exc)
        finally:
            self._pending_new_windows = []
            try:
                if original:
                    driver.switch_to.window(original)
            except Exception:
                pass

    # -- 验证 -------------------------------------------------------------
    def _wait_verified(self, driver, verify: Optional[Callable[[], bool]],
                       deadline: float, poll_only: bool = False) -> bool:
        interval = float(self.cfg.get("browser_automation.verify_interval", 3))
        while time.time() < deadline:
            if verify is not None:
                try:
                    if verify():
                        return True
                except Exception as exc:
                    self.log.debug("验证回调异常: %s", exc)
            else:
                # 没有外部回调时，退化为看页面文本
                try:
                    src = driver.page_source or ""
                    low = src.lower()
                    if any(t.lower() in low for t in SUCCESS_TEXTS):
                        return True
                except Exception:
                    pass
            time.sleep(max(0.5, interval))
            if poll_only:
                break
        return False

    # -- 诊断产物 ---------------------------------------------------------
    def _dump_artifacts(self, driver, res: AutoclickResult, prefix: str = "dump") -> None:
        if not self.cfg.get("browser_automation.dump_on_failure", True):
            return
        try:
            self.dump_dir.mkdir(parents=True, exist_ok=True)
            tag = datetime.now().strftime("%Y%m%d-%H%M%S")
            if self.cfg.get("browser_automation.screenshot_on_failure", True):
                shot = self.dump_dir / f"{prefix}-{tag}.png"
                try:
                    driver.save_screenshot(str(shot))
                    res.screenshot = str(shot)
                except Exception:
                    pass
            html = self.dump_dir / f"{prefix}-{tag}.html"
            try:
                try:
                    driver.switch_to.default_content()
                except Exception:
                    pass
                source = driver.page_source or ""
                html.write_text(source, encoding="utf-8", errors="replace")
                res.html_dump = str(html)
                if len(source.strip()) < 50:
                    self.log.warning("认证页返回的 HTML 很短，可能被浏览器错误页替代；"
                                     "请查看截图 %s", res.screenshot or "(未保存)")
            except Exception:
                pass
        except Exception as exc:
            self.log.debug("保存诊断文件失败: %s", exc)

    def _log_done(self, res: AutoclickResult, started: float) -> None:
        res.duration = round(time.time() - started, 2)
        res.checkboxes = list(dict.fromkeys(res.checkboxes))   # 去重，便于阅读
        self.log.info("自动点击认证成功（浏览器=%s headless=%s 用时=%.1fs 点击=%r 勾选=%s）",
                      res.browser, res.headless, res.duration,
                      res.clicked_text, res.checkboxes or "无")


# ---------------------------------------------------------------------------
# 7. 预下载驱动（首次必须联网）
# ---------------------------------------------------------------------------
def driver_version(caps: Dict[str, Any]) -> str:
    """从 WebDriver capabilities 里取出真正的**驱动**版本。

    不同浏览器把驱动版本放在不同的厂商命名空间里：
      Chrome -> caps["chrome"]["chromedriverVersion"]
      Edge   -> caps["msedge"]["msedgedriverVersion"]
      Firefox-> caps["moz:geckoDriverVersion"]
    注意 platformName 是操作系统名（windows），不是驱动版本。
    """
    candidates: List[str] = []
    for key, field in (("chrome", "chromedriverVersion"),
                       ("msedge", "msedgedriverVersion")):
        section = caps.get(key)
        if isinstance(section, dict) and section.get(field):
            candidates.append(str(section[field]))
    if caps.get("moz:geckoDriverVersion"):
        candidates.append(str(caps["moz:geckoDriverVersion"]))
    for value in candidates:
        # chromedriver 的值形如 "155.0.4283.62 (a1b2c3...)"，去掉括号里的提交哈希
        return value.split(" (")[0].strip()
    return "?"


def ensure_driver(cfg, browser: str = "auto", headless: bool = True) -> Tuple[bool, str]:
    """创建一次驱动再退出，用于在有网时预先把 msedgedriver/chromedriver 拉下来。"""
    if not selenium_available():
        return False, "未安装 selenium，请执行: pip install selenium"
    try:
        key, driver = create_driver(cfg, browser=browser, headless=headless)
    except Exception as exc:
        return False, f"驱动初始化失败: {type(exc).__name__}: {exc}"
    try:
        caps = driver.capabilities or {}
        msg = (f"驱动就绪: browser={key} {caps.get('browserVersion', '?')} "
               f"driver={driver_version(caps)} "
               f"python={sys.executable}")
        return True, msg
    finally:
        try:
            driver.quit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 8. 直接运行本文件时的自检（不需要校园网）
# ---------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    import argparse

    class _MiniConfig:
        def __init__(self, base: Path):
            self.base = base
            self.data = {
                "browser_automation": {
                    "enabled": True, "browser": "auto", "headless": "auto",
                    "timeout": 30, "profile_dir": str(base / "profile"),
                    "dump_dir": str(base / "dumps"),
                }
            }

        def get(self, dotted, default=None):
            cur = self.data
            for part in dotted.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    return default
                cur = cur[part]
            return cur

        def resolve_path(self, p):
            return Path(p) if Path(p).is_absolute() else (self.base / p)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ap = argparse.ArgumentParser(description="Portal 自动点击引擎自检")
    ap.add_argument("url", help="认证页 URL")
    ap.add_argument("--explain", action="store_true", help="只打印候选元素打分，不点击")
    ap.add_argument("--headed", action="store_true", help="使用可见窗口")
    args = ap.parse_args()

    c = _MiniConfig(Path(__file__).resolve().parent / "data" / "autoclick_selftest")
    clicker = PortalAutoClicker(c)
    print("selenium:", selenium_version() or "未安装",
          "| 浏览器:", find_browser("auto"))
    print("不可用原因:", clicker.unavailable_reason() or "无")
    if args.explain:
        for item in clicker.explain(args.url, headless=not args.headed):
            print(f"[{item['score']:>6.1f}] {item['frame']:<12} "
                  f"<{item['tag']}> {item['text'][:50]!r} "
                  f"id={item['id'][:20]!r} cls={item['cls'][:30]!r}")
    else:
        r = clicker.click(args.url, headless=not args.headed)
        print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
