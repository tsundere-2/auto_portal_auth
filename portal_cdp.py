"""CDP 版自动点击器：不依赖 msedgedriver，因此永远不会因 Edge 升级而失效。

为什么必须做这件事（实测）：
    Edge 自动更新到 157，而 Selenium 缓存驱动只有 155 ->
    "This version of Microsoft Edge WebDriver only supports 155"，
    浏览器兜底彻底不可用；而需要认证的网络里又下载不了新驱动（没网），
    形成死循环。CDP 是浏览器内置调试协议，不依赖驱动，Edge 升级多少次都照用。

复用 portal_autoclick 里已有的 _JS_COLLECT / _JS_CLICK / score_candidate，
保证"按钮打分"行为和 Selenium 版完全一致。
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import cdp_client

LOG = logging.getLogger("portal.cdp")

# 允许借用 portal_autoclick 的 JS 与打分（避免逻辑分叉）
try:
    import portal_autoclick as _ac
    _JS_COLLECT = getattr(_ac, "_JS_COLLECT", "")
    _JS_CLICK = getattr(_ac, "_JS_CLICK", "")
    _score = getattr(_ac, "score_candidate", None)
    _TERMS = getattr(_ac, "TERMS_KEYWORDS", [])
except Exception:                                  # pragma: no cover
    _JS_COLLECT = _JS_CLICK = ""
    _score = None
    _TERMS = []


def find_edge() -> str:
    """找 Edge 可执行文件。"""
    for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ):
        if Path(p).exists():
            return p
    return ""


class CDPClicker:
    """用 CDP 驱动 Edge 完成"填账号密码 + 勾条款 + 点连接"。"""

    name = "cdp"

    def __init__(self, cfg, logger: Optional[logging.Logger] = None):
        self.cfg = cfg
        self.log = logger or LOG
        self._proc: Optional[subprocess.Popen] = None
        self._browser: Optional[cdp_client.Browser] = None
        self._page: Optional[cdp_client.Page] = None
        self._profile: Optional[str] = None

    # ---- 生命周期 ---------------------------------------------------------
    @property
    def available(self) -> bool:
        return bool(find_edge())

    def unavailable_reason(self) -> str:
        return "" if self.available else "未找到 Microsoft Edge"

    def _launch(self, headless: bool) -> None:
        exe = find_edge()
        if not exe:
            raise RuntimeError("未找到 Edge")
        port = int(self.cfg.get("browser_automation.cdp_port", 0) or 0)
        if port <= 0:
            # 随机高位端口，避免和 qiandao 之类的工具撞车
            import socket as _s
            s = _s.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
        self._port = port

        profile = self.cfg.get("browser_automation.profile_dir", "") or ""
        if profile:
            self._profile = str(self.cfg.resolve_path(profile))
        else:
            self._profile = tempfile.mkdtemp(prefix="apa-cdp-")

        args = [
            exe,
            f"--remote-debugging-port={port}",
            f"--user-data-dir={self._profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=Translate,msEdgeIdentity,EdgeSync",
            "--disable-background-networking",
            "--disable-sync",
            "--no-service-autorun",
            "--disable-component-extensions-with-background-pages",
            "--disable-client-side-phishing-detection",
            "--metrics-recording-only",
        ]
        if headless:
            args.append("--headless=new")
        args.append("about:blank")

        self.log.debug("启动浏览器(CDP): edge headless=%s port=%s", headless, port)
        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        if not cdp_client.wait_port(port, timeout=float(
                self.cfg.get("browser_automation.cdp_start_timeout", 20))):
            raise RuntimeError("CDP 调试端口未就绪")
        self._browser = cdp_client.Browser(port, timeout=15)
        self._page = self._browser.first_page()
        self.log.debug("CDP 已连接: %s", self._browser.browser_version)

    def close(self) -> None:
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._proc:
                self._proc.terminate()
                self._proc.wait(timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        self._browser = self._page = self._proc = None

    # ---- 主流程 -----------------------------------------------------------
    def click(self, portal_url: str, verify: Optional[Callable[[], bool]] = None,
              headless: Optional[bool] = None, keep_open: bool = False) -> Dict[str, Any]:
        started = time.time()
        res: Dict[str, Any] = {"success": False, "clicked": False, "clicked_text": "",
                               "score": 0.0, "attempts": 0, "headless": True,
                               "error": "", "elapsed": 0.0}
        if headless is None:
            mode = str(self.cfg.get("browser_automation.headless", "auto")).lower()
            modes = [True, False] if mode == "auto" else [mode in ("true", "1", "yes")]
        else:
            modes = [bool(headless)]

        for hl in modes:
            res["headless"] = hl
            try:
                self.close()
                self._launch(hl)
                page = self._page
                page.navigate(portal_url, timeout=float(
                    self.cfg.get("browser_automation.page_load_timeout", 20)))
                self._wait_ready(page)
                self._fill_credentials(page)

                ok = self._click_once(page, res)
                res["attempts"] += 1
                if ok:
                    # 等认证生效并校验
                    if self._wait_verified(page, verify):
                        res["success"] = True
                        res["elapsed"] = time.time() - started
                        return res
            except Exception as exc:
                res["error"] = f"{type(exc).__name__}: {exc}"
                # 常见：某些 Portal 页会让渲染进程无响应（evaluate 超时），
                # 此时立刻放弃本轮，交给上层回退 Selenium 或打开浏览器。
                self.log.debug("CDP 尝试失败(headless=%s): %s", hl, exc)
                if "超时" in str(exc):
                    res["hint"] = "页面渲染进程无响应，建议回退 Selenium"
                    break

        if not keep_open:
            self.close()
        res["elapsed"] = time.time() - started
        # 兜底：至少把认证页打开让用户能手动点
        return res

    def _wait_ready(self, page, timeout: float = 12.0) -> None:
        """等 DOM 就绪即可，不等全部资源加载完成。

        Portal 页会引用外网图片/统计脚本，认证前必然加载不出来；
        等 load 事件会白等（实测 45 秒仍未完成）。只要 document 已有
        body 和登录表单就能干活。
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                state = page.evaluate("document.readyState")
                if state in ("interactive", "complete"):
                    # 再确认有 body（有的页面 interactive 时 body 还没建好）
                    if page.evaluate("!!document.body"):
                        return
            except Exception:
                pass
            time.sleep(0.3)
        self.log.debug("DOM 就绪等待超时，继续尝试操作")

    def _fill_credentials(self, page) -> int:
        """填账号密码（与 Selenium 版同语义：只填空的、可见的）。"""
        al = self.cfg.get("auth.auto_login") or {}
        user = str(al.get("username") or "")
        pwd = str(al.get("password") or "")
        if not (user and pwd):
            return 0
        js = """
        (function(u,p){
          var n=0;
          function vis(e){if(!e)return false;var r=e.getBoundingClientRect();
            var s=getComputedStyle(e);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none';}
          var pw=document.querySelector('input[type=password]');
          if(pw&&vis(pw)){pw.value=p;pw.dispatchEvent(new Event('input',{bubbles:true}));
            pw.dispatchEvent(new Event('change',{bubbles:true}));n++;}
          var cands=document.querySelectorAll('input[type=text],input:not([type])');
          for(var i=0;i<cands.length;i++){var e=cands[i];
            if(!vis(e))continue;
            var hint=((e.id||'')+(e.name||'')+(e.placeholder||'')).toLowerCase();
            if(/user|name|account|zhanghao|学号|账号|用户/.test(hint)||cands.length===1){
              e.value=u;e.dispatchEvent(new Event('input',{bubbles:true}));
              e.dispatchEvent(new Event('change',{bubbles:true}));n++;break;}
          }
          return n;
        })(%s,%s)
        """ % (_json_str(user), _json_str(pwd))
        try:
            n = page.evaluate(js) or 0
            if n:
                self.log.info("已填写登录账号「%s」和密码（CDP）", user)
            return int(n)
        except Exception as exc:
            self.log.debug("CDP 填表失败: %s", exc)
            return 0

    def _click_once(self, page, res: Dict[str, Any]) -> bool:
        """复用 portal_autoclick 的采集 + 打分，选出最可信的按钮并点击。"""
        try:
            # _JS_COLLECT 的签名是 (function(extraSel){...})，必须传参调用，
            # 否则整个函数不会被求值（返回 undefined），候选永远是 0 个。
            extra = str((self.cfg.get("browser_automation.extra_selectors") or ""))
            cands = page.evaluate(_adapt_selenium_js(_JS_COLLECT, extra)) or []
        except Exception as exc:
            self.log.debug("CDP 采集按钮失败: %s", exc)
            return False
        if not isinstance(cands, list) or not cands:
            return False

        # 勾选条款
        self._tick_terms(page)

        # score_candidate 期望 dict{文本: 权重}；配置里给的是 list，需要转成 dict，
        # 并与内置的 DEFAULT_BUTTON_TEXTS 合并（否则打分恒为 0）。
        texts = dict(getattr(_ac, "DEFAULT_BUTTON_TEXTS", {}) or {})
        configured = self.cfg.get("browser_automation.button_texts") or []
        if isinstance(configured, dict):
            texts.update({str(k): float(v) for k, v in configured.items()})
        else:
            for t in configured:
                texts.setdefault(str(t), 8.0)
        deny = list(getattr(_ac, "DEFAULT_DENY_TEXTS", []) or [])
        deny += [str(x) for x in (self.cfg.get("browser_automation.deny_texts") or [])]
        threshold = float(self.cfg.get("browser_automation.score_threshold", 6.0))

        best, best_score = None, 0.0
        if _score:
            for i, c in enumerate(cands):
                try:
                    s = _score(dict(c), texts, deny)
                except Exception:
                    continue
                if s > best_score:
                    best, best_score = (i, c), s
        if best is None or best_score < threshold:
            self.log.debug("CDP 未找到可信按钮（最高 %.1f < %.1f）", best_score, threshold)
            return False

        idx, cand = best
        res["clicked_text"] = (cand.get("text") or "").strip()[:60] or f"<{cand.get('tag')}>"
        res["score"] = best_score
        # _JS_COLLECT/_JS_CLICK 都是 "return (function(){...})" 形式，
        # 在 CDP 里要包成 IIFE 表达式才能直接求值。
        state = None
        try:
            state = page.evaluate(_adapt_selenium_js(_JS_CLICK, idx))
        except Exception as exc:
            self.log.debug("CDP 点击求值失败: %s", exc)
            return False
        if not state or state in ("missing", "failed"):
            self.log.debug("CDP 点击未生效: %s", state)
            return False
        res["clicked"] = True
        self.log.info("已点击认证按钮: 「%s」 (score=%.1f, CDP)", res["clicked_text"], best_score)
        time.sleep(float(self.cfg.get("browser_automation.click_delay", 0.8)))
        return True

    def _tick_terms(self, page) -> None:
        """勾选"同意条款"类复选框。

        注意：不能沿用"采集列表的下标"——那个列表里混了 a/div/form 等元素，
        下标对不上复选框集合。这里在页面里一次性做"查+判+点"，
        避免任何跨调用下标错位。
        """
        if self.cfg.get("browser_automation.skip_terms_checkbox", False):
            return
        kw = list(_TERMS) + [str(x) for x in
                             (self.cfg.get("browser_automation.checkbox_texts") or [])]
        if not kw:
            return
        try:
            n = page.evaluate("""
            (function(kw){
              var els=document.querySelectorAll('input[type=checkbox],[role=checkbox]');
              var n=0;
              for(var i=0;i<els.length;i++){
                var e=els[i];
                if(e.checked) continue;
                var t=((e.parentElement?e.parentElement.innerText:'')||'').toLowerCase();
                var hit=false;
                for(var k=0;k<kw.length;k++){ if(kw[k]&&t.indexOf(String(kw[k]).toLowerCase())>=0){hit=true;break;} }
                if(!hit) continue;
                try{ e.scrollIntoView({block:'center'}); }catch(_){}
                try{ e.click(); }catch(_){}
                if(!e.checked){ try{ e.checked=true;
                  e.dispatchEvent(new Event('change',{bubbles:true})); }catch(_){} }
                n++;
              }
              return n;
            })(%s)
            """ % _json_str(kw))
            if n:
                self.log.info("已勾选 %d 个条款复选框（CDP）", int(n))
        except Exception as exc:
            self.log.debug("CDP 勾选条款失败: %s", exc)

    def _wait_verified(self, page, verify: Optional[Callable[[], bool]],
                       timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if verify:
                try:
                    if verify():
                        return True
                except Exception:
                    pass
            time.sleep(1.0)
        return False


def _adapt_selenium_js(js: str, *args) -> str:
    """把 Selenium 风格的 JS 改成 CDP 可直接求值的表达式。

    portal_autoclick 里的 _JS_COLLECT / _JS_CLICK 都是这种写法：

        return (function (extraSel) { ... })(arguments[0]);

    `arguments` 只存在于 Selenium execute_script 的参数注入机制里，
    在 CDP 的 Runtime.evaluate 中是未定义的。这里把结尾的
    `(arguments[0])` / `(arguments[0],arguments[1])` 换成实参字面量。
    """
    text = js.strip()
    if text.startswith("return "):
        text = text[len("return "):]
    text = text.rstrip()
    if text.endswith(";"):
        text = text[:-1]
    # 替换结尾的实参列表
    import re as _re
    m = _re.search(r"\(\s*arguments\[0\].*\)\s*$", text)
    literal = "(" + ",".join(_json_str(a) for a in args) + ")"
    if m:
        text = text[:m.start()] + literal
    elif "arguments[" in text:
        # 兜底：把 arguments[0] 直接替换掉
        for i, a in enumerate(args):
            text = text.replace(f"arguments[{i}]", _json_str(a))
    return text


def _json_str(v: str) -> str:
    import json
    return json.dumps(v, ensure_ascii=False)
