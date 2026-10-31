#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_ruijie_login.py —— 锐捷 ePortal 直连登录（不需要浏览器）

覆盖两件事：
  1. RSA 加密必须和页面 security.js 逐字节一致（用真实公钥的已知向量）。
  2. 请求体必须和页面 doauthen() 完全一致（双重 encodeURIComponent、
     密码是密文、不带明文密码）。

运行：
    python tests/test_ruijie_login.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import requests                                        # noqa: E402

import auto_portal_auth as app                          # noqa: E402
from auto_portal_auth import AuthTrigger, Config, Fingerprint, NetStatus  # noqa: E402

# 来自真实校园网页面（公钥，不是秘密）
EXPONENT = "10001"
MODULUS = (
    "94dd2a8675fb779e6b9f7103698634cd400f27a154afa67af6166a43fc264172"
    "22a79506d34cacc7641946abda1785b7acf9910ad6a0978c91ec84d40b71d289"
    "1379af19ffb333e7517e390bd26ac312fe940c340466b4a5d4af1d65c3b59440"
    "78f96a1a51a5a53e4bc302818b7c9f63c4a1b07bd7d874cef1c3d4b2f5eb7871"
)
# node + 页面自带 security.js 对 "test-pass>c85309dcd933" 的计算结果
KNOWN_CIPHER = (
    "7af131005089c679fd5a2a1cf51e9400c5d526fb98ca4c7ed9b0d1f6132664dd"
    "4261c06774db4daca82bc4a84f7a7741bcfd293ad8a5117b2527596d1923f9f0"
    "22b512791390e69d642cb35767947cfcd04f4c50c65aaee80c084bf158cf86cb"
    "34f92ed6846c6c980a30bcad3a297af3b914f718f8e0ed8835004601515cac93"
)


class _FakeChecker:
    """只实现 AuthTrigger.ruijie_login 用到的那几个方法。"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.logged_in = False
        self._session = requests.Session()
        self._session.trust_env = False

    def _timeout(self):
        return (2, 3)

    # 与 NetworkChecker._body_text 同语义：真实代码现在统一走它取正文，
    # 假对象漏了就会让直连登录在 except 里静默失败（测试曾因此一直红）。
    @staticmethod
    def _body_text(resp):
        return resp.text or ""

    def _fetch_portal_page(self, url: str) -> str:
        return self._session.get(url, timeout=self._timeout()).text

    def is_online(self) -> bool:
        return self.logged_in


class _Handler(BaseHTTPRequestHandler):
    login_path = ""
    login_body = ""
    login_query = ""

    def log_message(self, *args):  # 静音
        pass

    def do_GET(self):
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>上网认证</title></head>
<body><form>
<input id="passwordEncrypt" value="true" type="hidden">
<input name="net_access_type" id="net_access_type" value="shu" type="hidden">
<input id="publicKeyExponent" value="{EXPONENT}" type="hidden">
<input id="publicKeyModulus" value="{MODULUS}" type="hidden">
</form></body></html>"""
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        type(self).login_path = parsed.path
        type(self).login_query = parsed.query
        type(self).login_body = body
        self.server.logged_in = True
        payload = b'{"result":"success","message":"","userIndex":"abc","keepaliveInterval":"240"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class TestRuijieLogin(unittest.TestCase):
    def test_rsa_matches_page_js(self):
        """必须和页面 security.js 的结果完全一致（否则密码解密失败）。"""
        out = app.ruijie_rsa_encrypt("test-pass>c85309dcd933"[::-1], EXPONENT, MODULUS)
        self.assertEqual(out, KNOWN_CIPHER)
        self.assertEqual(len(out), 256)

    def test_login_request_matches_doauthen(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.logged_in = False
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        portal = (base + "/eportal/index.jsp?wlanuserip=59.79.4.243"
                  "&mac=c85309dcd933&t=wireless-v2-plain")
        try:
            cfg = Config(data={
                "auth": {"auto_login": {
                    "enabled": True,
                    "username": "25124308@campus",
                    "password": "S3cret!pass",
                    "verify_timeout": 5,
                }},
                "browser_automation": {"fill_credentials": True},
            }, path=Path("."))
            checker = _FakeChecker(base)
            trigger = AuthTrigger(cfg, checker)
            checker.is_online = lambda: bool(server.logged_in)

            status = NetStatus(portal_url=portal, fingerprint=Fingerprint(vendor="ruijie"))
            self.assertTrue(trigger.ruijie_login(status), "直连登录应成功")

            # 端点：相对 index.jsp 的 ./InterFace.do?method=login
            self.assertEqual(_Handler.login_path, "/eportal/InterFace.do")
            self.assertEqual(_Handler.login_query, "method=login")

            body = _Handler.login_body
            fields = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            # 原始请求体里 userId 是双重 encodeURIComponent：@ -> %2540
            self.assertIn("userId=25124308%2540campus", body)
            # queryString 同理（parse_qsl 已解一层，所以这里看到 %3D）
            self.assertTrue(fields["queryString"].startswith("wlanuserip%3D"), fields["queryString"])
            self.assertEqual(fields["passwordEncrypt"], "true")
            # 服务名来自页面隐藏域 net_access_type（真实页面是 "shu"）
            self.assertEqual(fields["service"], "shu")
            # 密码是 256 位十六进制密文，且绝对不能出现明文
            self.assertRegex(fields["password"], r"^[0-9a-f]{256}$")
            self.assertNotIn("S3cret", body)
        finally:
            server.shutdown()
            server.server_close()


class _PageInfoHandler(BaseHTTPRequestHandler):
    """静态页面里公钥是空的，只有 pageInfo 接口才给（和真实锐捷页面一致）。"""

    paths: list = []
    login_body = ""
    pageinfo_body = ""

    def log_message(self, *args):  # 静音
        pass

    def _send(self, payload: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>上网认证</title></head>
<body><form>
<input id="passwordEncrypt" value="true" type="hidden">
<input name="net_access_type" id="net_access_type" value="shu" type="hidden">
<input id="publicKeyExponent" value="" type="hidden">
<input id="publicKeyModulus" value="" type="hidden">
</form></body></html>"""
        self._send(html.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        type(self).paths.append((parsed.path, parsed.query))
        if parsed.query == "method=pageInfo":
            type(self).pageinfo_body = body
            payload = json.dumps({
                "passwordEncrypt": "true",
                "publicKeyExponent": EXPONENT,
                "publicKeyModulus": MODULUS,
                "validCodeUrl": "",
                "prefixValue": "shdx",
            }).encode("utf-8")
            self._send(payload, "application/json; charset=utf-8")
            return
        type(self).login_body = body
        self.server.logged_in = True
        self._send(b'{"result":"success","message":""}', "application/json; charset=utf-8")


class TestRuijieLoginPageInfo(unittest.TestCase):
    def test_pageinfo_fallback_when_static_html_has_no_keys(self):
        """静态 HTML 没有公钥时必须去问 pageInfo，而不是退回浏览器。"""
        _PageInfoHandler.paths = []
        _PageInfoHandler.login_body = ""
        _PageInfoHandler.pageinfo_body = ""
        server = ThreadingHTTPServer(("127.0.0.1", 0), _PageInfoHandler)
        server.logged_in = False
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        portal = (base + "/eportal/index.jsp?wlanuserip=59.79.4.243"
                  "&mac=c85309dcd933&t=wireless-v2-plain")
        try:
            cfg = Config(data={
                "auth": {"auto_login": {
                    "enabled": True,
                    "username": "25124308@campus",
                    "password": "S3cret!pass",
                    "verify_timeout": 5,
                }},
                "browser_automation": {"fill_credentials": True},
            }, path=Path("."))
            checker = _FakeChecker(base)
            checker.is_online = lambda: bool(server.logged_in)
            trigger = AuthTrigger(cfg, checker)

            status = NetStatus(portal_url=portal, fingerprint=Fingerprint(vendor="ruijie"))
            self.assertTrue(trigger.ruijie_login(status), "pageInfo 兜底后应能直连登录")

            self.assertIn(("/eportal/InterFace.do", "method=pageInfo"), _PageInfoHandler.paths)
            fields = dict(urllib.parse.parse_qsl(_PageInfoHandler.login_body,
                                                 keep_blank_values=True))
            self.assertEqual(fields["service"], "shu")
            self.assertEqual(fields["passwordEncrypt"], "true")
            # 密文必须是用 pageInfo 给的公钥算出来的
            self.assertEqual(fields["password"], app.ruijie_rsa_encrypt(
                "S3cret!pass>c85309dcd933"[::-1], EXPONENT, MODULUS))
            # pageInfo 的 queryString 和登录一样是双重编码
            self.assertTrue(_PageInfoHandler.pageinfo_body.startswith(
                "queryString=wlanuserip%253D"), _PageInfoHandler.pageinfo_body[:60])
        finally:
            server.shutdown()
            server.server_close()


class TestWakePreauth(unittest.TestCase):
    """唤醒后先用缓存的认证页直连登录（不等 DNS 探测）。"""

    PORTAL = ("http://10.10.9.9/eportal/index.jsp?wlanuserip=59.79.4.243"
              "&mac=c85309dcd933&t=wireless-v2-plain")

    def _make_auth(self, cache_ip: str, live_ip: str):
        tmp = Path(tempfile.mkdtemp(prefix="apa-wake-"))
        cfg = Config(data={
            "app": {
                "portal_cache_file": "last_portal.json",
                "stats_file": "stats.json",
                "state_file": "state.json",
            },
            "stats": {"enabled": False},
            "auth": {"auto_login": {"enabled": True, "username": "u", "password": "p"}},
            "browser_automation": {"fill_credentials": True},
        }, path=tmp / "config.yaml")
        (tmp / "last_portal.json").write_text(json.dumps({
            "url": self.PORTAL, "vendor": "ruijie", "ip": cache_ip, "saved_at": "x",
        }), encoding="utf-8")
        auth = app.AutoPortalAuth(cfg)
        auth.checker.link_info = lambda: app.LinkInfo(
            up=True, interfaces={"以太网": [live_ip]}, primary_ip=live_ip,
            primary_iface="以太网")
        calls = []
        # 实际调用点在 AuthTrigger 上（见 test_preauth_calls_trigger_not_self）
        auth.trigger.ruijie_login = lambda status, **kw: calls.append((status, kw)) or True
        return auth, calls

    def test_preauth_uses_cached_url_when_ip_unchanged(self):
        auth, calls = self._make_auth("59.79.4.243", "59.79.4.243")
        auth._wake_preauth()
        self.assertEqual(len(calls), 1, "IP 没变时应直接用缓存地址登录")
        status, kwargs = calls[0]
        self.assertEqual(status.portal_url, self.PORTAL)
        self.assertEqual(status.fingerprint.vendor, "ruijie")
        self.assertTrue(kwargs.get("skip_verify"))
        self.assertTrue(auth._wake_preauth_ok)
        # 已经成功就不再重复抢跑
        auth._wake_preauth()
        self.assertEqual(len(calls), 1)

    def test_preauth_skips_when_ip_changed(self):
        auth, calls = self._make_auth("59.79.4.243", "59.79.4.250")
        auth._wake_preauth()
        self.assertEqual(calls, [], "IP 变了就不能用旧地址硬登，交给正常探测")

    def test_preauth_skips_without_cache(self):
        auth, calls = self._make_auth("59.79.4.243", "59.79.4.243")
        auth._portal_cache = {}
        auth._wake_preauth()
        self.assertEqual(calls, [])


class TestWakeRace(unittest.TestCase):
    """唤醒后的"抢跑窗口"：不等完整探测就把认证提上去，且不误报断网。

    复现的真实场景（日志 2026-10-29 14:27 / 17:45）：唤醒后 1 秒探测因 DNS
    getaddrinfo failed 直接失败，旧逻辑当场 warning + 结束会话，然后等
    15 秒才重新探测 —— 浏览器早就在弹认证页了。
    """

    def _make_auth(self, cache_ip: str = "59.79.4.243", live_ip: str = "59.79.4.243"):
        tmp = Path(tempfile.mkdtemp(prefix="apa-race-"))
        cfg = Config(data={
            "app": {"portal_cache_file": "last_portal.json", "stats_file": "stats.json",
                    "state_file": "state.json"},
            "stats": {"enabled": False},
            "auth": {"auto_login": {"enabled": True, "username": "u", "password": "p"}},
            "monitor": {"wake_preauth_window": 5, "wake_grace": 0},
        }, path=tmp / "config.yaml")
        (tmp / "last_portal.json").write_text(json.dumps({
            "url": TestWakePreauth.PORTAL, "vendor": "ruijie", "ip": cache_ip,
            "saved_at": "x"}), encoding="utf-8")
        auth = app.AutoPortalAuth(cfg)
        auth.checker.link_info = lambda: app.LinkInfo(
            up=True, interfaces={"以太网": [live_ip]}, primary_ip=live_ip,
            primary_iface="以太网")
        return auth

    def _enter_wake(self, auth):
        auth.after_wake = True
        auth._last_resume_wall = time.time()
        auth._wake_deadline = time.monotonic() + 5
        auth._wake_preauth_ok = False

    def test_dns_not_ready_still_preauths_and_skips_full_probe(self):
        """DNS 还没起来：仍然直连登录，并且本轮跳过完整探测（省掉 8~15 秒空等）。"""
        auth = self._make_auth()
        self._enter_wake(auth)
        auth.checker.quick_probe_ip = lambda: "transient"     # 模拟 DNS 未就绪
        calls = []
        auth.trigger.ruijie_login = lambda status, **kw: calls.append(kw) or True
        auth.stats.add_auth_result = lambda ok: None

        auth._sleep(30)          # 正常周期是 30s，抢跑窗口内必须缩短
        self.assertEqual(len(calls), 1, "DNS 未就绪也必须抢一次直连登录")
        self.assertTrue(calls[0].get("skip_verify"))
        self.assertTrue(auth._skip_tick, "抢跑后应跳过完整探测，避免空等")
        self.assertTrue(auth._wake_window_active(), "窗口应继续开着等链路就绪")
        self.assertLess(auth._wake_deadline - time.monotonic(), 5.0)

    def test_preauth_calls_trigger_not_self(self):
        """回归：_wake_preauth 曾经写成 self.ruijie_login（方法在 AuthTrigger 上），
        AttributeError 被吞掉，抢跑从头到尾一次都没真正执行过。"""
        auth = self._make_auth()
        self.assertFalse(hasattr(auth, "ruijie_login"), "AutoPortalAuth 上不该有这个属性")
        self._enter_wake(auth)
        auth.checker.quick_probe_ip = lambda: "transient"
        calls = []
        auth.trigger.ruijie_login = (
            lambda status, **kw: calls.append(kw) or True)
        auth._sleep(30)
        self.assertEqual(len(calls), 1, "必须真的调到 AuthTrigger.ruijie_login")
        self.assertTrue(auth._wake_preauth_ok)

    def test_wake_window_expires(self):
        auth = self._make_auth()
        self._enter_wake(auth)
        auth._wake_deadline = time.monotonic() - 0.01
        self.assertFalse(auth._wake_window_active(), "超时后必须交回正常节奏")

    def test_ip_changed_hands_back_to_normal_flow(self):
        auth = self._make_auth(cache_ip="59.79.4.10", live_ip="59.79.4.243")
        self._enter_wake(auth)
        auth.checker.quick_probe_ip = lambda: "transient"
        calls = []
        auth.trigger.ruijie_login = lambda status, **kw: calls.append(kw) or True
        auth._sleep(30)
        self.assertEqual(calls, [], "IP 变了不能拿旧地址瞎登录")
        self.assertFalse(auth._wake_window_active(), "这种情况应立即改走正常探测")

    def test_unknown_during_wake_does_not_end_session(self):
        """唤醒后探测失败 = 还没就绪，不是断网：不许结束会话、不许发告警。"""
        auth = self._make_auth()
        self._enter_wake(auth)
        auth._wake_preauth_ok = True
        ended = []
        auth._end_session = lambda reason, status=None: ended.append(reason)
        offline = app.NetStatus(state=app.NetState.UNKNOWN, detail="DNS 解析失败")
        prev = app.NetStatus(state=app.NetState.INTERNET_OK)
        with self.assertLogs("portal", level="INFO") as captured:
            auth._handle_unknown(offline, prev)
        self.assertEqual(ended, [])
        self.assertFalse([m for m in captured.output if "网络探测异常" in m],
                         "唤醒窗口内不该出现'网络探测异常'告警")
        self.assertTrue([m for m in captured.output if "尚未就绪" in m],
                        "应该只提示一次'还没就绪'")


class _AlreadyOnlineHandler(BaseHTTPRequestHandler):
    """网关返回"已在线"，但（可配置）实际并不通。"""

    online = False
    paths: list = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>上网认证</title></head>
<body><form>
<input id="passwordEncrypt" value="true" type="hidden">
<input name="net_access_type" id="net_access_type" value="shu" type="hidden">
<input id="publicKeyExponent" value="{EXPONENT}" type="hidden">
<input id="publicKeyModulus" value="{MODULUS}" type="hidden">
</form></body></html>"""
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        type(self).paths.append(self.path)
        payload = '{"result":"fail","message":"已在线"}'.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class TestNoFalseSuccess(unittest.TestCase):
    """核心回归：任何"网关说成功"都不许直接当成"能上网"。

    用户投诉的"睡醒后显示已连接、实际没网"就来自这种误判：网关回了
    "已在线"（旧 MAC 的会话还挂着），程序或用户都以为好了，实际流量照样被拦。
    """

    def _run(self, online: bool):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _AlreadyOnlineHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        portal = (base + "/eportal/index.jsp?wlanuserip=59.79.4.243"
                  "&mac=c85309dcd933&t=wireless-v2-plain")
        try:
            cfg = Config(data={
                "auth": {"auto_login": {
                    "enabled": True, "username": "25124308", "password": "S3cret!pass",
                    "verify_timeout": 1,
                }},
                "browser_automation": {"fill_credentials": True},
            }, path=Path("."))
            checker = _FakeChecker(base)
            trigger = AuthTrigger(cfg, checker)
            checker.is_online = lambda: bool(online)
            status = NetStatus(portal_url=portal,
                              fingerprint=Fingerprint(vendor="ruijie"))
            return trigger.ruijie_login(status, verify_seconds=0.3), trigger
        finally:
            server.shutdown()
            server.server_close()

    def test_already_online_but_offline_is_failure(self):
        ok, trigger = self._run(online=False)
        self.assertFalse(ok, "网关说'已在线'但探测不通，必须返回失败")
        self.assertFalse(trigger.last_login_verified)

    def test_already_online_and_verified_is_success(self):
        ok, trigger = self._run(online=True)
        self.assertTrue(ok)
        self.assertTrue(trigger.last_login_verified)


class TestQuickProbe(unittest.TestCase):
    def test_probe_error_is_transient_not_portal(self):
        """连接超时/拒绝是"暂时没通"，不是"看到认证页" —— 否则会提前结束抢跑。"""
        cfg = Config(data={
            "detect": {"probe_targets": [
                {"name": "dead", "url": "http://127.0.0.1:1/nope", "expect_status": 200}
            ]},
        }, path=Path("."))
        checker = app.NetworkChecker(cfg)
        self.assertEqual(checker.quick_probe_ip(), "transient")


class TestWatchdogHeartbeat(unittest.TestCase):
    def test_heartbeat_age_from_state_file(self):
        tmp = Path(tempfile.mkdtemp(prefix="apa-hb-"))
        cfg = Config(data={
            "app": {"state_file": "state.json"}, "stats": {"enabled": False},
        }, path=tmp / "config.yaml")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - 42))
        (tmp / "state.json").write_text(json.dumps({"heartbeat": stamp}), encoding="utf-8")
        age = app.daemon_heartbeat_age(cfg)
        self.assertIsNotNone(age)
        self.assertGreaterEqual(age, 40)
        self.assertLess(age, 120)

    def test_heartbeat_age_missing_file(self):
        tmp = Path(tempfile.mkdtemp(prefix="apa-hb2-"))
        cfg = Config(data={"app": {"state_file": "nope.json"}}, path=tmp / "config.yaml")
        self.assertIsNone(app.daemon_heartbeat_age(cfg))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestConnectedButNoNet(unittest.TestCase):
    """回归：长时间睡眠唤醒后"显示已连接、实际没网"。

    两个具体漏洞：
      1. check() 曾经"任意一个探测目标通过就 OK" —— 唤醒后网关半通
         （DNS 有缓存 / 只放行个别域名）会被误判成在线，于是永远不再认证；
      2. _handle_unknown 超过 wake_unknown_tolerance 后只打日志、什么都不做，
         再也没有恢复路径。
    """

    def _checker(self):
        cfg = Config(data={"detect": {"probe_targets": [
            {"name": "a", "url": "http://a/x", "expect_status": 200},
            {"name": "b", "url": "http://b/x", "expect_status": 204},
            {"name": "c", "url": "http://c/x", "expect_status": 204},
        ]}}, path=Path(tempfile.mkdtemp()) / "c.yaml")
        c = app.NetworkChecker(cfg)
        c.link_info = lambda use_cache=True: app.LinkInfo(
            up=True, interfaces={"<outbound>": ["59.79.4.243"]},
            primary_ip="59.79.4.243", primary_iface="<outbound>")
        return c

    def test_single_target_ok_is_not_online(self):
        """只有 1/3 目标通过时必须判 unknown，不能报 internet_ok。"""
        c = self._checker()

        def probe(target, fetch_portal=True, timeout=None):
            if target["name"] == "a":
                return app.ProbeResult(target="a", url=target["url"], kind="ok",
                                       status_code=200, detail="HTTP 200 OK")
            return app.ProbeResult(target=target["name"], url=target["url"],
                                   kind="error", detail="ConnectTimeout")

        c.probe_target = probe
        st = c.check()
        self.assertIs(st.state, app.NetState.UNKNOWN)
        self.assertIn("1/3", st.detail, "应说明只有少数目标通过")

    def test_majority_ok_is_online(self):
        """2/3 通过才算真的在线（正常网络下探测目标是全通的）。"""
        c = self._checker()

        def probe(target, fetch_portal=True, timeout=None):
            if target["name"] in ("a", "b"):
                return app.ProbeResult(target=target["name"], url=target["url"],
                                       kind="ok", status_code=200, detail="OK")
            return app.ProbeResult(target=target["name"], url=target["url"],
                                   kind="error", detail="ConnectTimeout")

        c.probe_target = probe
        self.assertIs(c.check().state, app.NetState.INTERNET_OK)

    def test_all_ok_is_online(self):
        c = self._checker()
        c.probe_target = lambda t, fetch_portal=True, timeout=None: app.ProbeResult(
            target=t["name"], url=t["url"], kind="ok", status_code=200, detail="OK")
        self.assertIs(c.check().state, app.NetState.INTERNET_OK)

    def test_unknown_after_wake_window_still_selfchecks_portal(self):
        """超过 30 秒容忍窗口、又拿不到探测结果时，必须主动去问 Portal 网关。

        之前这里只打一条日志就结束，导致"睡醒后一直没网且永不恢复"。
        """
        tmp = Path(tempfile.mkdtemp(prefix="apa-self-"))
        cfg = Config(data={
            "app": {"portal_cache_file": "p.json", "stats_file": "s.json",
                    "state_file": "st.json"},
            "stats": {"enabled": False},
            "monitor": {"wake_unknown_tolerance": 30},
            "auth": {"auto_login": {"enabled": True, "username": "u", "password": "p"}},
        }, path=tmp / "c.yaml")
        (tmp / "p.json").write_text(json.dumps({
            "url": TestWakePreauth.PORTAL, "vendor": "ruijie",
            "ip": "59.79.4.243", "saved_at": "x"}), encoding="utf-8")

        auth = app.AutoPortalAuth(cfg)
        auth.checker.link_info = lambda use_cache=True: app.LinkInfo(
            up=True, interfaces={"<outbound>": ["59.79.4.243"]},
            primary_ip="59.79.4.243", primary_iface="<outbound>")
        auth.checker._fetch_portal_page = lambda url: "<html>eportal login</html>"
        auth._last_resume_wall = time.time() - 3600      # 远超容忍窗口
        auth._last_selfcheck = 0.0
        handled = []
        auth._handle_portal = lambda s, p, i: handled.append(s.portal_url)

        offline = app.NetStatus(state=app.NetState.UNKNOWN, detail="DNS 解析失败")
        prev = app.NetStatus(state=app.NetState.INTERNET_OK)
        auth._handle_unknown(offline, prev)
        self.assertEqual(len(handled), 1, "应主动判定为需要认证并交给认证流程")
        self.assertIn("eportal", handled[0])
