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

import sys
import threading
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
