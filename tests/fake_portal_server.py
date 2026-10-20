#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fake_portal_server.py —— 用于测试的"校园网认证页"模拟服务器

它不是产品的一部分，只在 tests/ 里被引用。特点：
  * 认证按钮藏在一个 iframe 里（真实校园网很常见，用来验证 frame 递归）
  * 有一个"我已阅读并同意服务条款"复选框，未勾选时后端拒绝认证
  * 有"取消""下载客户端"等干扰按钮（用来验证打分不会乱点）
  * 认证成功后 /status 返回 online=true
"""

from __future__ import annotations

import http.server
import json
import threading
from typing import Dict, List, Optional
from urllib.parse import parse_qs

STATE: Dict[str, object] = {
    "online": False,
    "clicks": [],          # 记录点击时提交的表单
    "hits": 0,             # 首页访问次数
}

OUTER_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>校园网认证 - 上网登录</title>
<style>
  body { font-family: "Microsoft YaHei", sans-serif; background:#f2f5f9; margin:0; }
  .wrap { max-width: 900px; margin: 40px auto; background:#fff; border-radius:10px; padding:24px; }
  h1 { font-size: 20px; }
  iframe { width:100%; height:320px; border:1px dashed #ccd; }
  .cancel-area { margin-top: 12px; }
  button.cancel { background:#eee; border:0; padding:8px 18px; }
  a.dl { color:#888; font-size:12px; }
</style></head>
<body>
<div class="wrap">
  <h1>校园网认证</h1>
  <p>请点击下方"连接"按钮完成上网认证。</p>
  <!-- 认证表单藏在 iframe 里 -->
  <iframe src="/inner" title="认证表单"></iframe>
  <div class="cancel-area">
    <button class="cancel" id="cancel-btn" onclick="history.back()">取消</button>
    <a class="dl" href="/download">下载客户端</a>
  </div>
</div>
</body></html>
"""

INNER_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>认证表单</title>
<style>
  body { font-family: "Microsoft YaHei", sans-serif; padding: 10px; }
  .row { margin: 14px 0; }
  button#connect-btn { background:#1677ff; color:#fff; border:0; padding:10px 40px;
                       font-size:16px; border-radius:6px; cursor:pointer; }
  .tip { color:#888; font-size:12px; }
</style></head>
<body>
  <div class="row">
    <input type="checkbox" id="agree">
    <label for="agree">我已阅读并同意《校园网服务条款》</label>
  </div>
  <div class="row">
    <button id="connect-btn" onclick="doConnect()">连接</button>
  </div>
  <div class="tip" id="tip">认证方式：MAC 无感认证</div>

<script>
function doConnect() {
  var box = document.querySelector('#agree');
  var body = 'agree=' + (box && box.checked ? '1' : '0');
  fetch('/api/connect', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: body
  }).then(function (r) { return r.text(); }).then(function (t) {
    document.getElementById('tip').innerText = t;
    document.title = 'AUTH_RESULT:' + t;
  });
}
</script>
</body></html>
"""


# 锐捷 ePortal 风格：按钮文字是背景图，<a> 本身没有任何文本，
# 周围还有"连接网络"这种看起来可点、其实只是标题的 div/span。
RUIJIE_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>上网认证</title>
<style>
  body { margin:0; font-family:"Microsoft YaHei", sans-serif; background:#0b3d91; color:#fff; }
  #logininfo_hk { padding: 60px; }
  .span_2 { color:#fff; font-size:20px; cursor:pointer; }
  #login_btn_1 { position:relative; width:275px; margin-top:20px; }
  #loginLink { display:block; width:275px; height:54px; text-decoration:none; }
  #loginLink_div { width:275px; height:54px; background:#1677ff; border-radius:6px; }
</style></head>
<body id="loginbody">
  <div id="logininfo_hk">
    <div id="oldConnectNetwork">
      <span class="span_2" id="connectNetworkId">连接网络</span>
    </div>
    <div id="login_btn_1">
      <div id="SLoginBtn_1" class="SLoginBtn_1"><ol><li>
        <!-- 关键：<a> 没有文字，文字/图标由背景图或 CSS 绘制 -->
        <a id="loginLink" tabindex="-1"
           onclick="this.className='loginButtonHKClicked_1';doauthen();">
          <div id="loginLink_div"></div>
        </a>
      </li></ol></div>
    </div>
  </div>
<script>
function doauthen() {
  document.getElementById('loginLink_div').innerText = '已连接';
  document.title = '认证成功';
}
</script>
</body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "FakePortal/1.0"

    def log_message(self, fmt, *args):  # 静音
        pass

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/html; charset=utf-8",
              extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/connecttest.txt":
            # 模拟真实校园网：未认证时把探测请求 302 到认证页，认证后返回正常内容
            if STATE["online"]:
                self._send(200, b"Microsoft Connect Test", "text/plain; charset=utf-8")
            else:
                self._send(302, b"", extra={"Location": "/portal"})
        elif path in ("/", "/portal"):
            STATE["hits"] = int(STATE["hits"]) + 1
            self._send(200, OUTER_HTML.encode("utf-8"))
        elif path == "/inner":
            self._send(200, INNER_HTML.encode("utf-8"))
        elif path == "/ruijie":
            self._send(200, RUIJIE_HTML.encode("utf-8"))
        elif path == "/status":
            body = json.dumps({"online": bool(STATE["online"]),
                               "clicks": STATE["clicks"]}).encode("utf-8")
            self._send(200, body, "application/json")
        elif path == "/download":
            self._send(200, b"not a real client")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if path == "/api/connect":
            data = parse_qs(raw)
            agreed = (data.get("agree", ["0"])[0] == "1")
            STATE["clicks"].append({"raw": raw, "agreed": agreed})  # type: ignore[union-attr]
            if agreed:
                STATE["online"] = True
                self._send(200, "认证成功，已连接".encode("utf-8"), "text/plain; charset=utf-8")
            else:
                self._send(200, "请先勾选同意服务条款".encode("utf-8"), "text/plain; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")


class FakePortalServer:
    """上下文管理器：with FakePortalServer() as srv: srv.url"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host, self.port = host, port
        self.httpd: Optional[http.server.ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def __enter__(self) -> "FakePortalServer":
        STATE.update({"online": False, "clicks": [], "hits": 0})
        self.httpd = http.server.ThreadingHTTPServer((self.host, self.port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=3)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/portal"

    @property
    def online(self) -> bool:
        return bool(STATE["online"])

    @property
    def clicks(self) -> List[dict]:
        return list(STATE["clicks"])  # type: ignore[arg-type]


if __name__ == "__main__":
    import time
    with FakePortalServer(port=8931) as srv:
        print(f"假认证页已启动: {srv.url}  (Ctrl+C 退出)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n退出")
