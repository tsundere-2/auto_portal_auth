"""用本地 HTTP 回放真实锐捷认证页，验证 CDP 点击器能填表+点击。"""
import sys, threading, time, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, r"D:\auto_portal_auth")

# 一个精简但结构真实的锐捷认证页：账号/密码 + 条款 checkbox + 无文字按钮
PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>上网认证</title></head>
<body>
<div class="login_frame">
  <div id="serviceShowHide" style="display:none"><div id="defaultService">校园网</div></div>
  <form id="loginForm">
    <input type="text" id="username" name="userId" placeholder="请输入账号">
    <input type="password" id="pwd" name="password" placeholder="请输入密码">
    <input type="hidden" id="net_access_type" value="shu">
    <label><input type="checkbox" id="chk">我已阅读并同意上网认证服务条款</label>
    <a id="loginLink" href="javascript:void(0)" onclick="doLogin()"><div style="width:120px;height:36px;background:#2a7ae2"></div></a>
  </form>
  <div id="errorInfo_center"></div>
</div>
<script>
window.__clicked = 0;
function doLogin(){
  window.__clicked++;
  var u=document.getElementById('username').value;
  var p=document.getElementById('pwd').value;
  var t=document.getElementById('chk').checked;
  if(!u||!p){document.getElementById('errorInfo_center').innerText='请填写用户名';return;}
  if(!t){document.getElementById('errorInfo_center').innerText='请勾选服务条款';return;}
  document.getElementById('errorInfo_center').innerText='认证成功';
  document.title='AUTH_OK';
}
</script>
</body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}/eportal/index.jsp?wlanuserip=1.2.3.4"

import auto_portal_auth as app
import portal_cdp

cfg = app.Config(data={
    "app": {"stats_file": "s.json", "state_file": "st.json",
            "portal_cache_file": "p.json"},
    "stats": {"enabled": False},
    "auth": {"auto_login": {"enabled": True, "username": "25124308", "password": "testpw"}},
    "browser_automation": {
        "enabled": True, "browser": "edge", "headless": True,
        "profile_dir": "", "timeout": 40, "score_threshold": 6.0,
    },
}, path=__import__("pathlib").Path(tempfile.mkdtemp()) / "c.yaml")

clicker = portal_cdp.CDPClicker(cfg)
print("available:", clicker.available)


def verify():
    # 用页面内容作为"认证成功"信号（点击后会出现"认证成功"字样）
    try:
        txt = clicker._page.evaluate("document.body.innerText") or ""
        return "认证成功" in txt
    except Exception:
        return False


t0 = time.time()
res = clicker.click(url, verify=verify, headless=True)
print("=== RESULT ===")
for k, v in res.items():
    print(f"  {k} = {v}")
print(f"总耗时 {time.time()-t0:.1f}s")
try:
    if clicker._page:
        print("页面提示:", clicker._page.evaluate(
            "document.getElementById('errorInfo_center').innerText"))
        print("点击次数:", clicker._page.evaluate("window.__clicked"))
except Exception as e:
    print("读取页面状态失败:", e)
clicker.close()
srv.shutdown()
