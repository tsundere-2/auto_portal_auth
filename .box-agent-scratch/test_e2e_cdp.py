"""端到端：AutoPortalAuth 在 portal_required 状态下，用 CDP 引擎完成认证。"""
import sys, logging, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, r"D:\auto_portal_auth")

PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>上网认证</title></head>
<body><form id="loginForm">
  <input type="text" id="username" placeholder="请输入账号">
  <input type="password" id="pwd" placeholder="请输入密码">
  <input type="hidden" id="net_access_type" value="shu">
  <label><input type="checkbox" id="chk">我已阅读并同意上网认证服务条款</label>
  <a id="loginLink" href="javascript:void(0)" onclick="doLogin()"><div style="width:120px;height:36px;background:#2a7ae2"></div></a>
</form><div id="errorInfo_center"></div>
<script>
window.__authed = false;
function doLogin(){
  var u=document.getElementById('username').value, p=document.getElementById('pwd').value;
  if(!u||!p){document.getElementById('errorInfo_center').innerText='请填写用户名';return;}
  if(!document.getElementById('chk').checked){document.getElementById('errorInfo_center').innerText='请勾选服务条款';return;}
  window.__authed = true;
  document.getElementById('errorInfo_center').innerText='认证成功';
}
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}/eportal/index.jsp?wlanuserip=1.2.3.4"

import auto_portal_auth as app

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")

tmp = Path(tempfile.mkdtemp(prefix="e2e-"))
cfg = app.Config(data={
    "app": {"stats_file": "s.json", "state_file": "st.json",
            "portal_cache_file": "p.json"},
    "stats": {"enabled": False},
    "auth": {"auto_login": {"enabled": True, "username": "25124308", "password": "pw"}},
    "browser_automation": {"enabled": True, "engine": "cdp", "browser": "edge",
                           "headless": True, "profile_dir": "",
                           "score_threshold": 6.0, "timeout": 40},
}, path=tmp / "c.yaml")

auth = app.AutoPortalAuth(cfg)

# 校验函数：看页面是否真的认证成功（模拟"检查是否联网"）
def is_online():
    try:
        return bool(auth.trigger.autoclicker and
                    auth.trigger.autoclicker._page.evaluate("window.__authed"))
    except Exception:
        return False

auth.checker.is_online = is_online

status = app.NetStatus(state=app.NetState.PORTAL_REQUIRED, portal_url=url,
                       fingerprint=app.Fingerprint(vendor="ruijie", confidence=1.0,
                                                   portal_url=url))
t0 = time.time()
ok = auth.trigger.selenium_click(status)
print("=" * 50)
print("自动认证结果:", ok, f"耗时 {time.time()-t0:.1f}s")
print("引擎:", type(auth.trigger.autoclicker).__name__)
if auth.trigger.autoclicker:
    auth.trigger.autoclicker.close()
srv.shutdown()
