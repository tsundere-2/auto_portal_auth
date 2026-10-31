"""复现"长时间睡眠唤醒后：显示已连接、实际没网"。

真实故障形态（10-31 13:19 那次 12.5 小时睡眠）：
  1. 睡眠期间 Portal 会话被网关清掉，但本机 DHCP 租约还没到期，
     出口 IP 仍是 59.79.4.243；
  2. 唤醒后 DNS 还没起来 / 网关处于"半通"状态：
     - 部分探测能拿到 HTTP 200（被网关劫持返回一个"看起来正常"的页面），
     - 或 DNS 解析成功但 TCP 握手超时；
  3. 程序一旦把某个目标判成 ok，就 return INTERNET_OK，之后再也不会认证。

本脚本用可控的假探测器复现上述三种判定，检查 check() 是否会被骗。
"""
import sys

sys.path.insert(0, r"D:\auto_portal_auth")
import auto_portal_auth as app

cfg = app.Config.load(r"D:\auto_portal_auth\config.yaml")
checker = app.NetworkChecker(cfg)

# 场景 1：DNS 解析成功但连接超时（唤醒后最常见）
def probe_timeout(target, fetch_portal=True, timeout=None):
    return app.ProbeResult(target=target.get("name", "?"), url=target["url"],
                           kind="error", detail="ConnectTimeout")


# 场景 2：网关把 HTTP 请求劫持成 200，但正文是认证页（不是 Connect Test）
def probe_hijacked(target, fetch_portal=True, timeout=None):
    name = target.get("name")
    if name == "msft":
        return app.ProbeResult(target="msft", url=target["url"], kind="portal",
                               status_code=200, detail="响应内容不含预期关键字")
    return app.ProbeResult(target=name, url=target["url"], kind="error",
                           detail="ConnectTimeout")


# 场景 3：流转到多次唤醒后的"部分可达"——msft 通过但别的都不通
def probe_partial(target, fetch_portal=True, timeout=None):
    if target.get("name") == "msft":
        return app.ProbeResult(target="msft", url=target["url"], kind="ok",
                               status_code=200, detail="HTTP 200 OK")
    return app.ProbeResult(target=target.get("name", "?"), url=target["url"],
                           kind="error", detail="ConnectTimeout")


# 让链路层"看起来正常"（IP 还在，正是睡眠后的真实状态）
checker.link_info = lambda use_cache=True: app.LinkInfo(
    up=True, interfaces={"<outbound>": ["59.79.4.243"]},
    primary_ip="59.79.4.243", primary_iface="<outbound>")

for name, fn in (("DNS成功但连接超时", probe_timeout),
                 ("网关劫持成200认证页", probe_hijacked),
                 ("只有msft可达", probe_partial)):
    checker.probe_target = fn
    st = checker.check()
    print(f"{name:22s} -> {st.state.value:18s} | {st.detail[:60]}")

# 场景 4：全部超时（真实断网）
checker.probe_target = probe_timeout
print(f"{'全部超时':20s} -> {checker.check().state.value}")
