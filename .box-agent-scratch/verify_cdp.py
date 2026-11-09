import subprocess, sys, tempfile, time, json, os
sys.path.insert(0, r"D:\auto_portal_auth")
import cdp_client as cdp

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PORT = 19223
prof = tempfile.mkdtemp(prefix="cdpverify-")

proc = subprocess.Popen([
    EDGE, f"--remote-debugging-port={PORT}", "--headless=new",
    f"--user-data-dir={prof}", "--no-first-run", "--no-default-browser-check",
    "--disable-extensions", "about:blank",
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    ok = cdp.wait_port(PORT, timeout=20)
    print("port ready:", ok)
    if not ok:
        raise SystemExit(1)

    targets = cdp.list_targets(PORT)
    pages = [t for t in targets if t.get("type") == "page"]
    print("pages:", len(pages), pages[0].get("url") if pages else None)

    s = cdp.CDPSession(pages[0]["webSocketDebuggerUrl"])
    print("browser:", s.evaluate("navigator.userAgent"))

    # 打开认证页（真实地址，IP 直连）
    s.call("Page.enable")
    url = "http://10.10.9.9/eportal/index.jsp?wlanuserip=59.79.4.243&mac=c85309dcd933&t=wireless-v2-plain"
    s.navigate(url, timeout=20)
    time.sleep(3)

    print("title:", s.evaluate("document.title"))
    print("有登录框:", s.evaluate("!!document.getElementById('username')"))
    print("有net_access_type:", s.evaluate("!!document.getElementById('net_access_type')"))
    print("按钮候选数:", s.evaluate(
        "document.querySelectorAll('a,button,input[type=submit],div[onclick]').length"))
    print("JS 执行能力:", s.evaluate("1+1"))
    s.close()
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    print("cleaned")
