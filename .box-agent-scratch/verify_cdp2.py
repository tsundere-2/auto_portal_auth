import subprocess, sys, tempfile, time
sys.path.insert(0, r"D:\auto_portal_auth")
import cdp_client as cdp

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PORT = 19230
prof = tempfile.mkdtemp(prefix="cdpv2-")

p = subprocess.Popen([EDGE, f"--remote-debugging-port={PORT}", "--headless=new",
                      f"--user-data-dir={prof}", "--no-first-run", "about:blank"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    assert cdp.wait_port(PORT, 20), "port"
    b = cdp.Browser(PORT, timeout=12)
    print("browser:", b.browser_version)

    pg = b.first_page()
    print("eval before nav:", pg.evaluate("1+1"))

    url = ("http://10.10.9.9/eportal/index.jsp?wlanuserip=59.79.4.243"
           "&mac=c85309dcd933&t=wireless-v2-plain")
    pg.navigate(url, timeout=20)
    time.sleep(3)
    print("eval AFTER nav :", pg.evaluate("1+1"))
    print("title          :", pg.evaluate("document.title"))
    print("has username   :", pg.evaluate("!!document.getElementById('username')"))
    print("has net_acc_ty :", pg.evaluate("!!document.getElementById('net_access_type')"))
    print("btn candidates :", pg.evaluate(
        "document.querySelectorAll('a,button,input[type=submit]').length"))
    b.close()
finally:
    p.terminate()
    time.sleep(1)
    p.kill()
    print("cleaned")
